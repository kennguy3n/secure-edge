package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// tokenByteLength is the number of random bytes generated when the
// agent has to mint a fresh API token. 32 bytes (256 bits) is the
// same width the agent self-updater's Ed25519 verification keys use,
// and well above the 128-bit floor for capability tokens.
const tokenByteLength = 32

// DefaultAPITokenPath returns the recommended on-disk location for
// the per-install API capability token (work item A2) on the current
// OS, or "" when the home directory is not discoverable (e.g. some
// container init scenarios where HOME is unset).
//
// The Electron tray's DEFAULT_API_TOKEN_PATH (electron/main.ts)
// computes the same path so a fresh install — with `api_token_path`
// pointing here on the agent side — needs no extra environment
// variable on the tray launcher. Operators who deliberately pick a
// non-default location (e.g. an OS-managed StateDirectory under
// /var/lib/secure-edge/) still need to point the tray at it via
// SECURE_EDGE_API_TOKEN_PATH; this function only addresses the
// default-path mismatch the PR #18 review flagged.
//
// The agent's config.Default() returns "" (feature off); this helper
// is used by main to print a startup hint pointing at the canonical
// per-OS location so operators see exactly what to put in config.yaml
// when they're ready to flip the feature on. It does not change the
// default itself — the staged-rollout posture from PR #18 stays:
//   - api_token_path: ""           => feature disabled, no token file
//   - api_token_path: <this path>  => generated + advertised on /hello
//     and recognised by the tray with
//     zero further configuration.
func DefaultAPITokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "secure-edge", "api-token")
	case "windows":
		// Use LookupEnv (not Getenv) so APPDATA set to "" is honoured
		// verbatim — the Electron tray's DEFAULT_API_TOKEN_PATH does
		// `process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming')`
		// and JavaScript's `??` only falls back on null/undefined, NOT
		// on empty string. Treating "" as "unset" here (the old
		// os.Getenv("APPDATA") != "" check) would silently disagree
		// with the tray when APPDATA is explicitly empty (Go would
		// fall back to ~/AppData/Roaming, Electron would use the empty
		// string verbatim) — same byte-identity violation the XDG
		// branch below was tightened against. APPDATA="" doesn't
		// occur on real Windows installs (the OS always populates it),
		// so this is a contract-correctness fix rather than an
		// operator-visible failure mode, but keeping the two
		// implementations literally identical is the only sustainable
		// invariant for a path operators are expected to copy-paste.
		if appData, ok := os.LookupEnv("APPDATA"); ok {
			return filepath.Join(appData, "secure-edge", "api-token")
		}
		return filepath.Join(home, "AppData", "Roaming", "secure-edge", "api-token")
	default:
		// XDG Base Directory: $XDG_CONFIG_HOME or ~/.config.
		// No TrimSpace on the env value — the Electron tray's
		// DEFAULT_API_TOKEN_PATH (electron/main.ts) does a plain
		// length check (`xdg && xdg.length > 0`) and the two
		// computations are documented to stay byte-identical so
		// the agent's startup-hint output and the tray's runtime
		// discovery resolve to the same file. Trimming here would
		// silently disagree on whitespace-only XDG_CONFIG_HOME
		// values (Go would fall back to ~/.config/, Electron would
		// use the whitespace string verbatim) — exactly the
		// failure mode the helper was added to prevent.
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "secure-edge", "api-token")
		}
		return filepath.Join(home, ".config", "secure-edge", "api-token")
	}
}

// LoadOrCreateAPIToken reads the API capability token from path,
// generating a new 32-byte hex token and writing it with mode 0600
// when the file is missing, empty, or contains only whitespace.
//
// The returned token is always a lowercase hex string. The parent
// directory of path is created (mode 0700) if it does not already
// exist so first-run installs do not need a separate bootstrap step.
//
// A path of "" returns ("", nil) so callers can treat "no token
// configured" identically to "token feature disabled".
//
// Concurrency: the daemon and the Native Messaging host both call
// this on first install and can race. The create path stages the
// candidate in a tmp file (in the same directory, so it is on the
// same filesystem) and then calls os.Link to atomically install it
// at path. Link fails with EEXIST when path already exists, so the
// kernel picks exactly one winner across concurrent callers — and
// crucially the destination at path is never visible empty. Losers
// read the winner's token via readToken and return the same string.
// Two processes therefore never end up with different in-memory
// tokens from a single first-install — the tray, daemon, and NM
// host stay in sync without any explicit lockfile.
func LoadOrCreateAPIToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("api token: mkdir %s: %w", dir, err)
		}
	}

	// Bound the retry loop so a pathological filesystem state
	// (e.g. another process repeatedly recreating a whitespace
	// file under us) cannot wedge the daemon forever. In practice
	// every realistic call returns in 1 iteration; 32 is far above
	// what concurrent first-install contention can need.
	const maxAttempts = 32
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Fast path: an existing, non-empty token wins.
		if tok, ok, err := readToken(path); err != nil {
			return "", err
		} else if ok {
			return tok, nil
		}

		// Mint a candidate. Two concurrent callers will each mint
		// their own, but at most one wins the os.Link below.
		buf := make([]byte, tokenByteLength)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("api token: generate: %w", err)
		}
		candidate := hex.EncodeToString(buf)

		// Stage the candidate in a tmp file co-located with path so
		// the eventual os.Link is a same-filesystem link.
		tmpName, err := writeTokenTmpFile(dir, candidate)
		if err != nil {
			return "", err
		}

		// Atomically install tmp at path. Link fails with EEXIST
		// when path already exists, which is exactly the "someone
		// else already won" or "stale whitespace file" signal we
		// need.
		if linkErr := os.Link(tmpName, path); linkErr == nil {
			_ = os.Remove(tmpName)
			// Re-apply restrictive mode in case umask widened it
			// on the tmp file (and therefore on the link target).
			_ = os.Chmod(path, 0o600)
			return candidate, nil
		} else if !errors.Is(linkErr, fs.ErrExist) {
			_ = os.Remove(tmpName)
			return "", fmt.Errorf("api token: link %s: %w", path, linkErr)
		}
		_ = os.Remove(tmpName)

		// Lost the race or path already existed: read what's on
		// disk. A concurrent winner will have populated it with
		// their full candidate (Link is atomic, no empty window).
		if tok, ok, rerr := readToken(path); rerr != nil {
			return "", rerr
		} else if ok {
			return tok, nil
		}

		// Genuine pre-existing whitespace-only file (e.g. an
		// operator touched it). Remove it and retry — the next
		// iteration races to install our candidate. Use Remove
		// (not RemoveAll) so we don't accidentally clobber a
		// non-empty file written between the readToken above and
		// the Remove here.
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return "", fmt.Errorf("api token: remove %s: %w", path, rerr)
		}
	}
	return "", fmt.Errorf("api token: %s: gave up after %d attempts (filesystem racing?)", path, maxAttempts)
}

// writeTokenTmpFile stages token in a uniquely-named temp file in
// dir (so the eventual os.Link into the canonical path is a
// same-filesystem hard link). Returns the absolute path of the tmp
// file. Callers are responsible for either os.Link-ing it into
// place or os.Remove-ing it.
func writeTokenTmpFile(dir, token string) (string, error) {
	f, err := os.CreateTemp(dir, ".api-token.*.tmp")
	if err != nil {
		return "", fmt.Errorf("api token: create tmp: %w", err)
	}
	name := f.Name()
	if _, werr := f.WriteString(token); werr != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("api token: write tmp %s: %w", name, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("api token: close tmp %s: %w", name, cerr)
	}
	// Tighten the mode before linking; umask may have widened
	// CreateTemp's default.
	if cerr := os.Chmod(name, 0o600); cerr != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("api token: chmod tmp %s: %w", name, cerr)
	}
	return name, nil
}

// readToken returns (token, true, nil) when path holds a non-empty
// token, (_, false, nil) when path is missing or whitespace-only,
// and (_, _, err) for any other read error.
func readToken(path string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("api token: read %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", false, nil
	}
	return tok, true, nil
}

// tokenFromRequest extracts the bearer token from the Authorization
// header, returning "" when no Authorization header is present, the
// scheme is not Bearer (case-insensitive), or the token portion is
// empty. The check is intentionally permissive about trailing
// whitespace because some clients add a stray newline.
func tokenFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// tokensEqual returns true when got equals want using a
// constant-time comparison so a hostile caller cannot probe the
// token byte-by-byte via response timing.
func tokensEqual(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
