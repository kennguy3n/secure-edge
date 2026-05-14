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
	"strings"
)

// tokenByteLength is the number of random bytes generated when the
// agent has to mint a fresh API token. 32 bytes (256 bits) is the
// same width the agent self-updater's Ed25519 verification keys use,
// and well above the 128-bit floor for capability tokens.
const tokenByteLength = 32

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
// this on first install and can race. The create path uses
// O_CREATE|O_EXCL so the kernel picks exactly one winner; the loser
// reads the file the winner wrote and returns the same string. Two
// processes therefore never end up with different in-memory tokens
// from a single first-install — the tray, daemon, and NM host stay
// in sync without any explicit lockfile.
func LoadOrCreateAPIToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	// Fast path: an existing, non-empty token wins.
	if tok, ok, err := readToken(path); err != nil {
		return "", err
	} else if ok {
		return tok, nil
	}

	// Mint a candidate. Two concurrent callers will each mint
	// their own, but at most one wins the O_EXCL create below.
	buf := make([]byte, tokenByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api token: generate: %w", err)
	}
	candidate := hex.EncodeToString(buf)

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("api token: mkdir %s: %w", dir, err)
		}
	}

	// Create-or-lose: O_EXCL guarantees the kernel picks exactly
	// one winner across concurrent callers.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, werr := f.WriteString(candidate); werr != nil {
			_ = f.Close()
			return "", fmt.Errorf("api token: write %s: %w", path, werr)
		}
		if cerr := f.Close(); cerr != nil {
			return "", fmt.Errorf("api token: close %s: %w", path, cerr)
		}
		// Re-apply restrictive mode in case umask widened it.
		_ = os.Chmod(path, 0o600)
		return candidate, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("api token: create %s: %w", path, err)
	}

	// The file already exists. Either a concurrent caller won the
	// race (it just wrote a token), or a previous run left an
	// empty/whitespace file behind. Re-read — if it now has a
	// real token, that's our answer.
	if tok, ok, rerr := readToken(path); rerr != nil {
		return "", rerr
	} else if ok {
		return tok, nil
	}

	// Recovery: the file is still whitespace-only. Truncate-and-
	// rewrite, then re-read so concurrent overwriters converge on
	// whichever write hit disk last.
	if err := overwriteTokenFile(path, candidate); err != nil {
		return "", err
	}
	if tok, ok, rerr := readToken(path); rerr != nil {
		return "", rerr
	} else if ok {
		return tok, nil
	}
	return candidate, nil
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

// overwriteTokenFile is the recovery path for an existing empty or
// whitespace-only token file (e.g. a previous run crashed between
// create and write). The primary writer uses O_EXCL; this is reached
// only after readToken confirmed there's nothing useful to preserve.
func overwriteTokenFile(path, token string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("api token: open %s: %w", path, err)
	}
	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		return fmt.Errorf("api token: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("api token: close %s: %w", path, err)
	}
	// Re-apply restrictive mode in case umask widened it.
	_ = os.Chmod(path, 0o600)
	return nil
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
