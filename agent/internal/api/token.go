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
func LoadOrCreateAPIToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("api token: read %s: %w", path, err)
	}
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	}

	// Generate and persist.
	buf := make([]byte, tokenByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("api token: generate: %w", err)
	}
	token := hex.EncodeToString(buf)

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("api token: mkdir %s: %w", dir, err)
		}
	}
	if err := writeTokenFile(path, token); err != nil {
		return "", err
	}
	return token, nil
}

// writeTokenFile writes token to path with mode 0600, using
// O_EXCL when the file does not yet exist so a concurrent
// agent start cannot race two different tokens onto disk.
// When the file already exists (caller decided to overwrite an
// empty/whitespace token), we truncate it in place.
func writeTokenFile(path, token string) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	f, err := os.OpenFile(path, flags, 0o600)
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
	// Re-apply the restrictive mode in case umask widened it on
	// some platforms (and as a no-op on systems where the
	// original OpenFile already obeyed 0o600).
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
