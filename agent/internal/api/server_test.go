package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtensionIDPinning_RejectsUnpinnedOrigin confirms that once
// SetAllowedExtensionIDs is populated, an extension whose ID is not
// on the allowlist is rejected from control endpoints with 403.
// Before this guard ANY installed extension whose origin had a
// non-empty ID could drive state-changing endpoints, which is the
// posture the A1 work item is closing off.
func TestExtensionIDPinning_RejectsUnpinnedOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	const pinned = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	srv.SetAllowedExtensionIDs([]string{pinned})

	cases := []struct {
		name   string
		origin string
		want   int
	}{
		{
			name:   "pinned chrome extension is allowed",
			origin: "chrome-extension://" + pinned,
			want:   http.StatusNoContent,
		},
		{
			name:   "non-pinned chrome extension is rejected",
			origin: "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			want:   http.StatusForbidden,
		},
		{
			name:   "non-pinned moz extension is rejected",
			origin: "moz-extension://01234567-89ab-cdef-0123-456789abcdef",
			want:   http.StatusForbidden,
		},
		{
			name:   "non-pinned safari extension is rejected",
			origin: "safari-web-extension://01234567-89ab-cdef-0123-456789abcdef",
			want:   http.StatusForbidden,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newLocalRequest(http.MethodOptions, "/api/policies/AI%20Chat%20Blocked", nil)
			r.Header.Set("Origin", c.origin)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code != c.want {
				t.Errorf("origin=%q: code = %d, want %d (body=%q)",
					c.origin, w.Code, c.want, w.Body.String())
			}
		})
	}
}

// TestExtensionIDPinning_EmptyAllowlistKeepsLegacyBehaviour confirms
// the backwards-compat path: with no IDs pinned, ANY non-empty
// extension origin still reaches the control endpoint (matching the
// pre-A1 behaviour). The intent is that operators can opt into the
// stricter pin at their own pace.
func TestExtensionIDPinning_EmptyAllowlistKeepsLegacyBehaviour(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// No SetAllowedExtensionIDs call — allowlist stays nil.

	cases := []string{
		"chrome-extension://abcdefghijklmnopabcdefghijklmnop",
		"moz-extension://01234567-89ab-cdef-0123-456789abcdef",
		"safari-web-extension://01234567-89ab-cdef-0123-456789abcdef",
	}
	for _, origin := range cases {
		r := newLocalRequest(http.MethodOptions, "/api/policies/AI%20Chat%20Blocked", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("origin=%q: code = %d, want 204 (legacy behaviour)",
				origin, w.Code)
		}
	}
}

// TestExtensionIDPinning_RejectsMalformedExtensionOriginsOnControlPath
// guards the ID extractor against trivial spoofs: a
// chrome-extension:// URL with a host containing a dot (which never
// appears in a real extension ID) must be rejected at the control
// path even before the allowlist is consulted. Read-only paths are
// out of scope for this check — they're already gated by
// isAllowedOrigin which accepts the bare extension-scheme prefix.
func TestExtensionIDPinning_RejectsMalformedExtensionOriginsOnControlPath(t *testing.T) {
	srv, _, _ := newTestServer(t)

	cases := []string{
		"chrome-extension://has.dot.in.id",
		"chrome-extension://has spaces in id",
		"moz-extension://has@symbol",
	}
	for _, origin := range cases {
		r := newLocalRequest(http.MethodOptions, "/api/policies/AI%20Chat%20Blocked", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("origin=%q: code = %d, want 403", origin, w.Code)
		}
	}
}

// TestAPIToken_ControlPath401WithoutBearer confirms the Bearer
// middleware rejects a control-path request without an Authorization
// header when the token is required.
func TestAPIToken_ControlPath401WithoutBearer(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAPIToken("secret-token", true)

	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", w.Header().Get("WWW-Authenticate"))
	}
}

// TestAPIToken_ControlPath401WithWrongBearer confirms the middleware
// rejects a control-path request whose token does not match.
func TestAPIToken_ControlPath401WithWrongBearer(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAPIToken("secret-token", true)

	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	r.Header.Set("Authorization", "Bearer not-the-right-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d, want 401", w.Code)
	}
}

// TestAPIToken_ControlPath200WithCorrectBearer confirms a matching
// token lets the request reach the handler.
func TestAPIToken_ControlPath200WithCorrectBearer(t *testing.T) {
	srv, _, view := newTestServer(t)
	srv.SetAPIToken("secret-token", true)

	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	r.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 (body=%q)", w.Code, w.Body.String())
	}
	if view.resets == 0 {
		t.Errorf("stats reset handler did not run")
	}
}

// TestAPIToken_ReadOnlyPathDoesNotRequireBearer confirms read-only
// endpoints (e.g. GET /api/status) remain reachable without a token
// even when the middleware is enforcing — the token gate is scoped
// to isControlPath() only.
func TestAPIToken_ReadOnlyPathDoesNotRequireBearer(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAPIToken("secret-token", true)

	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200", w.Code)
	}
}

// TestAPIToken_StagedRejectsWrongTokenButAcceptsAbsent confirms the
// "staged" mode (required=false): a wrong token still gets 401 (so
// a misbehaving client can't silently impersonate the admin) but an
// absent header falls through to the existing origin-based check.
// This is the migration mode operators can sit on while rolling out
// the matching Electron / extension builds before flipping
// api_token_required to true.
func TestAPIToken_StagedRejectsWrongTokenButAcceptsAbsent(t *testing.T) {
	srv, _, view := newTestServer(t)
	srv.SetAPIToken("secret-token", false /* required */)

	// Wrong token: still 401.
	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: code = %d, want 401", w.Code)
	}

	// Missing header: falls through (legacy mode).
	r = newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("missing header in staged mode: code = %d, want 200", w.Code)
	}
	if view.resets == 0 {
		t.Errorf("stats reset handler did not run in staged-fallthrough mode")
	}
}

// TestAPIToken_DisabledWhenTokenEmpty confirms an empty token
// disables the middleware regardless of the required flag — the
// "no feature" path stays backwards compatible.
func TestAPIToken_DisabledWhenTokenEmpty(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetAPIToken("", true /* required, but token empty */)

	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, want 200 (no token configured)", w.Code)
	}
}

// TestLoadOrCreateAPIToken_CreatesFileWith0600 confirms the file
// helper generates a 64-char hex token (32 bytes -> 64 hex), writes
// it with mode 0600, and returns the same token on subsequent
// reads.
func TestLoadOrCreateAPIToken_CreatesFileWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "api-token")

	first, err := LoadOrCreateAPIToken(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(first) != 2*tokenByteLength {
		t.Errorf("token length = %d, want %d", len(first), 2*tokenByteLength)
	}
	// Re-read on disk — should be identical to what the helper
	// returned, with no trailing whitespace.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.TrimSpace(string(raw)) != first {
		t.Errorf("on-disk token differs from returned token")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// On Windows the mode bits are advisory; only enforce the
	// 0600 check on Unix-like platforms.
	if filepath.Separator == '/' && st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}

	second, err := LoadOrCreateAPIToken(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if second != first {
		t.Errorf("second load returned a different token (regenerated unexpectedly)")
	}
}

// TestLoadOrCreateAPIToken_EmptyPathReturnsEmpty confirms the "feature
// disabled" path: caller passes "" and gets ("", nil), no file
// generated.
func TestLoadOrCreateAPIToken_EmptyPathReturnsEmpty(t *testing.T) {
	tok, err := LoadOrCreateAPIToken("")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if tok != "" {
		t.Errorf("token = %q, want empty", tok)
	}
}

// TestLoadOrCreateAPIToken_RegeneratesWhenFileEmpty confirms that an
// existing but empty (or whitespace-only) file is treated as
// "missing" and a fresh token is generated. This is the behaviour an
// operator gets when they pre-create the file with `touch` so the
// agent can write into a directory they don't control.
func TestLoadOrCreateAPIToken_RegeneratesWhenFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tok, err := LoadOrCreateAPIToken(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(tok) != 2*tokenByteLength {
		t.Errorf("token length = %d, want %d", len(tok), 2*tokenByteLength)
	}
	raw, _ := os.ReadFile(path)
	if strings.TrimSpace(string(raw)) != tok {
		t.Errorf("file content not refreshed")
	}
}

// TestTokenFromRequest covers the parser edge cases the middleware
// relies on: scheme is case-insensitive, surrounding whitespace is
// trimmed, and non-Bearer schemes are rejected so the middleware
// never accidentally treats a Basic credential as a Bearer token.
func TestTokenFromRequest(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Bearer t", "t"},
		{"bearer t", "t"},
		{"BEARER t", "t"},
		{"Bearer   t   ", "t"},
		{"Basic dXNlcjpwYXNz", ""},
		{"Token t", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
	}
	for _, c := range cases {
		r := newLocalRequest(http.MethodGet, "/api/status", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got := tokenFromRequest(r)
		if got != c.want {
			t.Errorf("Authorization=%q: got %q, want %q", c.header, got, c.want)
		}
	}
}
