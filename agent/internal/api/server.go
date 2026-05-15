package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/profile"
	"github.com/kennguy3n/secure-edge/agent/internal/rules"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// controlOrigins is the strict allowlist of browser origins permitted
// to call the agent's state-changing (control) endpoints. Only the
// Electron renderer (file:// "null" and the Vite dev server) is listed
// here by exact match; the chrome- / moz- / safari-extension prefixes
// are also treated as control origins via isControlOrigin so any
// installed build of the companion extension can drive the admin
// surface.
//
// AI page origins (Tier-2 tool pages where the content script runs)
// are intentionally NOT included — a compromised AI tool page that
// talks to our agent should be limited to the scan / read endpoints,
// never to policy mutation, proxy enable/disable, or rule updates.
var controlOrigins = map[string]struct{}{
	"null":                  {}, // file:// — packaged Electron renderer
	"http://localhost:5173": {}, // Vite dev server
	"http://127.0.0.1:5173": {},
}

// aiPageOrigins is the set of Tier-2 AI tool page origins where the
// extension's content scripts run. Keep in sync with
// extension/manifest.json content_scripts.matches.
//
// These origins are permitted to call the read-only / scan endpoints
// (POST /api/dlp/scan, GET /api/status, GET /api/stats, etc.) but are
// rejected by isControlOrigin so they cannot reach state-changing
// endpoints (PUT /api/policies/, /api/proxy/enable, etc.). The browser
// stamps the page's own origin (not the extension's) when content
// scripts fetch with mode:"cors", which is why these origins are
// allowlisted at all.
var aiPageOrigins = map[string]struct{}{
	"https://chat.openai.com":       {},
	"https://chatgpt.com":           {},
	"https://claude.ai":             {},
	"https://gemini.google.com":     {},
	"https://copilot.microsoft.com": {},
	"https://www.bing.com":          {},
	"https://you.com":               {},
	"https://www.perplexity.ai":     {},
	"https://huggingface.co":        {},
	"https://poe.com":               {},
	// Tier-2 expansion (P1-2). These chat / agent UIs may be flipped
	// to AllowWithDLP by an enterprise policy; pre-allowing the CORS
	// origin avoids a 403 on the first scan after the flip.
	"https://grok.com":              {},
	"https://x.ai":                  {},
	"https://chat.mistral.ai":       {},
	"https://mistral.ai":            {},
	"https://openrouter.ai":         {},
	"https://chat.lmsys.org":        {},
	"https://aistudio.google.com":   {},
	"https://notebooklm.google.com": {},
}

// allowedOrigins is the union of controlOrigins and aiPageOrigins,
// used by isAllowedOrigin to gate the CORS allowlist on any path. The
// per-path control / read-only split is enforced in withCORS via
// isControlPath + isControlOrigin so wildcard CORS is never used
// (state-changing endpoints exist, so wildcards would be a real
// DNS-rebinding vector).
//
// The Host-header allowlist (allowedHostnames) remains the actual
// DNS-rebinding defence — a hostile site can hijack a DNS name to
// point at 127.0.0.1, but it cannot forge the Host header.
var allowedOrigins = func() map[string]struct{} {
	m := make(map[string]struct{}, len(controlOrigins)+len(aiPageOrigins))
	for k := range controlOrigins {
		m[k] = struct{}{}
	}
	for k := range aiPageOrigins {
		m[k] = struct{}{}
	}
	return m
}()

// chromeExtensionScheme / mozExtensionScheme / safariExtensionScheme
// are matched as prefixes so any companion extension build (unpacked
// dev build, signed Web Store / AMO / App Store build, etc.) is
// accepted without hard-coding its install-time ID. Firefox stamps
// moz-extension://<UUID>, Chrome / Edge / Chromium derivatives use
// chrome-extension://<id>, and Safari stamps
// safari-web-extension://<UUID> on requests from the service worker
// and content scripts.
const (
	chromeExtensionScheme = "chrome-extension://"
	mozExtensionScheme    = "moz-extension://"
	safariExtensionScheme = "safari-web-extension://"
)

// allowedHostnames is the Host-header allowlist. A DNS-rebinding
// attacker can only point a hostname under their control at 127.0.0.1;
// they cannot make the browser send a Host header they don't control.
var allowedHostnames = map[string]struct{}{
	"127.0.0.1": {},
	"localhost": {},
	"::1":       {},
	"[::1]":     {},
}

// Version is the agent version reported by /api/status.
var Version = "0.1.0"

// PolicyEngine is the subset of policy.Engine the API needs.
type PolicyEngine interface {
	Reload(ctx context.Context) error
}

// StatsView is the subset of stats.Counter the API needs.
type StatsView interface {
	GetStats(ctx context.Context) (stats.Snapshot, error)
	Reset(ctx context.Context) error
}

// DLPScanner is the subset of dlp.Pipeline the API needs. It is wired
// in NewServer / SetDLP so the API package does not have to import
// dlp.Pipeline directly for tests.
type DLPScanner interface {
	Scan(ctx context.Context, content string) dlp.ScanResult
	Threshold() *dlp.ThresholdEngine
	SetWeights(w dlp.ScoreWeights)
	Patterns() []*dlp.Pattern
}

// RuleUpdater is the subset of rules.Updater the API needs. Wired in
// SetRuleUpdater so the API package does not import the rules package
// for handler tests.
type RuleUpdater interface {
	CheckNow(ctx context.Context) (rules.Result, error)
	Status() rules.Status
}

// ProxyStatus is the snapshot returned by GET /api/proxy/status.
type ProxyStatus struct {
	Running         bool   `json:"running"`
	CAInstalled     bool   `json:"ca_installed"`
	ProxyConfigured bool   `json:"proxy_configured"`
	ListenAddr      string `json:"listen_addr"`
	CACertPath      string `json:"ca_cert_path,omitempty"`
	DLPScansTotal   int64  `json:"dlp_scans_total"`
	DLPBlocksTotal  int64  `json:"dlp_blocks_total"`
}

// ProxyController is the subset of proxy.Server (and CA management)
// the API needs. Wired in SetProxyController; nil means the
// /api/proxy/* endpoints return 503.
type ProxyController interface {
	Enable(ctx context.Context) (caCertPath string, err error)
	Disable(ctx context.Context, removeCA bool) error
	Status() ProxyStatus
}

// TamperStatus is the body returned by GET /api/tamper/status. It
// mirrors tamper.Status field-for-field so the wire format stays in
// sync with the producer.
type TamperStatus struct {
	DNSOK           bool      `json:"dns_ok"`
	ProxyOK         bool      `json:"proxy_ok"`
	LastCheck       time.Time `json:"last_check"`
	DetectionsTotal int64     `json:"detections_total"`
}

// TamperReporter is the subset of tamper.Detector the API needs.
// Wired in SetTamperReporter; nil means the /api/tamper/* endpoints
// return 503.
type TamperReporter interface {
	Status() TamperStatus
}

// RuleOverride is the subset of rules.OverrideStore the API needs.
// Wired in SetRuleOverride; nil means the override endpoints return
// 503.
type RuleOverride interface {
	Add(domain, list string) error
	Remove(domain string) error
	List() (allow, block []string)
}

// AgentUpdateCheck is the wire shape returned by the agent-update
// check endpoint. Mirrors updater.CheckResult so a separate import is
// not required from this package.
type AgentUpdateCheck struct {
	Latest          string `json:"latest"`
	Current         string `json:"current"`
	UpdateAvailable bool   `json:"update_available"`
	DownloadURL     string `json:"download_url,omitempty"`
}

// AgentUpdateStage is the wire shape returned by the agent-update
// download endpoint.
type AgentUpdateStage struct {
	Version   string `json:"version"`
	StagedAt  string `json:"staged_at"`
	BytesSize int64  `json:"bytes_size"`
}

// AgentSelfUpdater is the subset of updater.Self the API needs. Wired
// in SetAgentUpdater; nil means /api/agent/update* endpoints return
// 503.
type AgentSelfUpdater interface {
	CheckLatest(ctx context.Context) (AgentUpdateCheck, error)
	DownloadAndStage(ctx context.Context) (AgentUpdateStage, error)
}

// Server is the API server (handlers and dependencies).
type Server struct {
	Store           *store.Store
	Policy          PolicyEngine
	Stats           StatsView
	DLP             DLPScanner
	RuleUpdater     RuleUpdater
	Proxy           ProxyController
	Profile         *profile.Holder
	ProfileApply    profile.PolicyStore
	ProfileVerifier *profile.Verifier
	Tamper          TamperReporter
	Rules           RuleOverride
	AgentUpdate     AgentSelfUpdater
	RuleFiles       []string // optional paths whose mtimes feed /api/status
	startedAt       time.Time
	scanLimiter     *rateLimiter
	once            sync.Once

	// allowedExtensionIDs is the optional pinned-ID allowlist set
	// via SetAllowedExtensionIDs. nil / empty means "accept any
	// extension origin with a non-empty ID" (the historical
	// behaviour). When non-nil, only the listed IDs are accepted
	// as control-plane callers from chrome-extension:// /
	// moz-extension:// / safari-web-extension:// origins.
	allowedExtensionIDs map[string]struct{}

	// apiToken is the per-install capability token loaded from
	// the file at config.api_token_path. Empty string means "no
	// token configured", which disables the Bearer middleware
	// regardless of apiTokenRequired.
	apiToken string

	// apiTokenRequired, when true, makes the Bearer middleware
	// reject control-path requests that lack a matching token.
	// When false the middleware still validates a token if one is
	// supplied (so a misbehaving client doesn't silently get
	// admin access with the wrong token) but does not reject
	// callers that omit the header.
	apiTokenRequired bool

	// enforcementMode is the C2 fail-policy posture the agent reports
	// to the browser extension and the Electron tray. Valid values:
	// "personal" (fall-open, default), "team" (fall-open + warn), and
	// "managed" (fall-closed for unreachable / oversized payloads).
	// The agent itself does not enforce the policy — it only owns the
	// canonical value and serves it through /api/status and
	// /api/config/enforcement-mode so every client agrees on the
	// active posture. Mutated only via SetEnforcementMode at startup.
	enforcementMode string

	// riskyFileExtensions is the B2 (Phase 7) override list of
	// lowercase dot-less file extensions the browser extension
	// hard-blocks at the upload gesture. Three possible values:
	//
	//   nil   — operator did not opt in; the extension uses its
	//           built-in baked-in default list. Served as a JSON
	//           document where the `extensions` field is omitted
	//           so the wire format mirrors the absent-key
	//           semantics.
	//   []    — operator explicitly opted out of blocking. Served
	//           as `{"extensions": []}` (an empty array) so the
	//           extension knows to disable enforcement rather than
	//           fall back to its default.
	//   [...] — operator override. Served verbatim.
	//
	// The agent itself does not scan filenames; it only owns this
	// canonical list and serves it through GET
	// /api/config/risky-extensions so every extension build agrees
	// on the policy. Mutated only via SetRiskyFileExtensions at
	// startup.
	riskyFileExtensions    []string
	riskyFileExtensionsSet bool

	// degraded is set when the agent booted but a non-fatal
	// security-relevant subsystem failed to initialise — currently
	// only "team mode tried to load a profile and the load failed".
	// /api/status surfaces this as a top-level "degraded": true so
	// the extension / tray can warn the operator that policy is
	// running on whatever was previously persisted rather than the
	// expected baseline. Mutated only via SetDegraded.
	degraded bool
}

// SetDegraded toggles the degraded flag reported through /api/status.
// Called by the agent boot path when team-mode profile load fails so
// the front-ends can render a "running degraded" warning without
// having to introspect logs. Idempotent.
func (s *Server) SetDegraded(d bool) { s.degraded = d }

// Degraded reports the current degraded flag. Exposed for handler
// tests and for the /api/status response builder.
func (s *Server) Degraded() bool { return s.degraded }

// NewServer returns an API server with its start time set to now.
// The scan rate limiter is initialised with a permissive default that
// can be tightened post-construction via SetScanRateLimit.
func NewServer(s *store.Store, p PolicyEngine, st StatsView) *Server {
	return &Server{
		Store:       s,
		Policy:      p,
		Stats:       st,
		startedAt:   time.Now(),
		scanLimiter: newRateLimiter(100, 100),
	}
}

// SetScanRateLimit replaces the per-process rate limiter applied to
// POST /api/dlp/scan. rate is in tokens per second; burst caps the
// in-flight allowance. A rate <= 0 disables limiting entirely (the
// limiter still exists, just always returns Allow()=true).
func (s *Server) SetScanRateLimit(rate float64, burst int) {
	s.scanLimiter = newRateLimiter(rate, burst)
}

// SetRuleFiles records the on-disk paths whose mtimes are reported
// through GET /api/status. Best-effort: missing or unreadable files
// are simply omitted from the response.
func (s *Server) SetRuleFiles(paths []string) {
	s.RuleFiles = append(s.RuleFiles[:0], paths...)
}

// SetDLP wires a DLP scanner into the server after construction.
// Phase 1 callers don't have to provide one; Phase 2 callers do.
func (s *Server) SetDLP(d DLPScanner) { s.DLP = d }

// SetRuleUpdater wires the rule updater into the server. Phase 3 only;
// when nil the /api/rules/* endpoints return 503.
func (s *Server) SetRuleUpdater(u RuleUpdater) { s.RuleUpdater = u }

// SetProxyController wires the MITM proxy controller into the server.
// Phase 4 only; when nil the /api/proxy/* endpoints return 503.
func (s *Server) SetProxyController(p ProxyController) { s.Proxy = p }

// SetProfile wires a profile holder into the server. When the
// holder's current profile reports Managed=true, policy mutation
// endpoints (PUT /api/policies/:category, PUT /api/dlp/config) return
// 403 — the central deployment owns those knobs.
func (s *Server) SetProfile(h *profile.Holder, ps profile.PolicyStore) {
	s.Profile = h
	s.ProfileApply = ps
}

// SetProfileVerifier wires the D2 Ed25519 verifier into the server.
// Both POST /api/profile/import paths (URL fetch and inline-body)
// enforce the operator's trust posture through this verifier. A nil
// verifier (or one constructed from an empty public key) operates
// in the backwards-compatible warn-once-and-accept posture; a
// verifier with a configured key rejects unsigned / tampered /
// wrong-signature profiles.
func (s *Server) SetProfileVerifier(v *profile.Verifier) {
	s.ProfileVerifier = v
}

// SetTamperReporter wires the tamper detector into the server.
func (s *Server) SetTamperReporter(t TamperReporter) { s.Tamper = t }

// SetRuleOverride wires the admin allow/block override store into
// the server.
func (s *Server) SetRuleOverride(o RuleOverride) { s.Rules = o }

// SetAgentUpdater wires the agent self-updater (Phase 6 Task 15) into
// the server. When nil, /api/agent/update-check and /api/agent/update
// return 503 so the Electron UI can hide the "Check for updates"
// button on builds without a release channel.
func (s *Server) SetAgentUpdater(u AgentSelfUpdater) { s.AgentUpdate = u }

// SetAllowedExtensionIDs pins the browser-extension ID allowlist
// consulted by isControlOrigin. ids may be nil or empty to keep the
// pre-existing "any non-empty ID" behaviour; otherwise only the
// listed IDs are accepted as control-plane callers from
// chrome-extension:// / moz-extension:// / safari-web-extension://
// origins. The check is case-sensitive against the ID substring
// between the scheme and the next "/" (or end of string).
func (s *Server) SetAllowedExtensionIDs(ids []string) {
	if len(ids) == 0 {
		s.allowedExtensionIDs = nil
		return
	}
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		m[id] = struct{}{}
	}
	if len(m) == 0 {
		s.allowedExtensionIDs = nil
		return
	}
	s.allowedExtensionIDs = m
}

// SetAPIToken installs the per-install capability token. An empty
// token disables Bearer validation regardless of the required flag.
// When required is true and token is non-empty, control-path
// requests without a matching "Authorization: Bearer <token>" header
// receive 401. When required is false the token is still accepted
// on valid requests (so a correctly-configured client doesn't get
// silently downgraded) but missing-header requests fall through to
// the existing origin-based authorisation — preserving backwards
// compatibility with installs that have not yet rolled out the
// matching Electron / extension builds.
func (s *Server) SetAPIToken(token string, required bool) {
	s.apiToken = token
	s.apiTokenRequired = required
}

// SetEnforcementMode records the C2 fail-policy posture the agent
// reports to clients. Valid values are "personal", "team", and
// "managed"; an empty string is normalised to "personal" so callers
// can pass cfg.EnforcementMode through unchanged. Any other value is
// silently coerced to "personal" — config.validate() is the
// authoritative gate, so reaching this function with an unexpected
// value means the operator bypassed config loading and the safest
// behaviour is the conservative fall-open default rather than a
// startup panic.
func (s *Server) SetEnforcementMode(mode string) {
	switch mode {
	case "personal", "team", "managed":
		s.enforcementMode = mode
	default:
		s.enforcementMode = "personal"
	}
}

// EnforcementMode returns the currently configured fail-policy
// posture. Always one of "personal", "team", "managed"; defaults to
// "personal" when SetEnforcementMode was never called.
func (s *Server) EnforcementMode() string {
	if s.enforcementMode == "" {
		return "personal"
	}
	return s.enforcementMode
}

// SetRiskyFileExtensions records the B2 risky-extension blocklist
// the agent advertises to browser extension clients. The argument
// distinguishes three states:
//
//	nil   — operator did not opt in; the extension uses its
//	        built-in baked-in default. The agent advertises this
//	        by omitting the `extensions` field from the response.
//	[]    — operator explicitly opted out; the extension disables
//	        enforcement. The agent advertises this by serving an
//	        empty array.
//	[...] — operator override; served verbatim.
//
// Callers should pass cfg.RiskyFileExtensions through unchanged —
// config.Load normalises entries to lowercase dot-less form and
// preserves the nil-vs-empty-vs-populated distinction.
//
// Idempotent: a server that never had this setter called returns
// the same "use default" wire shape as one that called
// SetRiskyFileExtensions(nil).
func (s *Server) SetRiskyFileExtensions(exts []string) {
	if exts == nil {
		s.riskyFileExtensions = nil
		s.riskyFileExtensionsSet = false
		return
	}
	// Defensive copy: the caller may keep the slice and mutate
	// it later; the server's view must be stable across reads.
	cp := make([]string, len(exts))
	copy(cp, exts)
	s.riskyFileExtensions = cp
	s.riskyFileExtensionsSet = true
}

// RiskyFileExtensions returns (list, configured). list is a defensive
// copy of the configured override list (nil when the operator
// did not opt in, or empty when they explicitly opted out).
// configured is true when SetRiskyFileExtensions was called with
// a non-nil argument; false when nothing was configured. The
// handler uses the bool to decide whether to emit the `extensions`
// field at all on the wire — absent field tells the extension to
// fall back to its baked-in default.
func (s *Server) RiskyFileExtensions() ([]string, bool) {
	if !s.riskyFileExtensionsSet {
		return nil, false
	}
	cp := make([]string, len(s.riskyFileExtensions))
	copy(cp, s.riskyFileExtensions)
	return cp, true
}


// Handler returns the http.Handler wired with all routes and CORS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/policies", s.handlePoliciesCollection)
	mux.HandleFunc("/api/policies/", s.handlePolicyItem)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/reset", s.handleStatsReset)
	mux.Handle("/api/dlp/scan", rateLimitMiddleware(func() *rateLimiter { return s.scanLimiter }, http.HandlerFunc(s.handleDLPScan)))
	mux.HandleFunc("/api/dlp/config", s.handleDLPConfig)
	mux.HandleFunc("/api/rules/update", s.handleRulesUpdate)
	mux.HandleFunc("/api/rules/status", s.handleRulesStatus)
	mux.HandleFunc("/api/proxy/enable", s.handleProxyEnable)
	mux.HandleFunc("/api/proxy/disable", s.handleProxyDisable)
	mux.HandleFunc("/api/proxy/status", s.handleProxyStatus)
	mux.HandleFunc("/api/profile", s.handleProfileGet)
	mux.HandleFunc("/api/profile/import", s.handleProfileImport)
	mux.HandleFunc("/api/tamper/status", s.handleTamperStatus)
	mux.HandleFunc("/api/stats/export", s.handleStatsExport)
	mux.HandleFunc("/api/rules/override", s.handleRuleOverride)
	mux.HandleFunc("/api/rules/override/", s.handleRuleOverrideItem)
	mux.HandleFunc("/api/agent/update-check", s.handleAgentUpdateCheck)
	mux.HandleFunc("/api/agent/update", s.handleAgentUpdate)
	mux.HandleFunc("/api/config/enforcement-mode", s.handleEnforcementMode)
	mux.HandleFunc("/api/config/risky-extensions", s.handleRiskyExtensions)
	return s.withCORS(mux)
}

// ListenAndServe starts the HTTP server in a background goroutine and
// returns the *http.Server so callers can shut it down gracefully.
func (s *Server) ListenAndServe(addr string) (*http.Server, error) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return nil, err
	case <-time.After(100 * time.Millisecond):
	}
	return srv, nil
}

func (s *Server) withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Host-header allowlist: blocks DNS-rebinding (the browser sends
		// the attacker-controlled hostname in the Host header even after
		// the A record flips to 127.0.0.1).
		if !isAllowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		// Echo Access-Control-* only for known callers (Electron
		// renderer / Vite dev / companion extension / Tier-2 AI pages).
		// Requests without an Origin header (Electron main process via
		// Node http, curl, etc.) are allowed through but receive no
		// CORS headers.
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !isAllowedOrigin(origin) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			// Per-path control / read-only split: AI page origins
			// (Tier-2 tool pages where the content script runs) may
			// call scan / status / read endpoints but MUST NOT reach
			// state-changing endpoints (policy mutation, proxy
			// enable / disable, profile import, rule updates /
			// overrides, agent self-update, stats reset). The Origin
			// check is in series with the Host-header check above;
			// together they keep both a DNS-rebinding attacker and a
			// compromised AI tool page out of the admin surface.
			if isControlPath(r.URL.Path) && !s.isControlOrigin(origin) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Bearer-token enforcement for state-changing endpoints.
		// This runs after the Origin and Host checks so the failure
		// mode for an unauthenticated control caller is 401 (rather
		// than 403 from CORS) — useful signal for the Electron tray,
		// which can then surface "agent rejected token" to the user.
		//
		// When apiToken is empty (operator hasn't configured the
		// token feature yet) we skip this gate entirely, preserving
		// the pre-existing origin-only authorisation model. When
		// apiToken is set but apiTokenRequired is false ("staged")
		// we validate any token the caller supplies but accept a
		// missing header — useful for rolling out the token to
		// extension and tray builds before enforcing.
		if s.apiToken != "" && isControlPath(r.URL.Path) {
			got := tokenFromRequest(r)
			switch {
			case got == "":
				if s.apiTokenRequired {
					w.Header().Set("WWW-Authenticate", "Bearer")
					http.Error(w, "missing bearer token", http.StatusUnauthorized)
					return
				}
			case !tokensEqual(got, s.apiToken):
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

// isControlPath reports whether path is a state-changing endpoint
// that must reject AI page origins. The list mirrors the mux
// registrations in Handler() — keep them in sync.
//
// Endpoints intentionally absent from this list (POST /api/dlp/scan,
// GET /api/status, GET /api/stats, GET /api/stats/export,
// GET /api/proxy/status, GET /api/tamper/status,
// GET /api/rules/status, GET /api/profile, GET /api/policies) are
// read-only or scan-only and are reachable from AI page origins.
//
// Note on /api/dlp/config: this path is matched here regardless of
// HTTP method, so GET /api/dlp/config is ALSO blocked from AI page
// origins. That is deliberate, not an oversight — the DLP config
// response includes per-category thresholds, entropy weights, and
// classifier mappings. An adversarial Tier-2 page that could read
// those numbers could tune its exfil payload to score just under
// the block threshold. The Electron tray and the installed extension
// are the only legitimate readers of DLP config, and both reach the
// endpoint through controlOrigins (or one of the extension schemes),
// not through aiPageOrigins. If a future client running on an AI
// page genuinely needs to display config to the user, expose a
// narrowed read-only projection on a separate path rather than
// loosening this guard.
func isControlPath(path string) bool {
	switch path {
	case "/api/dlp/config",
		"/api/proxy/enable",
		"/api/proxy/disable",
		"/api/profile/import",
		"/api/rules/update",
		"/api/rules/override",
		"/api/agent/update",
		"/api/agent/update-check",
		"/api/stats/reset":
		return true
	}
	// Prefix-matched collections with item children:
	//   PUT /api/policies/:category      — state-changing per-category policy
	//   POST/DELETE /api/rules/override/ — admin allow/block overrides
	// /api/policies (no trailing slash) is the read-only listing handler
	// and is NOT matched here.
	return strings.HasPrefix(path, "/api/policies/") ||
		strings.HasPrefix(path, "/api/rules/override/")
}

// isControlOrigin reports whether origin is permitted to call
// state-changing endpoints. AI page origins (Tier-2 tool pages) are
// explicitly excluded; only the Electron renderer and any installed
// build of the companion extension qualify.
//
// When s.allowedExtensionIDs is non-empty, an extension-scheme
// origin is accepted only if the ID portion (between scheme and
// the next slash) is in the allowlist. An empty allowlist preserves
// the pre-existing "any non-empty ID" behaviour; the operator-
// recommended configuration is to populate the allowlist with the
// install-time IDs of the Web Store / AMO / App Store builds.
func (s *Server) isControlOrigin(origin string) bool {
	if _, ok := aiPageOrigins[origin]; ok {
		return false
	}
	if _, ok := controlOrigins[origin]; ok {
		return true
	}
	if id, ok := extractExtensionID(origin); ok {
		return s.extensionIDAllowed(id)
	}
	return false
}

// extractExtensionID returns the (id, true) parsed from a
// chrome-extension://, moz-extension://, or safari-web-extension://
// origin. The id is the substring between the scheme and the next
// slash or end-of-string. ok is false for other schemes, an empty
// id, or an id containing characters that should never appear in a
// real extension ID (a defensive check against trivial spoofs).
func extractExtensionID(origin string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(origin, chromeExtensionScheme):
		rest = origin[len(chromeExtensionScheme):]
	case strings.HasPrefix(origin, mozExtensionScheme):
		rest = origin[len(mozExtensionScheme):]
	case strings.HasPrefix(origin, safariExtensionScheme):
		rest = origin[len(safariExtensionScheme):]
	default:
		return "", false
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	// Real Chrome IDs are 32 lowercase letters [a-p]; Firefox and
	// Safari use UUIDs (hex + dashes + curly braces). Reject
	// anything outside the union of those character classes so a
	// path-traversal-ish origin like
	// "chrome-extension://attacker.com/" doesn't even reach the
	// allowlist check.
	for _, c := range rest {
		if !isValidExtensionIDChar(c) {
			return "", false
		}
	}
	return rest, true
}

func isValidExtensionIDChar(c rune) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-', c == '{', c == '}':
		return true
	}
	return false
}

// extensionIDAllowed reports whether id is permitted to act as a
// control caller. When s.allowedExtensionIDs is nil/empty we fall
// back to the historical "any non-empty ID" rule; otherwise we
// require an exact case-sensitive match.
func (s *Server) extensionIDAllowed(id string) bool {
	if id == "" {
		return false
	}
	if len(s.allowedExtensionIDs) == 0 {
		return true
	}
	_, ok := s.allowedExtensionIDs[id]
	return ok
}

func isAllowedOrigin(origin string) bool {
	if _, ok := allowedOrigins[origin]; ok {
		return true
	}
	// chrome-extension://<id>, moz-extension://<UUID>, or
	// safari-web-extension://<UUID> — any installed build of the
	// companion extension's service worker. The host_permissions in
	// the extension's own manifest gate which hosts the extension can
	// reach.
	if strings.HasPrefix(origin, chromeExtensionScheme) &&
		len(origin) > len(chromeExtensionScheme) {
		return true
	}
	if strings.HasPrefix(origin, mozExtensionScheme) &&
		len(origin) > len(mozExtensionScheme) {
		return true
	}
	if strings.HasPrefix(origin, safariExtensionScheme) &&
		len(origin) > len(safariExtensionScheme) {
		return true
	}
	return false
}

func isAllowedHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	_, ok := allowedHostnames[strings.ToLower(h)]
	return ok
}
