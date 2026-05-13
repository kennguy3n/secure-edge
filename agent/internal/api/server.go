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

// allowedOrigins is the strict allowlist of browser origins that are
// permitted to talk to the local agent. Three classes are accepted,
// all enforced through isAllowedOrigin so wildcard CORS is never used
// (state-changing endpoints exist, so wildcards would be a real
// DNS-rebinding vector):
//
//  1. The Electron renderer: file:// in production (Origin: "null")
//     and the Vite dev server. Exact match.
//  2. The browser companion extension's service worker, which sends
//     Origin: chrome-extension://<extension-id>. The ID is fixed once
//     the extension is published but not knowable at compile time, so
//     any chrome-extension://* origin is accepted. Host permissions in
//     the extension's own manifest gate which agents the extension is
//     allowed to call — the Origin check here is in series with that.
//  3. The 10 Tier-2 AI tool pages where the paste-interceptor content
//     script runs. The browser stamps the page's own origin (not the
//     extension's) when content scripts fetch with mode:"cors", so
//     these origins must be explicitly listed. The list is the same
//     set as extension/manifest.json's content_scripts.matches.
//
// The Host-header allowlist (allowedHostnames) remains the actual
// DNS-rebinding defence — a hostile site can hijack a DNS name to
// point at 127.0.0.1, but it cannot forge the Host header.
var allowedOrigins = map[string]struct{}{
	"null":                  {}, // file:// — packaged Electron renderer
	"http://localhost:5173": {}, // Vite dev server
	"http://127.0.0.1:5173": {},

	// Tier-2 AI tools (extension content scripts). Keep in sync with
	// extension/manifest.json content_scripts.matches.
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
}

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
	Store        *store.Store
	Policy       PolicyEngine
	Stats        StatsView
	DLP          DLPScanner
	RuleUpdater  RuleUpdater
	Proxy        ProxyController
	Profile      *profile.Holder
	ProfileApply profile.PolicyStore
	Tamper       TamperReporter
	Rules        RuleOverride
	AgentUpdate  AgentSelfUpdater
	RuleFiles    []string // optional paths whose mtimes feed /api/status
	startedAt    time.Time
	scanLimiter  *rateLimiter
	once         sync.Once
}

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
	return withCORS(mux)
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

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Host-header allowlist: blocks DNS-rebinding (the browser sends
		// the attacker-controlled hostname in the Host header even after
		// the A record flips to 127.0.0.1).
		if !isAllowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}

		// Echo Access-Control-* only for known callers (Electron
		// renderer / Vite dev). Requests without an Origin header
		// (Electron main process via Node http, curl, etc.) are
		// allowed through but receive no CORS headers.
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !isAllowedOrigin(origin) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
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
