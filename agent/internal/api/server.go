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

// chromeExtensionScheme is matched as a prefix so any companion
// extension build (unpacked dev build, signed Web Store build, etc.)
// is accepted without hard-coding its install-time ID.
const chromeExtensionScheme = "chrome-extension://"

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
}

// Server is the API server (handlers and dependencies).
type Server struct {
	Store     *store.Store
	Policy    PolicyEngine
	Stats     StatsView
	DLP       DLPScanner
	startedAt time.Time
	once      sync.Once
}

// NewServer returns an API server with its start time set to now.
func NewServer(s *store.Store, p PolicyEngine, st StatsView) *Server {
	return &Server{Store: s, Policy: p, Stats: st, startedAt: time.Now()}
}

// SetDLP wires a DLP scanner into the server after construction.
// Phase 1 callers don't have to provide one; Phase 2 callers do.
func (s *Server) SetDLP(d DLPScanner) { s.DLP = d }

// Handler returns the http.Handler wired with all routes and CORS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/policies", s.handlePoliciesCollection)
	mux.HandleFunc("/api/policies/", s.handlePolicyItem)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/reset", s.handleStatsReset)
	mux.HandleFunc("/api/dlp/scan", s.handleDLPScan)
	mux.HandleFunc("/api/dlp/config", s.handleDLPConfig)
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
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
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
	// chrome-extension://<id> — any installed build of the companion
	// extension's service worker. The host_permissions in the
	// extension manifest gate which hosts the extension can reach.
	if strings.HasPrefix(origin, chromeExtensionScheme) &&
		len(origin) > len(chromeExtensionScheme) {
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
