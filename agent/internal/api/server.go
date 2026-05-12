package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

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

// Server is the API server (handlers and dependencies).
type Server struct {
	Store     *store.Store
	Policy    PolicyEngine
	Stats     StatsView
	startedAt time.Time
	once      sync.Once
}

// NewServer returns an API server with its start time set to now.
func NewServer(s *store.Store, p PolicyEngine, st StatsView) *Server {
	return &Server{Store: s, Policy: p, Stats: st, startedAt: time.Now()}
}

// Handler returns the http.Handler wired with all routes and CORS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/policies", s.handlePoliciesCollection)
	mux.HandleFunc("/api/policies/", s.handlePolicyItem)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stats/reset", s.handleStatsReset)
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
		// The Electron tray app runs on localhost only.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}
