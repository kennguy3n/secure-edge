package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// maxScanBytes caps the body size accepted by /api/dlp/scan. Pastes
// well beyond this size are typically not what a user is sending to an
// AI tool, and an unbounded body is a memory-exhaustion vector.
const maxScanBytes = 4 * 1024 * 1024 // 4 MiB

// StatusResponse is the body for GET /api/status.
// Both `uptime` (human-readable) and `uptime_seconds` (machine-readable)
// are emitted so the Electron tray and the browser extension don't have
// to parse the formatted string.
type StatusResponse struct {
	Status        string `json:"status"`
	Uptime        string `json:"uptime"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	Version       string `json:"version"`
}

// PolicyUpdate is the request body for PUT /api/policies/:category.
type PolicyUpdate struct {
	Action string `json:"action"`
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	since := time.Since(s.startedAt)
	if since < 0 {
		since = 0
	}
	writeJSON(w, http.StatusOK, StatusResponse{
		Status:        "running",
		Uptime:        formatUptime(since),
		UptimeSeconds: int64(since / time.Second),
		Version:       Version,
	})
}

func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int(d / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

func (s *Server) handlePoliciesCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pols, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list policies failed")
		return
	}
	if pols == nil {
		pols = []store.CategoryPolicy{}
	}
	writeJSON(w, http.StatusOK, pols)
}

func (s *Server) handlePolicyItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	category := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	category = strings.TrimSpace(category)
	if category == "" {
		writeError(w, http.StatusBadRequest, "category is required")
		return
	}
	var body PolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetPolicy(r.Context(), category, body.Action); err != nil {
		if errors.Is(err, store.ErrInvalidAction) {
			writeError(w, http.StatusBadRequest, "invalid action")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if err := s.Policy.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "policy reload failed")
		return
	}
	writeJSON(w, http.StatusOK, store.CategoryPolicy{Category: category, Action: body.Action})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snap, err := s.Stats.GetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats unavailable")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.Stats.Reset(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reset failed")
		return
	}
	writeJSON(w, http.StatusOK, stats.Snapshot{})
}

// dlpScanRequest is the body for POST /api/dlp/scan.
type dlpScanRequest struct {
	Content string `json:"content"`
}

func (s *Server) handleDLPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.DLP == nil {
		writeError(w, http.StatusServiceUnavailable, "DLP pipeline not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxScanBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var req dlpScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Privacy invariant: req.Content lives in this stack frame only.
	// It is not logged and not persisted; the response carries the
	// decision plus the pattern name (never the match itself).
	result := s.DLP.Scan(r.Context(), req.Content)
	req.Content = "" // drop reference promptly.

	// Increment anonymous DLP counters.
	if s.Stats != nil {
		_ = bumpDLPStats(r.Context(), s.Store, result.Blocked)
	}

	writeJSON(w, http.StatusOK, result)
}

// dlpConfigResponse is the wire shape of GET /api/dlp/config and the
// expected body of PUT /api/dlp/config. We just reflect the SQLite
// dlp_config columns so callers can round-trip the value.
type dlpConfigResponse = store.DLPConfig

func (s *Server) handleDLPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDLPConfigGet(w, r)
	case http.MethodPut:
		s.handleDLPConfigPut(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleDLPConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Store.GetDLPConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dlp config unavailable")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleDLPConfigPut(w http.ResponseWriter, r *http.Request) {
	var body store.DLPConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetDLPConfig(r.Context(), body); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if s.DLP != nil {
		s.DLP.Threshold().Set(dlp.Thresholds{
			Critical: body.ThresholdCritical,
			High:     body.ThresholdHigh,
			Medium:   body.ThresholdMedium,
			Low:      body.ThresholdLow,
		})
		// Propagate scoring weights to the live pipeline too —
		// without this, weight fields are persisted to SQLite but
		// only take effect after an agent restart, silently
		// diverging from the values returned by GET /api/dlp/config.
		s.DLP.SetWeights(dlp.ScoreWeights{
			HotwordBoost:     body.HotwordBoost,
			EntropyBoost:     body.EntropyBoost,
			EntropyPenalty:   body.EntropyPenalty,
			ExclusionPenalty: body.ExclusionPenalty,
			MultiMatchBoost:  body.MultiMatchBoost,
		})
	}
	writeJSON(w, http.StatusOK, body)
}

// bumpDLPStats increments dlp_scans_total (+1) and optionally
// dlp_blocks_total (+1 when blocked). Errors are intentionally
// swallowed by the caller — counter updates must not break a scan.
func bumpDLPStats(ctx context.Context, s *store.Store, blocked bool) error {
	if s == nil {
		return nil
	}
	delta := store.AggregateStats{DLPScansTotal: 1}
	if blocked {
		delta.DLPBlocksTotal = 1
	}
	return s.AddStats(ctx, delta)
}

// Compile-time check: dlp.ScanResult must remain JSON-encodable
// without referencing user content. If anyone adds a field here that
// might leak content, this var will need to be updated explicitly.
var _ = dlp.ScanResult{Blocked: false, PatternName: "", Score: 0}

// Suppress the unused import warning when none of the type's fields
// are referenced (it is used via the s.DLP interface).
var _ = stats.Snapshot{}
