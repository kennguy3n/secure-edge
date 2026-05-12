package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// StatusResponse is the body for GET /api/status.
type StatusResponse struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime"`
	Version string `json:"version"`
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
	writeJSON(w, http.StatusOK, StatusResponse{
		Status:  "running",
		Uptime:  formatUptime(time.Since(s.startedAt)),
		Version: Version,
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
