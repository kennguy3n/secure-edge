package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/profile"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// osStat is a thin indirection so tests can stub the filesystem. The
// default points at os.Stat; tests can replace it to drive
// collectRuleFileInfo against an in-memory fixture.
var osStat = func(name string) (os.FileInfo, error) { return os.Stat(name) }

// maxScanBytes caps the body size accepted by /api/dlp/scan. Pastes
// well beyond this size are typically not what a user is sending to an
// AI tool, and an unbounded body is a memory-exhaustion vector.
const maxScanBytes = 4 * 1024 * 1024 // 4 MiB

// maxControlBytes caps the body size accepted by every JSON control
// endpoint that is not /api/dlp/scan or /api/profile/import. The
// control surface accepts small documents (a single category /
// action pair, a DLP-config struct, a single allow/block override,
// etc.) — none of these legitimately exceed a few hundred bytes, so
// 64 KiB is comfortable for headroom while still keeping an
// unbounded body from forcing the agent to buffer megabytes of
// attacker-controlled JSON before json.Decode has a chance to
// reject it. Wired in via http.MaxBytesReader so the handler
// surfaces 413 Request Entity Too Large with a consistent error
// shape — the same status code MaxBytesReader uses by convention.
const maxControlBytes = 64 * 1024 // 64 KiB

// StatusResponse is the body for GET /api/status.
// Both `uptime` (human-readable) and `uptime_seconds` (machine-readable)
// are emitted so the Electron tray and the browser extension don't have
// to parse the formatted string. The optional `runtime` and `rules`
// sections were added in Phase 6 (Task 17). All embedded values are
// non-sensitive operational metadata — no scan content, domains, URLs,
// IPs, or user identifiers ever appear here.
type StatusResponse struct {
	Status        string         `json:"status"`
	Uptime        string         `json:"uptime"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Version       string         `json:"version"`
	Runtime       RuntimeStats   `json:"runtime,omitempty"`
	Rules         []RuleFileInfo `json:"rules,omitempty"`
	DLPPatterns   int            `json:"dlp_patterns,omitempty"`
	// EnforcementMode is the C2 fail-policy posture the
	// extension consults when the agent is unreachable or the
	// content exceeds its inline-scan size limit. Always one of
	// "personal", "team", "managed". Surfaced here (rather than
	// only on /api/config/enforcement-mode) so the Electron tray
	// can show the active posture in its existing /api/status
	// poll without an extra round trip.
	EnforcementMode string `json:"enforcement_mode"`
	// Degraded is true when the agent booted but a security-relevant
	// subsystem failed to initialise (currently only "team mode
	// profile load failed"). Omitted from the wire when false so the
	// happy-path payload is unchanged; present as true so the
	// extension / tray can render a "running degraded" warning.
	Degraded bool `json:"degraded,omitempty"`
}

// EnforcementModeResponse is the body served by
// GET /api/config/enforcement-mode. The endpoint exists in addition
// to the /api/status echo so the browser extension's service worker
// can fetch the mode in isolation on cold start without parsing the
// full status payload (which carries Go runtime counters the
// extension neither needs nor should see).
type EnforcementModeResponse struct {
	Mode string `json:"mode"`
}

// RiskyExtensionsResponse is the body served by
// GET /api/config/risky-extensions. The B2 (Phase 7) endpoint
// advertises the agent's override list of risky file extensions
// the browser extension hard-blocks at the upload gesture.
//
// Three wire shapes are distinguished:
//
//	{}                          — `extensions` field omitted. The
//	                              operator did not opt in; the
//	                              extension uses its built-in
//	                              baked-in default list.
//	{"extensions": []}          — explicit empty list. The operator
//	                              opted out; the extension disables
//	                              risky-extension blocking entirely.
//	{"extensions": ["exe",...]} — operator-supplied override.
//
// Entries are lowercase dot-less file extensions (e.g. "exe",
// "scr") — config.Load normalises them on parse.
type RiskyExtensionsResponse struct {
	// Extensions is a pointer-to-slice so a nil value omits the
	// JSON field entirely (the "use baked-in default" wire shape)
	// while an explicit empty slice serialises as `[]` (the
	// "opt-out" wire shape). Without the pointer indirection JSON
	// encoding folds both into `null` (omitempty) or `null`
	// (without omitempty), and we'd lose the distinction
	// operators relied on at config-load time.
	Extensions *[]string `json:"extensions,omitempty"`
}

// RuntimeStats captures Go runtime counters surfaced via /api/status.
// All fields are derived from runtime.MemStats / runtime.NumGoroutine
// and contain no user-derived data.
type RuntimeStats struct {
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCPU       int    `json:"num_cpu"`
	HeapAllocKB  uint64 `json:"heap_alloc_kb"`
	HeapInuseKB  uint64 `json:"heap_inuse_kb"`
	SysKB        uint64 `json:"sys_kb"`
	NumGC        uint32 `json:"num_gc"`
	GoMaxProcs   int    `json:"gomaxprocs"`
}

// RuleFileInfo carries the modification time and byte size of a rule
// file. Paths are echoed back unchanged so callers know which file is
// which.
type RuleFileInfo struct {
	Path         string    `json:"path"`
	SizeBytes    int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
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

// capControlBody applies maxControlBytes to r.Body without decoding
// it. Use this on POST/PUT control handlers whose business logic
// does not read the body — e.g. `POST /api/proxy/enable`,
// `POST /api/rules/update`, `POST /api/stats/reset`,
// `POST /api/agent/update` — so the server-side body drain that
// keeps the connection alive is bounded. Without this, a hostile
// peer can ship megabytes of payload at an endpoint that does not
// look at it and waste server I/O budget; MaxBytesReader returns an
// error from the reader once the cap is hit and tells the
// ResponseWriter to close the connection. Cheap belt-and-suspenders
// for the JSON control surface; the body-reading siblings call
// decodeControlBody instead.
func capControlBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxControlBytes)
}

// allowLongWrite drops the per-connection write deadline that
// http.Server.WriteTimeout sets on every request. The control API
// runs with a 10 s WriteTimeout (set in api/server.go) so a stalled
// peer cannot pin a listener thread, but three control handlers
// legitimately do outbound IO that can outlast 10 s and need the
// response budget extended: handleRulesUpdate (signed rule manifest
// fetch), handleAgentUpdate (agent binary download), and
// handleProfileImport (profile URL fetch). Each handler is still
// bounded by its own client timeout and by r.Context() (which
// inherits ReadHeaderTimeout + ReadTimeout for the request side),
// so removing the write deadline does not open a hang vector —
// the worst case for a stuck handler is the client-timeout budget,
// not an unbounded wait.
//
// A zero time.Time means "no deadline" per net/http semantics.
// http.NewResponseController is the supported way to mutate the
// per-request deadline introduced in Go 1.20.
func allowLongWrite(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

// decodeControlBody caps r.Body at maxControlBytes via
// http.MaxBytesReader and json.Decodes into dst. It writes a 413
// when the body exceeds the cap (so the caller doesn't conflate
// "too big" with "malformed JSON") and a 400 when the JSON is
// otherwise invalid. allowEmpty is for the two endpoints whose
// body is optional (POST /api/proxy/disable, POST /api/rules/local
// reload) — passing true treats io.EOF as a no-op.
//
// The returned bool is true when decoding succeeded; the caller
// should `return` immediately when it is false because an error
// response has already been written.
func decodeControlBody(w http.ResponseWriter, r *http.Request, dst any, allowEmpty bool) bool {
	capControlBody(w, r)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return true
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
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

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rt := RuntimeStats{
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		HeapAllocKB:  ms.HeapAlloc / 1024,
		HeapInuseKB:  ms.HeapInuse / 1024,
		SysKB:        ms.Sys / 1024,
		NumGC:        ms.NumGC,
		GoMaxProcs:   runtime.GOMAXPROCS(0),
	}

	resp := StatusResponse{
		Status:          "running",
		Uptime:          formatUptime(since),
		UptimeSeconds:   int64(since / time.Second),
		Version:         Version,
		Runtime:         rt,
		EnforcementMode: s.EnforcementMode(),
		Degraded:        s.Degraded(),
	}
	if s.DLP != nil {
		resp.DLPPatterns = len(s.DLP.Patterns())
	}
	if len(s.RuleFiles) > 0 {
		resp.Rules = collectRuleFileInfo(s.RuleFiles, s.statusDebugEnabled(r))
	}
	writeJSON(w, http.StatusOK, resp)
}

// statusDebugEnabled reports whether the caller asked for the
// debug-only full rule-file paths AND is allowed to receive them.
// The default response strips paths to filepath.Base() so an
// extension page (or any unauthenticated caller) cannot enumerate
// the operator's filesystem layout via /api/status.
//
// The agent's listener binds to 127.0.0.1, so RemoteAddr is always
// loopback and gating on RemoteAddr alone is dead code — a content
// script on an AI-page origin allowed by CORS would still appear as
// a loopback caller. Instead we gate on the request Origin:
//
//   - no Origin header (curl / direct CLI calls from the operator's
//     shell) → debug allowed; this is the local-troubleshooting path.
//   - Origin matches a control origin (Electron renderer or an
//     allowlisted extension build, per s.isControlOrigin) → debug
//     allowed; the tray needs full paths for its diagnostics view.
//   - Origin is anything else (notably any aiPageOrigins entry) →
//     debug rejected so a compromised AI-page script cannot use
//     ?debug=true to read the operator's install layout.
func (s *Server) statusDebugEnabled(r *http.Request) bool {
	if r == nil || s == nil {
		return false
	}
	if r.URL == nil || r.URL.Query().Get("debug") != "true" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return s.isControlOrigin(origin)
}

// collectRuleFileInfo gathers mtime + size for each rule file path
// the agent was started with. Missing files are silently skipped so a
// partial deployment (e.g. an upcoming rule file not yet present)
// doesn't break the status endpoint.
//
// When debug is false (the default), the returned Path field is the
// basename of the on-disk file rather than the absolute path. The
// default /api/status response is reachable from the browser
// extension; exposing full filesystem paths there would leak the
// operator's install layout for negligible operational value. Debug
// mode (?debug=true from localhost) restores the full path so local
// troubleshooting still has what it needs.
func collectRuleFileInfo(paths []string, debug bool) []RuleFileInfo {
	out := make([]RuleFileInfo, 0, len(paths))
	for _, p := range paths {
		fi, err := osStat(p)
		if err != nil {
			continue
		}
		shown := p
		if !debug {
			shown = filepath.Base(p)
		}
		out = append(out, RuleFileInfo{
			Path:         shown,
			SizeBytes:    fi.Size(),
			LastModified: fi.ModTime(),
		})
	}
	return out
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

// handleEnforcementMode serves the C2 fail-policy posture as a small
// JSON document the extension's service worker fetches on cold start.
// The endpoint is read-only — there is no PUT/POST counterpart;
// mutation goes through config.yaml + agent restart so the value is
// always rooted in the operator-controlled config file rather than
// any runtime API surface. That keeps the policy decision out of
// reach of a compromised AI page origin or a hostile Tier-2 tool.
func (s *Server) handleEnforcementMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, EnforcementModeResponse{Mode: s.EnforcementMode()})
}

// handleRiskyExtensions serves the B2 risky-file-extension blocklist
// as a small JSON document the extension's service worker fetches on
// cold start. Read-only — there is no PUT/POST counterpart; mutation
// goes through config.yaml + agent restart so the value is always
// rooted in the operator-controlled config file rather than any
// runtime API surface. That keeps the policy decision out of reach
// of a compromised AI page origin or a hostile Tier-2 tool.
//
// See RiskyExtensionsResponse for the three wire shapes (absent
// field = "use default", empty array = "opt-out", populated array
// = "override").
func (s *Server) handleRiskyExtensions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	exts, configured := s.RiskyFileExtensions()
	resp := RiskyExtensionsResponse{}
	if configured {
		// Re-bind the slice value to a fresh local so the JSON
		// encoder serialises the empty case as `[]` instead of
		// `null`. *RiskyExtensionsResponse.Extensions = nil
		// would produce `null` with omitempty falling through to
		// "absent field" — but the "operator-opted-out" wire
		// shape requires an explicit empty array.
		if exts == nil {
			exts = []string{}
		}
		resp.Extensions = &exts
	}
	writeJSON(w, http.StatusOK, resp)
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
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body PolicyUpdate
	if !decodeControlBody(w, r, &body, false) {
		return
	}
	if err := s.Store.SetPolicy(r.Context(), category, body.Action); err != nil {
		// Both error sentinels mean "the caller handed us invalid
		// input" — return 400 with the underlying message so the
		// caller knows which constraint they tripped, instead of a
		// generic 500 that implies a server-side fault. Task 7
		// introduced ErrInvalidCategory at the store boundary; the
		// HTTP surface must follow.
		if errors.Is(err, store.ErrInvalidAction) {
			writeError(w, http.StatusBadRequest, "invalid action")
			return
		}
		if errors.Is(err, store.ErrInvalidCategory) {
			writeError(w, http.StatusBadRequest, err.Error())
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
	capControlBody(w, r)
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
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body store.DLPConfig
	if !decodeControlBody(w, r, &body, false) {
		return
	}
	if err := s.Store.SetDLPConfig(r.Context(), body); err != nil {
		// Same contract as handlePolicyItem: an invalid threshold or
		// out-of-bounds weight is a 400, not a 500. The wrapped
		// ErrInvalidDLPConfig message names the offending field
		// ("threshold_critical must be positive", "hotword_boost=200
		// outside [-100,100]", ...) so the caller can fix the input
		// without having to guess which knob is wrong.
		if errors.Is(err, store.ErrInvalidDLPConfig) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.applyLiveDLP(dlpConfigToSnapshot(body))
	writeJSON(w, http.StatusOK, body)
}

// applyLiveDLP propagates the given snapshot's thresholds and
// scoring weights into the live DLP pipeline. Used by PUT
// /api/dlp/config, POST /api/profile/import, and the startup
// profile loader so all three paths stay in sync with what's
// persisted in SQLite — without this, weight/threshold changes
// would only take effect after an agent restart, silently
// diverging from the values returned by GET /api/dlp/config and
// GET /api/profile. A nil DLP pipeline (Phase 1, no DLP wired)
// short-circuits to a no-op.
//
// Threshold is set first and the weights setter is invoked last on
// purpose: SetWeights resets the pipeline's scan-result cache, so a
// PUT /api/dlp/config invalidates any cached verdicts produced under
// the previous policy before the next /api/dlp/scan can hit them.
func (s *Server) applyLiveDLP(c profile.DLPConfigSnapshot) {
	if s == nil || s.DLP == nil {
		return
	}
	s.DLP.Threshold().Set(dlp.Thresholds{
		Critical: c.ThresholdCritical,
		High:     c.ThresholdHigh,
		Medium:   c.ThresholdMedium,
		Low:      c.ThresholdLow,
	})
	s.DLP.SetWeights(dlp.ScoreWeights{
		HotwordBoost:     c.HotwordBoost,
		EntropyBoost:     c.EntropyBoost,
		EntropyPenalty:   c.EntropyPenalty,
		ExclusionPenalty: c.ExclusionPenalty,
		MultiMatchBoost:  c.MultiMatchBoost,
	})
}

// dlpConfigToSnapshot mirrors the field-for-field shape between
// store.DLPConfig and profile.DLPConfigSnapshot. The two types are
// kept separate to avoid a profile→store import cycle.
func dlpConfigToSnapshot(c store.DLPConfig) profile.DLPConfigSnapshot {
	return profile.DLPConfigSnapshot{
		ThresholdCritical: c.ThresholdCritical,
		ThresholdHigh:     c.ThresholdHigh,
		ThresholdMedium:   c.ThresholdMedium,
		ThresholdLow:      c.ThresholdLow,
		HotwordBoost:      c.HotwordBoost,
		EntropyBoost:      c.EntropyBoost,
		EntropyPenalty:    c.EntropyPenalty,
		ExclusionPenalty:  c.ExclusionPenalty,
		MultiMatchBoost:   c.MultiMatchBoost,
	}
}

// bumpDLPStats increments dlp_scans_total (+1) and optionally
// dlp_blocks_total (+1 when blocked). Errors are intentionally
// swallowed by the caller — counter updates must not break a scan.
//
// This is a documented direct-to-store path that intentionally
// bypasses *stats.Counter: the per-scan handler (handleDLPScan) and
// the Native Messaging frame handler both run inside per-request
// goroutines that have no reference to the Counter wired into them.
// The store-level write is atomic (store.Store.AddStats serialises
// through its own mutex), so the bypass cannot corrupt counter
// values. It DOES mean that a stats reset issued by the operator
// while a scan is in flight may persist the +1 on top of the freshly
// zeroed row, but the same window already existed in the original
// design and is acceptable for low-resolution telemetry counters.
// If you add a new direct-to-store call site (e.g. for a future
// proxy-side counter), update stats.Counter's package comment so the
// audit list there stays accurate.
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

// handleRulesUpdate handles POST /api/rules/update. It triggers an
// immediate manifest check and waits for the result before responding.
// 503 is returned when no updater was wired (Phase 1 / Phase 2
// deployments). The reply matches rules.Result so callers can decide
// whether to flash a "rules updated" toast in the tray UI.
func (s *Server) handleRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RuleUpdater == nil {
		writeError(w, http.StatusServiceUnavailable, "rule updater not configured")
		return
	}
	capControlBody(w, r)
	// Outbound HTTPS to fetch the signed rule manifest can exceed the
	// server-wide 10 s WriteTimeout; the RuleUpdater client has its
	// own timeout that bounds the operation.
	allowLongWrite(w)
	res, err := s.RuleUpdater.CheckNow(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "rule update failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleRulesStatus handles GET /api/rules/status. Returns the
// updater's current bookkeeping fields. 503 is returned when no
// updater was wired so callers can suppress the rules section in the
// tray UI on legacy installs.
func (s *Server) handleRulesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RuleUpdater == nil {
		writeError(w, http.StatusServiceUnavailable, "rule updater not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.RuleUpdater.Status())
}

// proxyEnableResponse is the body of POST /api/proxy/enable.
type proxyEnableResponse struct {
	CACertPath string `json:"ca_cert_path"`
}

// proxyDisableRequest is the body of POST /api/proxy/disable. Both
// fields are optional; empty body is equivalent to remove_ca=false.
type proxyDisableRequest struct {
	RemoveCA bool `json:"remove_ca"`
}

// handleProxyEnable triggers CA generation (if needed) and starts the
// proxy listener. Returns 503 when no proxy controller is wired.
func (s *Server) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	capControlBody(w, r)
	caPath, err := s.Proxy.Enable(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "enable proxy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, proxyEnableResponse{CACertPath: caPath})
}

// handleProxyDisable stops the proxy listener and optionally removes
// the on-disk CA when remove_ca=true is set in the body.
func (s *Server) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	// Always attempt to decode; treat io.EOF (empty body in any
	// transfer encoding) as a no-op equivalent to remove_ca=false.
	// Gating on r.ContentLength is unsafe because net/http reports
	// -1 when no Content-Length header is present (e.g. chunked
	// transfer encoding or a plain POST without the header).
	var body proxyDisableRequest
	if !decodeControlBody(w, r, &body, true) {
		return
	}
	if err := s.Proxy.Disable(r.Context(), body.RemoveCA); err != nil {
		writeError(w, http.StatusInternalServerError, "disable proxy: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Proxy.Status())
}

// handleProxyStatus returns the current proxy lifecycle snapshot.
func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.Proxy.Status())
}

// maxProfileBytes caps the size of a profile uploaded via
// /api/profile/import to keep an unbounded body from exhausting
// memory. Profiles are tiny JSON documents in practice.
const maxProfileBytes = 1 << 20 // 1 MiB

// profileImportRequest is the body for POST /api/profile/import. A
// non-empty URL takes precedence over an inline Profile body — the
// agent downloads the profile and applies it.
type profileImportRequest struct {
	URL     string           `json:"url,omitempty"`
	Profile *profile.Profile `json:"profile,omitempty"`
}

// handleProfileGet returns the active enterprise profile or 404 if
// none is loaded.
func (s *Server) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile == nil {
		writeError(w, http.StatusNotFound, "no profile loaded")
		return
	}
	p := s.Profile.Get()
	if p == nil {
		writeError(w, http.StatusNotFound, "no profile loaded")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleProfileImport accepts either a URL to fetch the profile from
// or an inline JSON profile body, validates it, applies it to the
// store (which can flip Managed=true and lock the device), and
// returns the active profile.
func (s *Server) handleProfileImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile == nil {
		writeError(w, http.StatusServiceUnavailable, "profile holder not configured")
		return
	}

	// When `url` is set the handler fetches the profile from a remote
	// HTTPS endpoint; that fetch can outlast the server-wide 10 s
	// WriteTimeout and is bounded only by the profile HTTP client.
	allowLongWrite(w)

	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}

	var req profileImportRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	var p *profile.Profile
	switch {
	case strings.TrimSpace(req.URL) != "":
		// LoadFromURL with the configured verifier (D2) — the
		// verifier is nil before D2 ships, which preserves the
		// historical behaviour. When configured with a public
		// key the verifier rejects unsigned / tampered profiles
		// before they ever touch the apply path; when configured
		// without a key it logs a one-time warning and accepts.
		p, err = profile.LoadFromURL(r.Context(), nil, req.URL, s.ProfileVerifier)
		if err != nil {
			writeError(w, http.StatusBadGateway, "fetch profile: "+err.Error())
			return
		}
	case req.Profile != nil:
		if err := req.Profile.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// D2: verify the inline-body profile through the same
		// envelope the URL path uses. Mirrors the rule-manifest
		// verifier path (rules.verifyManifestSignature) so the
		// inline import surface can't be used to bypass the
		// signing posture an operator configured. The verifier
		// recomputes the canonical bytes via CanonicalForSigning,
		// which goes through profileBody and so produces the
		// same bytes the signer signed regardless of whether the
		// inline Profile already carries a Signature field. A
		// nil verifier preserves pre-D2 behaviour.
		if s.ProfileVerifier != nil {
			if err := s.ProfileVerifier.Verify(req.Profile); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p = req.Profile
	default:
		writeError(w, http.StatusBadRequest, "url or profile required")
		return
	}

	if s.ProfileApply != nil {
		if err := p.Apply(r.Context(), profile.ApplyOptions{
			PolicyStore: s.ProfileApply,
			Reloader:    s.Policy,
			DLPSink:     s.applyLiveDLP,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "apply profile: "+err.Error())
			return
		}
	}
	if err := s.Profile.Set(p); err != nil {
		writeError(w, http.StatusInternalServerError, "store profile: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Profile.Get())
}

// handleTamperStatus surfaces the tamper detector's most recent check.
func (s *Server) handleTamperStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Tamper == nil {
		writeError(w, http.StatusServiceUnavailable, "tamper detector not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.Tamper.Status())
}

// statsExportResponse adds the human / runtime context that turns a
// raw counter dump into a usable export. Nothing sensitive is added
// — only the build/OS metadata an admin needs to correlate the
// counters with the device.
type statsExportResponse struct {
	AgentVersion string         `json:"agent_version"`
	OSType       string         `json:"os_type"`
	OSArch       string         `json:"os_arch"`
	ExportedAt   time.Time      `json:"exported_at"`
	Stats        stats.Snapshot `json:"stats"`
}

// handleStatsExport returns the same counters as /api/stats wrapped
// with a small envelope so the export file is self-describing. The
// response has a Content-Disposition header so the Electron UI can
// surface "Save as…" naturally.
func (s *Server) handleStatsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snap, err := s.Stats.GetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats unavailable")
		return
	}
	body := statsExportResponse{
		AgentVersion: Version,
		OSType:       runtime.GOOS,
		OSArch:       runtime.GOARCH,
		ExportedAt:   time.Now().UTC(),
		Stats:        snap,
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"secure-edge-stats-%s.json\"",
			body.ExportedAt.Format("20060102-150405")))
	writeJSON(w, http.StatusOK, body)
}

// ruleOverrideRequest is the body for POST /api/rules/override.
type ruleOverrideRequest struct {
	Domain string `json:"domain"`
	// List is "allow" or "block". Anything else returns 400.
	List string `json:"list"`
}

// ruleOverrideResponse is the body returned by the override
// endpoints; ListAllow / ListBlock reflect the merged-on-disk state
// after the call.
type ruleOverrideResponse struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}

// handleRuleOverride adds (POST) or lists (GET) admin allow/block
// override entries. Writes through to rules/local/*.txt and then
// triggers a policy reload so the change is picked up immediately.
func (s *Server) handleRuleOverride(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusServiceUnavailable, "rule overrides not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a, b := s.Rules.List()
		writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
	case http.MethodPost:
		var body ruleOverrideRequest
		if !decodeControlBody(w, r, &body, false) {
			return
		}
		if strings.TrimSpace(body.Domain) == "" {
			writeError(w, http.StatusBadRequest, "domain is required")
			return
		}
		if body.List != "allow" && body.List != "block" {
			writeError(w, http.StatusBadRequest, "list must be allow or block")
			return
		}
		if err := s.Rules.Add(body.Domain, body.List); err != nil {
			writeError(w, http.StatusInternalServerError, "add override: "+err.Error())
			return
		}
		// Surface reload errors instead of silently 200ing. The
		// override file has already been persisted; if reload fails
		// the on-disk state is ahead of the in-memory engine and the
		// caller needs to know the change isn't live yet. Same
		// contract as handlePolicyItem above.
		if s.Policy != nil {
			if err := s.Policy.Reload(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, "policy reload failed")
				return
			}
		}
		a, b := s.Rules.List()
		writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRuleOverrideItem handles DELETE /api/rules/override/:domain.
func (s *Server) handleRuleOverrideItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Rules == nil {
		writeError(w, http.StatusServiceUnavailable, "rule overrides not configured")
		return
	}
	domain := strings.TrimPrefix(r.URL.Path, "/api/rules/override/")
	domain = strings.TrimSpace(domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := s.Rules.Remove(domain); err != nil {
		writeError(w, http.StatusInternalServerError, "remove override: "+err.Error())
		return
	}
	// See handleRuleOverride: a failed reload after a successful
	// on-disk removal must not return 200, otherwise the caller
	// thinks the override is gone while DNS still applies it.
	if s.Policy != nil {
		if err := s.Policy.Reload(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "policy reload failed")
			return
		}
	}
	a, b := s.Rules.List()
	writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
}

// handleAgentUpdateCheck reports whether a newer agent release is
// published on the configured manifest channel. Returns 503 if no
// updater is wired (builds without a release channel).
func (s *Server) handleAgentUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.AgentUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "agent updater not configured")
		return
	}
	res, err := s.AgentUpdate.CheckLatest(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "update check failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleAgentUpdate downloads the latest agent release, verifies its
// SHA256 + Ed25519 signature, and stages it for restart. Returns 503
// when no updater is wired.
func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.AgentUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "agent updater not configured")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	capControlBody(w, r)
	// Downloading the agent binary is a long outbound HTTPS operation
	// that easily exceeds the server-wide 10 s WriteTimeout; the
	// AgentUpdater client bounds the wall-clock budget.
	allowLongWrite(w)
	staged, err := s.AgentUpdate.DownloadAndStage(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "stage failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, staged)
}
