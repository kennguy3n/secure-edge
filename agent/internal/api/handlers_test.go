package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

type fakeReloader struct{ calls int64 }

func (f *fakeReloader) Reload(_ context.Context) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}

type fakeStatsView struct {
	snap   stats.Snapshot
	resets int64
}

func (f *fakeStatsView) GetStats(_ context.Context) (stats.Snapshot, error) { return f.snap, nil }
func (f *fakeStatsView) Reset(_ context.Context) error {
	atomic.AddInt64(&f.resets, 1)
	f.snap = stats.Snapshot{}
	return nil
}

func newTestServer(t *testing.T) (*Server, *fakeReloader, *fakeStatsView) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	rel := &fakeReloader{}
	view := &fakeStatsView{snap: stats.Snapshot{DNSQueriesTotal: 42, DNSBlocksTotal: 5}}
	return NewServer(s, rel, view), rel, view
}

// newLocalRequest builds an httptest request whose Host header is
// 127.0.0.1, matching the loopback-only allowlist enforced by the API.
func newLocalRequest(method, path string, body interface{}) *http.Request {
	var r *http.Request
	switch b := body.(type) {
	case nil:
		r = httptest.NewRequest(method, path, nil)
	case *bytes.Buffer:
		r = httptest.NewRequest(method, path, b)
	default:
		panic("unsupported body type")
	}
	r.Host = "127.0.0.1:8080"
	return r
}

func TestStatusEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("status = %q", got.Status)
	}
	if got.Version == "" {
		t.Errorf("version is empty")
	}
}

func TestPoliciesCollection(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/policies", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var pols []store.CategoryPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &pols); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pols) == 0 {
		t.Fatal("expected seeded policies")
	}
}

func TestUpdatePolicyTriggersReload(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt64(&rel.calls) != 1 {
		t.Fatalf("reload calls = %d", rel.calls)
	}
}

func TestUpdatePolicyInvalidAction(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"bogus"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdatePolicyMissingCategory(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got stats.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.DNSQueriesTotal != 42 {
		t.Errorf("queries = %d", got.DNSQueriesTotal)
	}
}

func TestStatsResetEndpoint(t *testing.T) {
	srv, _, view := newTestServer(t)
	r := newLocalRequest(http.MethodPost, "/api/stats/reset", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if atomic.LoadInt64(&view.resets) != 1 {
		t.Fatalf("resets = %d", view.resets)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/status"},
		{http.MethodPost, "/api/policies"},
		{http.MethodGet, "/api/policies/foo"},
		{http.MethodPost, "/api/stats"},
		{http.MethodGet, "/api/stats/reset"},
	}
	for _, c := range cases {
		r := newLocalRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: code = %d", c.method, c.path, w.Code)
		}
	}
}

func TestCORSPreflightAllowedOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, origin := range []string{"null", "http://localhost:5173", "http://127.0.0.1:5173"} {
		r := newLocalRequest(http.MethodOptions, "/api/policies", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s: code = %d", origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("%s: ACAO = %q", origin, got)
		}
		if w.Header().Get("Vary") != "Origin" {
			t.Errorf("%s: Vary header missing", origin)
		}
	}
}

func TestCORSRejectsUnknownOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/policies", nil)
	r.Header.Set("Origin", "http://evil.example.com")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("ACAO must not be echoed for rejected origin")
	}
}

func TestRejectsNonLoopbackHost(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []string{"evil.example.com", "evil.example.com:8080", ""}
	for _, host := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		r.Host = host
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("host=%q: code = %d, want 403", host, w.Code)
		}
	}
}

func TestAllowsRequestsWithoutOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO unexpectedly set: %q", got)
	}
}

// --- DLP endpoint tests (Phase 2) ---

type fakeDLP struct {
	thr    *dlp.ThresholdEngine
	result dlp.ScanResult
	calls  int64
}

func (f *fakeDLP) Scan(_ context.Context, _ string) dlp.ScanResult {
	atomic.AddInt64(&f.calls, 1)
	return f.result
}
func (f *fakeDLP) Threshold() *dlp.ThresholdEngine { return f.thr }

func TestDLPScan_WithoutPipelineReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"x"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body=%q)", rec.Code, rec.Body.String())
	}
}

func TestDLPScan_ReturnsScanResult(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{
		thr:    dlp.NewThresholdEngine(dlp.DefaultThresholds()),
		result: dlp.ScanResult{Blocked: true, PatternName: "AWS Access Key", Score: 3},
	})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/dlp/scan",
		bytes.NewBufferString(`{"content":"AKIAABCDEFGHIJKLMNOP aws"}`))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rec.Code, rec.Body.String())
	}
	var got dlp.ScanResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Blocked || got.PatternName != "AWS Access Key" || got.Score != 3 {
		t.Fatalf("scan result = %+v, want blocked AWS Access Key score=3", got)
	}
}

func TestDLPScan_RejectsNonPOST(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetDLP(&fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/scan", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestDLPConfig_GetAndPut(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	srv.SetDLP(&fakeDLP{thr: thr})

	// GET returns the defaults seeded by store.Open.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/dlp/config", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/dlp/config got %d", rec.Code)
	}
	var cfg store.DLPConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.ThresholdCritical == 0 {
		t.Fatalf("expected non-zero defaults, got %+v", cfg)
	}

	// PUT updates thresholds and propagates to the engine.
	cfg.ThresholdCritical = 99
	cfg.ThresholdHigh = 100
	cfg.ThresholdMedium = 101
	cfg.ThresholdLow = 102
	body, _ := json.Marshal(cfg)
	rec = httptest.NewRecorder()
	req = newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := thr.Get(); got.Critical != 99 || got.Low != 102 {
		t.Fatalf("threshold engine not updated: %+v", got)
	}
}
