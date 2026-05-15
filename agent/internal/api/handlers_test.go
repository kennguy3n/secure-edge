package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/profile"
	"github.com/kennguy3n/secure-edge/agent/internal/rules"
	"github.com/kennguy3n/secure-edge/agent/internal/stats"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

type fakeReloader struct {
	calls int64
	err   error // optional: when set, Reload returns this error
}

func (f *fakeReloader) Reload(_ context.Context) error {
	atomic.AddInt64(&f.calls, 1)
	return f.err
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
	// uptime_seconds is the machine-readable number consumed by the
	// browser extension; it must always be present (>= 0) so the
	// popup doesn't fall back to "—".
	if got.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d, want >= 0", got.UptimeSeconds)
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
	origins := []string{
		// Electron renderer + Vite dev server.
		"null",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		// Browser extension service worker. The ID is install-time
		// and not knowable here; any chrome-extension:// (Chrome,
		// Edge, Chromium), moz-extension:// (Firefox), or
		// safari-web-extension:// (Safari) origin must be accepted
		// so the popup's /api/status fetch works.
		"chrome-extension://abcdefghijklmnopabcdefghijklmnop",
		"moz-extension://01234567-89ab-cdef-0123-456789abcdef",
		"safari-web-extension://01234567-89ab-cdef-0123-456789abcdef",
		// Content-script origins (Tier-2 AI tools). The browser
		// stamps the page's own origin for content-script fetches,
		// not the extension's, so each Tier-2 host has to be
		// explicitly allowed. Sample two ends of the list.
		"https://chatgpt.com",
		"https://poe.com",
	}
	for _, origin := range origins {
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

// TestCORSRejectsLookalikeExtensionOrigins guards the extension
// prefix checks against trivial spoofs (an attacker page can set an
// arbitrary Origin via fetch on the server side only; from a browser
// the Origin is controlled, but the test pins the parser anyway).
func TestCORSRejectsLookalikeExtensionOrigins(t *testing.T) {
	srv, _, _ := newTestServer(t)
	cases := []string{
		// Bare schemes without an ID component.
		"chrome-extension://",
		"moz-extension://",
		"safari-web-extension://",
		// Embedded but not as scheme prefixes.
		"https://chrome-extension.example.com",
		"https://moz-extension.example.com",
		"https://safari-web-extension.example.com",
	}
	for _, origin := range cases {
		r := newLocalRequest(http.MethodGet, "/api/status", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("origin=%q: code = %d, want 403", origin, w.Code)
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
	thr     *dlp.ThresholdEngine
	result  dlp.ScanResult
	calls   int64
	weights dlp.ScoreWeights
}

func (f *fakeDLP) Scan(_ context.Context, _ string) dlp.ScanResult {
	atomic.AddInt64(&f.calls, 1)
	return f.result
}
func (f *fakeDLP) Threshold() *dlp.ThresholdEngine { return f.thr }
func (f *fakeDLP) SetWeights(w dlp.ScoreWeights)   { f.weights = w }
func (f *fakeDLP) Patterns() []*dlp.Pattern        { return nil }

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
		bytes.NewBufferString(`{"content":"placeholder aws credentials test"}`))
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

func TestDLPConfig_PutPropagatesWeightsToPipeline(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fake := &fakeDLP{thr: dlp.NewThresholdEngine(dlp.DefaultThresholds())}
	srv.SetDLP(fake)

	cfg := store.DLPConfig{
		ThresholdCritical: 1, ThresholdHigh: 2, ThresholdMedium: 3, ThresholdLow: 4,
		HotwordBoost: 7, EntropyBoost: 8, EntropyPenalty: -9,
		ExclusionPenalty: -11, MultiMatchBoost: 13,
	}
	body, _ := json.Marshal(cfg)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT got %d body=%q", rec.Code, rec.Body.String())
	}
	want := dlp.ScoreWeights{
		HotwordBoost: 7, EntropyBoost: 8, EntropyPenalty: -9,
		ExclusionPenalty: -11, MultiMatchBoost: 13,
	}
	if fake.weights != want {
		t.Fatalf("live pipeline weights = %+v, want %+v", fake.weights, want)
	}
}

// stubUpdater is a minimal RuleUpdater for handler tests.
type stubUpdater struct {
	check      func(ctx context.Context) (rules.Result, error)
	status     rules.Status
	checkCalls int
}

func (s *stubUpdater) CheckNow(ctx context.Context) (rules.Result, error) {
	s.checkCalls++
	if s.check != nil {
		return s.check(ctx)
	}
	return rules.Result{Updated: true, Version: "1.2.3", FilesDownloaded: 2}, nil
}

func (s *stubUpdater) Status() rules.Status { return s.status }

func TestRulesUpdate_RequiresUpdater(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRulesUpdate_PostInvokesCheckNow(t *testing.T) {
	srv, _, _ := newTestServer(t)
	upd := &stubUpdater{}
	srv.SetRuleUpdater(upd)

	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
	if upd.checkCalls != 1 {
		t.Errorf("CheckNow calls = %d, want 1", upd.checkCalls)
	}
	var res rules.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Version != "1.2.3" || !res.Updated || res.FilesDownloaded != 2 {
		t.Errorf("response = %+v", res)
	}
}

func TestRulesUpdate_RejectsNonPost(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleUpdater(&stubUpdater{})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rec.Code)
	}
}

func TestRulesUpdate_PropagatesError(t *testing.T) {
	srv, _, _ := newTestServer(t)
	upd := &stubUpdater{check: func(_ context.Context) (rules.Result, error) {
		return rules.Result{}, fmt.Errorf("manifest 404")
	}}
	srv.SetRuleUpdater(upd)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/update", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestRulesStatus_RequiresUpdater(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestRulesStatus_ReturnsSnapshot(t *testing.T) {
	srv, _, _ := newTestServer(t)
	when := time.Now().UTC().Truncate(time.Second)
	srv.SetRuleUpdater(&stubUpdater{status: rules.Status{
		CurrentVersion: "9.9.9",
		LastCheck:      when,
		NextCheck:      when.Add(6 * time.Hour),
		UpdateURL:      "https://example.test/manifest.json",
	}})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%q", rec.Code, rec.Body.String())
	}
	var got rules.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CurrentVersion != "9.9.9" || got.UpdateURL == "" {
		t.Errorf("status = %+v", got)
	}
	if !got.LastCheck.Equal(when) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, when)
	}
}

func TestRulesStatus_RejectsNonGet(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleUpdater(&stubUpdater{})
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/rules/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d", rec.Code)
	}
}

// fakeProxyController is a deterministic ProxyController for tests.
type fakeProxyController struct {
	enableCalls  int
	disableCalls int
	lastRemoveCA bool
	statusSnap   ProxyStatus
	enableErr    error
	disableErr   error
}

func (f *fakeProxyController) Enable(_ context.Context) (string, error) {
	f.enableCalls++
	if f.enableErr != nil {
		return "", f.enableErr
	}
	f.statusSnap.Running = true
	f.statusSnap.CAInstalled = true
	f.statusSnap.ProxyConfigured = true
	if f.statusSnap.ListenAddr == "" {
		f.statusSnap.ListenAddr = "127.0.0.1:8443"
	}
	if f.statusSnap.CACertPath == "" {
		f.statusSnap.CACertPath = "/tmp/ca.crt"
	}
	return f.statusSnap.CACertPath, nil
}

func (f *fakeProxyController) Disable(_ context.Context, removeCA bool) error {
	f.disableCalls++
	f.lastRemoveCA = removeCA
	if f.disableErr != nil {
		return f.disableErr
	}
	f.statusSnap.Running = false
	f.statusSnap.ProxyConfigured = false
	if removeCA {
		f.statusSnap.CAInstalled = false
		f.statusSnap.CACertPath = ""
	}
	return nil
}

func (f *fakeProxyController) Status() ProxyStatus { return f.statusSnap }

func TestProxyEnable_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/enable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxyDisable_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/disable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxyStatus_WithoutControllerReturns503(t *testing.T) {
	srv, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodGet, "/api/proxy/status", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxy_EnableDisableLifecycle(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{statusSnap: ProxyStatus{ListenAddr: "127.0.0.1:8443"}}
	srv.SetProxyController(fc)

	// 1) Enable.
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPost, "/api/proxy/enable", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.enableCalls != 1 {
		t.Errorf("enable calls = %d", fc.enableCalls)
	}
	var enableBody proxyEnableResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enableBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enableBody.CACertPath == "" {
		t.Error("ca_cert_path empty in enable response")
	}

	// 2) Status reports running.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/proxy/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var st ProxyStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Running || !st.CAInstalled || !st.ProxyConfigured {
		t.Errorf("post-enable status = %+v", st)
	}
	if st.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("listen_addr = %q", st.ListenAddr)
	}

	// 3) Disable with remove_ca=true.
	rec = httptest.NewRecorder()
	body := bytes.NewBufferString(`{"remove_ca": true}`)
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/disable", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if !fc.lastRemoveCA {
		t.Error("remove_ca=true not propagated to controller")
	}

	// 4) Status reports stopped.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodGet, "/api/proxy/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Running || st.CAInstalled {
		t.Errorf("post-disable status = %+v", st)
	}
}

func TestProxy_DisableEmptyBodyAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{}
	_, _ = fc.Enable(context.Background())
	srv.SetProxyController(fc)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/disable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if fc.lastRemoveCA {
		t.Error("remove_ca defaulted to true; expected false on empty body")
	}
}

// TestProxy_DisableEmptyBodyNoContentLength covers the case where a
// client sends an empty POST without a Content-Length header (e.g.
// chunked transfer encoding). net/http reports ContentLength=-1 for
// this case, so a guard like `if r.ContentLength != 0` would attempt
// to decode an empty stream and fail with io.EOF, returning a spurious
// 400. The handler must treat this identically to remove_ca=false.
func TestProxy_DisableEmptyBodyNoContentLength(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{}
	_, _ = fc.Enable(context.Background())
	srv.SetProxyController(fc)

	req := newLocalRequest(http.MethodPost, "/api/proxy/disable", nil)
	req.ContentLength = -1
	req.Header.Del("Content-Length")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: got %d body=%q", rec.Code, rec.Body.String())
	}
	if fc.disableCalls != 1 {
		t.Errorf("disable calls = %d", fc.disableCalls)
	}
	if fc.lastRemoveCA {
		t.Error("remove_ca defaulted to true; expected false on empty body")
	}
}

func TestProxy_EnableErrorReturns500(t *testing.T) {
	srv, _, _ := newTestServer(t)
	fc := &fakeProxyController{enableErr: errors.New("ca disk full")}
	srv.SetProxyController(fc)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, newLocalRequest(http.MethodPost, "/api/proxy/enable", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("got %d", rec.Code)
	}
}

func TestProxy_RejectsNonMatchingMethods(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetProxyController(&fakeProxyController{})
	cases := []struct {
		path   string
		method string
	}{
		{"/api/proxy/enable", http.MethodGet},
		{"/api/proxy/disable", http.MethodGet},
		{"/api/proxy/status", http.MethodPost},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, newLocalRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s -> %d, want 405", tc.method, tc.path, rec.Code)
		}
	}
}

// ---------- Phase 5: profile, tamper, stats export, rule override ----------

type fakeRuleOverride struct {
	allow []string
	block []string
	added []string
	rm    []string
	err   error
}

func (f *fakeRuleOverride) Add(d, list string) error {
	if f.err != nil {
		return f.err
	}
	f.added = append(f.added, list+":"+d)
	switch list {
	case "allow":
		f.allow = append(f.allow, d)
	case "block":
		f.block = append(f.block, d)
	}
	return nil
}
func (f *fakeRuleOverride) Remove(d string) error {
	if f.err != nil {
		return f.err
	}
	f.rm = append(f.rm, d)
	return nil
}
func (f *fakeRuleOverride) List() ([]string, []string) { return f.allow, f.block }

type fakeTamper struct{ st TamperStatus }

func (f fakeTamper) Status() TamperStatus { return f.st }

type fakePolicyStore struct{ calls int64 }

func (f *fakePolicyStore) SetPolicy(_ context.Context, _, _ string) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}
func (f *fakePolicyStore) GetDLPConfig(_ context.Context) (profile.DLPConfigSnapshot, error) {
	return profile.DLPConfigSnapshot{}, nil
}
func (f *fakePolicyStore) SetDLPConfig(_ context.Context, _ profile.DLPConfigSnapshot) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}
func (f *fakePolicyStore) ApplyProfileTx(_ context.Context, _ []profile.CategoryPolicy, _ *profile.DLPConfigSnapshot) error {
	atomic.AddInt64(&f.calls, 1)
	return nil
}

func TestProfileGetReturnsHolderContents(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/profile", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("no holder wired => 404 expected, got %d", w.Code)
	}

	h := profile.NewHolder(nil)
	if err := h.Set(&profile.Profile{Name: "acme", Version: "1", Managed: true}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	srv.SetProfile(h, &fakePolicyStore{})

	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/profile", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got profile.Profile
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Name != "acme" || !got.Managed {
		t.Fatalf("unexpected profile: %+v", got)
	}
}

func TestProfileImportLocksPolicies(t *testing.T) {
	srv, _, _ := newTestServer(t)
	h := profile.NewHolder(nil)
	ps := &fakePolicyStore{}
	srv.SetProfile(h, ps)

	body := bytes.NewBufferString(`{"profile":{"name":"acme","version":"1","managed":true,"categories":{"AI Chat":"deny"}}}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import", body))
	if w.Code != http.StatusOK {
		t.Fatalf("import code=%d body=%s", w.Code, w.Body.String())
	}
	if !h.Locked() {
		t.Fatalf("expected holder locked after import")
	}
	if atomic.LoadInt64(&ps.calls) == 0 {
		t.Fatalf("expected policy store calls during apply")
	}

	// Once locked, PUT /api/policies/:cat must return 403.
	put := bytes.NewBufferString(`{"action":"allow"}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat", put))
	if w.Code != http.StatusForbidden {
		t.Fatalf("policy PUT not locked, code=%d", w.Code)
	}

	// And PUT /api/dlp/config too.
	dlp := bytes.NewBufferString(`{"threshold_critical":1}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPut, "/api/dlp/config", dlp))
	if w.Code != http.StatusForbidden {
		t.Fatalf("dlp PUT not locked, code=%d", w.Code)
	}
}

// TestProfileImportPropagatesDLPToPipeline locks in the contract
// fixed for Bug 8: when a profile carries DLP thresholds /
// weights, POST /api/profile/import MUST push them into the live
// DLP pipeline. Before the fix, p.Apply only wrote SQLite and the
// pipeline kept its construction-time values until the next
// restart — silently diverging from GET /api/dlp/config.
func TestProfileImportPropagatesDLPToPipeline(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	fake := &fakeDLP{thr: thr}
	srv.SetDLP(fake)
	srv.SetProfile(profile.NewHolder(nil), &fakePolicyStore{})

	body := bytes.NewBufferString(`{
		"profile": {
			"name": "acme",
			"version": "1",
			"dlp_thresholds": {
				"threshold_critical": 11,
				"threshold_high":     7,
				"hotword_boost":      42,
				"entropy_boost":      13
			}
		}
	}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import", body))
	if w.Code != http.StatusOK {
		t.Fatalf("import code=%d body=%s", w.Code, w.Body.String())
	}

	got := thr.Get()
	if got.Critical != 11 || got.High != 7 {
		t.Fatalf("live thresholds = %+v, want Critical=11 High=7", got)
	}
	if fake.weights.HotwordBoost != 42 || fake.weights.EntropyBoost != 13 {
		t.Fatalf("live weights = %+v, want HotwordBoost=42 EntropyBoost=13", fake.weights)
	}
}

func TestProfileImportRequiresPayload(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetProfile(profile.NewHolder(nil), &fakePolicyStore{})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import",
		bytes.NewBufferString(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty payload code=%d body=%s", w.Code, w.Body.String())
	}
}

// signInlineProfile returns the JSON request body POST
// /api/profile/import expects, with the inline-Profile object
// signed by priv using the same canonical-form helper the agent
// verifies against. Used by the D2 inline-import trust-matrix
// tests below.
func signInlineProfile(t *testing.T, priv ed25519.PrivateKey, p profile.Profile) []byte {
	t.Helper()
	body, err := profile.CanonicalForSigning(p)
	if err != nil {
		t.Fatalf("CanonicalForSigning: %v", err)
	}
	p.Signature = hex.EncodeToString(ed25519.Sign(priv, body))
	wrapped := map[string]any{"profile": p}
	raw, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestProfileImportInline_VerifierTrustMatrix exercises the D2
// inline-body path through the four-cell trust matrix the verifier
// enforces. The URL fetch path is covered by the profile package's
// TestLoadFromURL_WithVerifier; this test pins the parallel
// behaviour on inline-Profile imports so the two sides of POST
// /api/profile/import can't drift apart in the future.
func TestProfileImportInline_VerifierTrustMatrix(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey other: %v", err)
	}

	base := profile.Profile{Name: "acme", Version: "1.0.0", Managed: true,
		Categories: map[string]string{"AI Allowed": "allow"}}

	cases := []struct {
		name     string
		verifier *profile.Verifier
		body     []byte
		wantCode int
	}{
		{
			name:     "no verifier (pre-D2 behaviour) accepts unsigned",
			verifier: nil,
			body:     []byte(`{"profile":{"name":"acme","version":"1.0.0","managed":true,"categories":{"AI Allowed":"allow"}}}`),
			wantCode: http.StatusOK,
		},
		{
			name:     "unconfigured verifier (warn-once) accepts unsigned",
			verifier: mustVerifier(t, nil),
			body:     []byte(`{"profile":{"name":"acme","version":"1.0.0","managed":true,"categories":{"AI Allowed":"allow"}}}`),
			wantCode: http.StatusOK,
		},
		{
			name:     "configured verifier rejects unsigned",
			verifier: mustVerifier(t, pub),
			body:     []byte(`{"profile":{"name":"acme","version":"1.0.0","managed":true,"categories":{"AI Allowed":"allow"}}}`),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "configured verifier accepts validly-signed",
			verifier: mustVerifier(t, pub),
			body:     signInlineProfile(t, priv, base),
			wantCode: http.StatusOK,
		},
		{
			name:     "configured verifier rejects signed-by-other-key",
			verifier: mustVerifier(t, pub),
			body:     signInlineProfile(t, otherPriv, base),
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "configured verifier rejects tampered body",
			verifier: mustVerifier(t, pub),
			body: func() []byte {
				// Sign one body, then mutate the JSON in flight
				// so the verifier sees a different canonical body
				// than the one the signature was computed over.
				raw := signInlineProfile(t, priv, base)
				return bytes.Replace(raw, []byte(`"acme"`), []byte(`"hijack"`), 1)
			}(),
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestServer(t)
			srv.SetProfile(profile.NewHolder(nil), &fakePolicyStore{})
			srv.SetProfileVerifier(tc.verifier)

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/profile/import",
				bytes.NewBuffer(tc.body)))
			if w.Code != tc.wantCode {
				t.Fatalf("code=%d (want %d) body=%s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

// mustVerifier wraps profile.NewVerifier with a t.Fatal on any
// constructor error so the table-driven test above stays readable.
// nil pub returns an unconfigured (warn-once) verifier.
func mustVerifier(t *testing.T, pub ed25519.PublicKey) *profile.Verifier {
	t.Helper()
	v, err := profile.NewVerifier(pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestTamperStatusUnconfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/tamper/status", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured tamper => 503 expected, got %d", w.Code)
	}
}

func TestTamperStatusOK(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetTamperReporter(fakeTamper{st: TamperStatus{DNSOK: true, ProxyOK: false, DetectionsTotal: 7}})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/tamper/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	var got TamperStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProxyOK || !got.DNSOK || got.DetectionsTotal != 7 {
		t.Fatalf("unexpected status: %+v", got)
	}
}

func TestStatsExportEnvelope(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/stats/export", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Fatalf("missing Content-Disposition")
	}
	var got statsExportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.AgentVersion == "" || got.OSType == "" {
		t.Fatalf("missing envelope metadata: %+v", got)
	}
	if got.Stats.DNSQueriesTotal == 0 {
		t.Fatalf("stats body not forwarded: %+v", got.Stats)
	}
}

func TestRuleOverrideAddListRemove(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	fake := &fakeRuleOverride{}
	srv.SetRuleOverride(fake)

	add := bytes.NewBufferString(`{"domain":"foo.example","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", add))
	if w.Code != http.StatusOK {
		t.Fatalf("add code=%d body=%s", w.Code, w.Body.String())
	}
	if len(fake.added) != 1 || fake.added[0] != "allow:foo.example" {
		t.Fatalf("Add not invoked correctly: %v", fake.added)
	}
	if atomic.LoadInt64(&rel.calls) == 0 {
		t.Fatalf("expected policy reload after override change")
	}

	// GET listing.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodGet, "/api/rules/override", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list code=%d", w.Code)
	}

	// DELETE :domain.
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodDelete, "/api/rules/override/foo.example", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete code=%d body=%s", w.Code, w.Body.String())
	}
	if len(fake.rm) != 1 || fake.rm[0] != "foo.example" {
		t.Fatalf("Remove not invoked: %v", fake.rm)
	}
}

func TestRuleOverrideValidation(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleOverride(&fakeRuleOverride{})

	bad := bytes.NewBufferString(`{"domain":"","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty domain => 400 expected, got %d", w.Code)
	}

	bad = bytes.NewBufferString(`{"domain":"ok","list":"middle"}`)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad list => 400 expected, got %d", w.Code)
	}
}

func TestRuleOverrideUnconfigured(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, newLocalRequest(m, "/api/rules/override", nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s => 503 expected, got %d", m, w.Code)
		}
	}
}

// Bug 9 regression: when the underlying policy engine fails to
// reload after a rule-override write, the handler must return 500
// rather than 200. Returning 200 made callers think the override
// was live while the in-memory DNS engine still used the old map.
func TestRuleOverrideAddReloadFailure(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	rel.err = errors.New("boom")
	srv.SetRuleOverride(&fakeRuleOverride{})

	body := bytes.NewBufferString(`{"domain":"foo.example","list":"allow"}`)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodPost, "/api/rules/override", body))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("add => 500 expected when reload fails, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestRuleOverrideDeleteReloadFailure(t *testing.T) {
	srv, rel, _ := newTestServer(t)
	rel.err = errors.New("boom")
	srv.SetRuleOverride(&fakeRuleOverride{allow: []string{"foo.example"}})

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, newLocalRequest(http.MethodDelete, "/api/rules/override/foo.example", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("delete => 500 expected when reload fails, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestCORS_AIPageOriginsBlockedFromControlEndpoints pins the P0-1
// per-path origin split. AI page origins (Tier-2 tool pages where the
// extension's content scripts run) MUST NOT reach state-changing
// endpoints — a compromised AI tool page that talks to the agent is
// restricted to /api/dlp/scan and the GET-only status surface. The
// Electron renderer and chrome-/moz-/safari-extension origins remain
// the only callers that can mutate policy, flip the proxy, import a
// profile, or roll a rule update.
func TestCORS_AIPageOriginsBlockedFromControlEndpoints(t *testing.T) {
	srv, _, _ := newTestServer(t)

	controlPaths := []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/api/policies/AI%20Chat%20Blocked"},
		{http.MethodPut, "/api/dlp/config"},
		{http.MethodPost, "/api/proxy/enable"},
		{http.MethodPost, "/api/proxy/disable"},
		{http.MethodPost, "/api/profile/import"},
		{http.MethodPost, "/api/rules/update"},
		{http.MethodPost, "/api/rules/override"},
		{http.MethodDelete, "/api/rules/override/foo.example"},
		{http.MethodPost, "/api/agent/update"},
		{http.MethodGet, "/api/agent/update-check"},
		{http.MethodPost, "/api/stats/reset"},
	}
	// Derive the fixture from the production aiPageOrigins map so a
	// future PR that extends the allowlist (P1-2 style) is
	// automatically covered. Before this PR the list was a hardcoded
	// slice; the Tier-2 hosts added in P1-2 silently fell outside
	// the test's coverage. Iterating the map directly closes that
	// gap permanently — every entry that can reach the read-only
	// CORS surface must also be proven to be rejected on the control
	// surface.
	origins := make([]string, 0, len(aiPageOrigins))
	for origin := range aiPageOrigins {
		origins = append(origins, origin)
	}
	// Sort for deterministic test output — Go map iteration is
	// randomised and a failure should always print the same origin.
	sort.Strings(origins)
	// Mass-deletion guard. The dynamic iteration above already
	// guarantees that every entry currently in aiPageOrigins is
	// exercised, so a hardcoded floor would just be a maintenance
	// trap (every legitimate addition to the map would also have
	// to bump the floor here). An empty map almost certainly means
	// the var declaration was accidentally wiped — fail loudly.
	if len(origins) == 0 {
		t.Fatal("aiPageOrigins is empty — refusing to claim CORS coverage with no fixtures")
	}
	for _, origin := range origins {
		for _, c := range controlPaths {
			r := newLocalRequest(c.method, c.path, nil)
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s from %s: code = %d, want 403", c.method, c.path, origin, w.Code)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("%s %s from %s: ACAO leaked %q", c.method, c.path, origin, got)
			}
		}
	}
}

// TestCORS_AIPageOriginsAllowedOnReadEndpoints confirms the read-only
// half of the split: AI page origins keep their access to the scan
// pipeline, status readouts, profile read, and rules-status polling
// so the in-page DLP coaching and the extension's dynamic Tier-2
// updater both continue to work.
func TestCORS_AIPageOriginsAllowedOnReadEndpoints(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRuleUpdater(&stubUpdater{})

	readPaths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/status"},
		{http.MethodGet, "/api/stats"},
		{http.MethodGet, "/api/stats/export"},
		{http.MethodGet, "/api/proxy/status"},
		{http.MethodGet, "/api/tamper/status"},
		{http.MethodGet, "/api/rules/status"},
		{http.MethodGet, "/api/policies"},
		// /api/config/enforcement-mode is intentionally outside
		// isControlPath because the response is one of three enum
		// strings — no scoring thresholds, no classifier mappings —
		// and AI pages already learn agent reachability empirically.
		// Pinning it here prevents a future "tighten everything"
		// change from quietly demoting the read endpoint to a
		// control path and breaking the extension service-worker's
		// auth-free poll (`service-worker.ts: fetchEnforcementMode`).
		{http.MethodGet, "/api/config/enforcement-mode"},
		// /api/config/risky-extensions (B2) follows the same
		// reasoning as enforcement-mode: a small read-only JSON
		// body, no DLP-scoring information leakage, and the
		// extension service worker fetches it on cold start.
		{http.MethodGet, "/api/config/risky-extensions"},
		{http.MethodOptions, "/api/dlp/scan"},
	}
	for _, c := range readPaths {
		r := newLocalRequest(c.method, c.path, nil)
		r.Header.Set("Origin", "https://chatgpt.com")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		// We're only verifying that the CORS layer didn't 403 the
		// request and echoed the origin back. The handlers themselves
		// can still return 404 / 503 / etc., which is fine — what
		// would be a P0-1 regression is a 403 from the middleware.
		if w.Code == http.StatusForbidden {
			t.Errorf("%s %s from chatgpt.com: code = 403 (control endpoint regression)", c.method, c.path)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://chatgpt.com" {
			t.Errorf("%s %s from chatgpt.com: ACAO = %q, want https://chatgpt.com", c.method, c.path, got)
		}
	}
}

// TestCORS_ControlOriginsReachControlEndpoints confirms the Electron
// renderer and any installed extension build can still drive the
// state-changing endpoints. Without this pin a future tightening of
// isControlOrigin could lock the tray app out of its own agent.
func TestCORS_ControlOriginsReachControlEndpoints(t *testing.T) {
	srv, _, _ := newTestServer(t)

	controlOrigins := []string{
		"null",                  // packaged Electron renderer (file://)
		"http://localhost:5173", // Vite dev server
		"chrome-extension://abcdefghijklmnopabcdefghijklmnop",
		"moz-extension://01234567-89ab-cdef-0123-456789abcdef",
		"safari-web-extension://01234567-89ab-cdef-0123-456789abcdef",
	}
	for _, origin := range controlOrigins {
		r := newLocalRequest(http.MethodOptions, "/api/policies/AI%20Chat%20Blocked", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("%s preflight to /api/policies/...: code = %d, want 204", origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("%s: ACAO = %q, want %q", origin, got, origin)
		}
	}
}

// TestEnforcementMode_DefaultIsPersonal locks in the no-setter
// behaviour: a server constructed without SetEnforcementMode echoes
// "personal" through both /api/status and /api/config/enforcement-mode.
// This is the posture an operator gets from a config.yaml with the
// field omitted.
func TestEnforcementMode_DefaultIsPersonal(t *testing.T) {
	srv, _, _ := newTestServer(t)

	r := newLocalRequest(http.MethodGet, "/api/config/enforcement-mode", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("enforcement-mode code = %d", w.Code)
	}
	var em EnforcementModeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &em); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if em.Mode != "personal" {
		t.Errorf("mode = %q, want %q", em.Mode, "personal")
	}

	r = newLocalRequest(http.MethodGet, "/api/status", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	var st StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if st.EnforcementMode != "personal" {
		t.Errorf("status enforcement_mode = %q, want %q", st.EnforcementMode, "personal")
	}
}

// TestEnforcementMode_RoundTrip walks each accepted value through
// SetEnforcementMode and asserts both endpoints surface the same
// string. The Electron tray (status poll) and the extension service
// worker (dedicated endpoint) must agree on the posture or the user
// gets contradictory UI signals.
func TestEnforcementMode_RoundTrip(t *testing.T) {
	for _, mode := range []string{"personal", "team", "managed"} {
		t.Run(mode, func(t *testing.T) {
			srv, _, _ := newTestServer(t)
			srv.SetEnforcementMode(mode)

			r := newLocalRequest(http.MethodGet, "/api/config/enforcement-mode", nil)
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("enforcement-mode code = %d", w.Code)
			}
			var em EnforcementModeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &em); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if em.Mode != mode {
				t.Errorf("/api/config/enforcement-mode mode = %q, want %q", em.Mode, mode)
			}

			r = newLocalRequest(http.MethodGet, "/api/status", nil)
			w = httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, r)
			var st StatusResponse
			if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
				t.Fatalf("unmarshal status: %v", err)
			}
			if st.EnforcementMode != mode {
				t.Errorf("/api/status enforcement_mode = %q, want %q", st.EnforcementMode, mode)
			}
		})
	}
}

// TestEnforcementMode_UnknownCoercesToPersonal pins the defensive
// branch in SetEnforcementMode. config.validate() is the primary
// gate, but if a future code path bypasses config loading (a test, a
// future profile import, etc.) the safer behaviour is to fall back
// to "personal" rather than report an unknown string to clients.
func TestEnforcementMode_UnknownCoercesToPersonal(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetEnforcementMode("bogus")

	r := newLocalRequest(http.MethodGet, "/api/config/enforcement-mode", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var em EnforcementModeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &em); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if em.Mode != "personal" {
		t.Errorf("mode = %q, want personal", em.Mode)
	}
}

// TestEnforcementMode_RejectsNonGET confirms PUT/POST/DELETE return
// 405. The endpoint is read-only by design — mutation must go
// through config.yaml + restart so the policy is rooted in the
// operator-controlled config rather than any runtime API surface.
func TestEnforcementMode_RejectsNonGET(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := newLocalRequest(method, "/api/config/enforcement-mode", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code = %d, want 405", method, w.Code)
		}
	}
}

// TestRiskyExtensions_DefaultOmitsField pins the B2 backwards-compat
// wire shape: a server constructed without SetRiskyFileExtensions
// (or called with nil) must serve a JSON body where the
// `extensions` field is *absent*, not `null` or `[]`. The
// extension's service worker treats the absent field as "use my
// baked-in default list"; both `null` and `[]` would be
// indistinguishable from the opt-out wire shape and would silently
// disable risky-extension blocking on every fresh install.
func TestRiskyExtensions_DefaultOmitsField(t *testing.T) {
	srv, _, _ := newTestServer(t)

	r := newLocalRequest(http.MethodGet, "/api/config/risky-extensions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	body := w.Body.String()
	// Trim trailing newline that json.Encoder.Encode adds so the
	// equality check tolerates the encoder's behaviour without
	// reparsing.
	if got, want := strings.TrimRight(body, "\n"), `{}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestRiskyExtensions_ExplicitEmptyArrayOptOut pins the opt-out
// wire shape: when the operator wrote `risky_file_extensions: []`
// in config.yaml (and main wired that through
// SetRiskyFileExtensions([]string{})), the response body must
// carry an explicit empty array so the extension knows to disable
// enforcement rather than fall back to its built-in default.
func TestRiskyExtensions_ExplicitEmptyArrayOptOut(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRiskyFileExtensions([]string{})

	r := newLocalRequest(http.MethodGet, "/api/config/risky-extensions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	if got, want := strings.TrimRight(w.Body.String(), "\n"), `{"extensions":[]}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestRiskyExtensions_OverrideRoundTrip walks a populated override
// list through SetRiskyFileExtensions and asserts the JSON body
// surfaces the list verbatim. The slice is also order-preserving so
// the extension's cached copy looks identical to what the operator
// wrote in config.yaml.
func TestRiskyExtensions_OverrideRoundTrip(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRiskyFileExtensions([]string{"exe", "scr", "ps1"})

	r := newLocalRequest(http.MethodGet, "/api/config/risky-extensions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var got RiskyExtensionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Extensions == nil {
		t.Fatalf("extensions = nil, want populated slice")
	}
	want := []string{"exe", "scr", "ps1"}
	if len(*got.Extensions) != len(want) {
		t.Fatalf("len = %d, want %d", len(*got.Extensions), len(want))
	}
	for i, e := range want {
		if (*got.Extensions)[i] != e {
			t.Errorf("[%d] = %q, want %q", i, (*got.Extensions)[i], e)
		}
	}
}

// TestRiskyExtensions_DefensiveCopy pins the contract that the
// caller can mutate the slice they handed to SetRiskyFileExtensions
// and the server's view stays stable. The first response captures
// the original list; the post-mutation response must surface the
// same list unchanged. Without the defensive copy a hostile
// invocation could swap the active list out from under in-flight
// requests.
func TestRiskyExtensions_DefensiveCopy(t *testing.T) {
	srv, _, _ := newTestServer(t)
	src := []string{"exe", "scr"}
	srv.SetRiskyFileExtensions(src)
	src[0] = "POISONED"
	src[1] = "POISONED"

	r := newLocalRequest(http.MethodGet, "/api/config/risky-extensions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var got RiskyExtensionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Extensions == nil || len(*got.Extensions) != 2 {
		t.Fatalf("extensions = %#v, want [exe scr]", got.Extensions)
	}
	if (*got.Extensions)[0] != "exe" || (*got.Extensions)[1] != "scr" {
		t.Errorf("server view mutated by caller: got %q, %q",
			(*got.Extensions)[0], (*got.Extensions)[1])
	}
}

// TestRiskyExtensions_RejectsNonGET confirms PUT/POST/DELETE return
// 405. Like /api/config/enforcement-mode the endpoint is read-only by
// design — mutation must go through config.yaml + restart so the
// policy is rooted in the operator-controlled config rather than any
// runtime API surface that a compromised AI page or hostile Tier-2
// tool could reach.
func TestRiskyExtensions_RejectsNonGET(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := newLocalRequest(method, "/api/config/risky-extensions", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code = %d, want 405", method, w.Code)
		}
	}
}

// TestRiskyExtensions_AIPageOriginAllowed locks in that the endpoint
// is reachable from AI page origins (chatgpt.com, claude.ai, etc.).
// The browser extension's service worker fetches the list on cold
// start; a CORS regression that demoted the endpoint to control-only
// would break risky-extension blocking on every fresh navigation to
// a Tier-2 page. The endpoint's body is one of three small wire
// shapes — no scoring thresholds, no classifier mappings — so the
// disclosure surface is identical to /api/config/enforcement-mode.
func TestRiskyExtensions_AIPageOriginAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.SetRiskyFileExtensions([]string{"exe", "scr"})

	r := newLocalRequest(http.MethodGet, "/api/config/risky-extensions", nil)
	r.Header.Set("Origin", "https://chatgpt.com")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusForbidden {
		t.Fatalf("AI origin returned 403 — control-path regression")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://chatgpt.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want chatgpt.com", got)
	}
}

// TestStatus_StripsRuleFilePaths is the Task 6 regression: the
// default /api/status payload must not echo full filesystem paths
// in its rule-file metadata. Leaking install layouts to any
// caller (the extension page included) gives free reconnaissance
// information for negligible operational gain. The basename is
// preserved so the existing operator-facing JSON still tells you
// which file is which.
func TestStatus_StripsRuleFilePaths(t *testing.T) {
	srv, _, _ := newTestServer(t)
	dir := t.TempDir()
	full := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(full, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("seed rule file: %v", err)
	}
	srv.SetRuleFiles([]string{full})

	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body=%s", w.Code, w.Body.String())
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(got.Rules))
	}
	p := got.Rules[0].Path
	if strings.ContainsAny(p, `/\`) {
		t.Errorf("Path %q contains separator; expected basename", p)
	}
	if p != "block.txt" {
		t.Errorf("Path = %q, want %q", p, "block.txt")
	}
}

// TestStatus_DebugFlagFromLocalhostExposesFullPath proves the
// debug-only escape hatch still works: ?debug=true from a loopback
// caller re-enables the absolute path so operators tailing the
// status JSON locally can still see the on-disk location.
func TestStatus_DebugFlagFromLocalhostExposesFullPath(t *testing.T) {
	srv, _, _ := newTestServer(t)
	dir := t.TempDir()
	full := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(full, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("seed rule file: %v", err)
	}
	srv.SetRuleFiles([]string{full})

	r := newLocalRequest(http.MethodGet, "/api/status?debug=true", nil)
	r.RemoteAddr = "127.0.0.1:55555"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(got.Rules))
	}
	if got.Rules[0].Path != full {
		t.Errorf("Path = %q, want %q (debug should expose full path)", got.Rules[0].Path, full)
	}
}

// TestStatus_DegradedFlag covers Task 4's wire surface: SetDegraded
// flips the top-level status response to expose a "degraded": true
// hint so the extension / tray can warn the operator that the
// agent booted without its expected baseline.
func TestStatus_DegradedFlag(t *testing.T) {
	srv, _, _ := newTestServer(t)

	r := newLocalRequest(http.MethodGet, "/api/status", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Degraded {
		t.Errorf("degraded=true before SetDegraded")
	}

	srv.SetDegraded(true)
	r = newLocalRequest(http.MethodGet, "/api/status", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var got2 StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got2.Degraded {
		t.Errorf("degraded=false after SetDegraded(true)")
	}
}

// TestUpdatePolicy_UnknownCategoryReturns400 covers the API-shape
// half of the Task 7 hardening: store.SetPolicy now returns
// ErrInvalidCategory for an out-of-set category name, and the
// handler must map that to 400, not 500. A 500 would mislead
// callers into believing the agent malfunctioned rather than that
// their request was rejected.
func TestUpdatePolicy_UnknownCategoryReturns400(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/Made%20Up%20Category", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d body=%s, want 400", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid category") {
		t.Errorf("body %q should mention invalid category", w.Body.String())
	}
}

// TestUpdatePolicy_InvalidActionReturns400 is the regression baseline:
// the existing ErrInvalidAction → 400 mapping must still fire. Without
// this test a future refactor of the err-mapping ladder could drop the
// pre-existing branch and only the new category branch would be
// covered by the suite.
func TestUpdatePolicy_InvalidActionReturns400(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"definitely-not-an-action"}`)
	r := newLocalRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d body=%s, want 400", w.Code, w.Body.String())
	}
}

// TestDLPConfig_InvalidThresholdReturns400 covers the API-shape
// half of the Task 7 DLP validator: store.SetDLPConfig now returns
// ErrInvalidDLPConfig-wrapped errors for non-positive thresholds and
// out-of-bounds weights, and the handler must surface that as 400
// with the underlying message so callers know which field is wrong.
func TestDLPConfig_InvalidThresholdReturns400(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	srv.SetDLP(&fakeDLP{thr: thr})

	bad := store.DLPConfig{
		ThresholdCritical: 0, // invalid
		ThresholdHigh:     1,
		ThresholdMedium:   2,
		ThresholdLow:      3,
	}
	body, _ := json.Marshal(bad)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "threshold_critical") {
		t.Errorf("body %q should name the offending field", rec.Body.String())
	}
}

// TestDLPConfig_OutOfBoundsWeightReturns400 covers the weight half
// of the Task 7 DLP validator at the API surface.
func TestDLPConfig_OutOfBoundsWeightReturns400(t *testing.T) {
	srv, _, _ := newTestServer(t)
	thr := dlp.NewThresholdEngine(dlp.DefaultThresholds())
	srv.SetDLP(&fakeDLP{thr: thr})

	bad := store.DLPConfig{
		ThresholdCritical: 10,
		ThresholdHigh:     8,
		ThresholdMedium:   5,
		ThresholdLow:      2,
		HotwordBoost:      200, // outside [-100,100]
	}
	body, _ := json.Marshal(bad)
	rec := httptest.NewRecorder()
	req := newLocalRequest(http.MethodPut, "/api/dlp/config", bytes.NewBuffer(body))
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "hotword_boost") {
		t.Errorf("body %q should name the offending field", rec.Body.String())
	}
}

// TestStatus_DebugFlagRejectedFromAIPageOrigin closes the Devin
// Review bypass: the agent's listener binds to 127.0.0.1, so every
// caller's RemoteAddr is loopback — including content scripts on
// AI-page origins that CORS already lets reach /api/status. Gating
// ?debug=true on RemoteAddr was therefore dead code against the
// stated threat model. The new gate is Origin-based: an AI-page
// Origin (here https://chatgpt.com) must still receive the
// path-stripped response even when the caller asked for debug.
func TestStatus_DebugFlagRejectedFromAIPageOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	dir := t.TempDir()
	full := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(full, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("seed rule file: %v", err)
	}
	srv.SetRuleFiles([]string{full})

	r := newLocalRequest(http.MethodGet, "/api/status?debug=true", nil)
	r.Header.Set("Origin", "https://chatgpt.com")
	r.RemoteAddr = "127.0.0.1:55555"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(got.Rules))
	}
	if got.Rules[0].Path == full {
		t.Errorf("AI-page Origin received full path %q; debug should be denied", full)
	}
	if got.Rules[0].Path != filepath.Base(full) {
		t.Errorf("Path = %q, want basename %q",
			got.Rules[0].Path, filepath.Base(full))
	}
}

// TestStatus_DebugFlagAllowedFromControlOrigin pins the positive
// half of the new gate: a control Origin (the Electron renderer's
// file:// → "null") gets the absolute path back so the tray's
// diagnostics view keeps working. Without this, the operator-facing
// admin surface would lose its access to the on-disk path.
func TestStatus_DebugFlagAllowedFromControlOrigin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	dir := t.TempDir()
	full := filepath.Join(dir, "block.txt")
	if err := os.WriteFile(full, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("seed rule file: %v", err)
	}
	srv.SetRuleFiles([]string{full})

	r := newLocalRequest(http.MethodGet, "/api/status?debug=true", nil)
	// "null" is the Origin Chromium sends for file:// — the
	// packaged Electron renderer in production.
	r.Header.Set("Origin", "null")
	r.RemoteAddr = "127.0.0.1:55555"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	var got StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].Path != full {
		t.Errorf("control-origin debug request did not surface full path: %+v", got.Rules)
	}
}

// TestControlEndpoints_BodyTooLarge confirms every JSON control
// endpoint that reads r.Body returns 413 Request Entity Too Large
// when the body exceeds maxControlBytes. The handlers are wired
// through decodeControlBody (defined in handlers.go), which wraps
// r.Body in http.MaxBytesReader and distinguishes the cap from a
// malformed-JSON error so the caller knows which constraint they
// tripped. A regression that strips the cap (or that returns 400
// instead of 413 on overrun) would silently re-expose the
// memory-exhaustion vector this guard exists to close — hence the
// per-endpoint table here.
func TestControlEndpoints_BodyTooLarge(t *testing.T) {
	// 64 KiB is the documented cap; one extra byte forces
	// MaxBytesReader to surface http.MaxBytesError on the very
	// first read. The payload itself is syntactically valid JSON
	// (an array of "x" characters) so a handler that wrongly
	// classifies the overrun as a parse error would land on
	// http.StatusBadRequest instead and fail the assertion below.
	oversize := bytes.Repeat([]byte{'x'}, 64*1024+1)
	bigJSON := []byte(`{"x":"` + string(oversize) + `"}`)

	// Each endpoint here either previously read r.Body without a
	// cap (handlePolicyItem PUT, handleDLPConfigPut,
	// handleRuleOverride POST) or treated an empty body as a
	// no-op while still accepting an arbitrary-sized one
	// (handleProxyDisable). All four now share decodeControlBody.
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"policy PUT", http.MethodPut, "/api/policies/AI%20Chat%20Blocked"},
		{"dlp config PUT", http.MethodPut, "/api/dlp/config"},
		{"rule override POST", http.MethodPost, "/api/rules/override"},
		{"proxy disable POST", http.MethodPost, "/api/proxy/disable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _, _ := newTestServer(t)
			// handleProxyDisable returns 503 when no Proxy is
			// wired, before reading the body. Wire a stub so the
			// cap path is the one we observe.
			if c.path == "/api/proxy/disable" {
				srv.SetProxyController(&fakeProxyController{})
			}
			// handleRuleOverride returns 503 when no rule
			// override backend is wired; wire a stub so the cap
			// path is what we observe.
			if c.path == "/api/rules/override" {
				srv.SetRuleOverride(&fakeRuleOverride{})
			}
			req := newLocalRequest(c.method, c.path, bytes.NewBuffer(bigJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("%s: code = %d (body=%q), want %d",
					c.name, rec.Code, rec.Body.String(),
					http.StatusRequestEntityTooLarge)
			}
		})
	}
}
