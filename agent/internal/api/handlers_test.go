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

func TestStatusEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/status", nil)
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
	r := httptest.NewRequest(http.MethodGet, "/api/policies", nil)
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
	r := httptest.NewRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
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
	r := httptest.NewRequest(http.MethodPut, "/api/policies/AI%20Chat%20Blocked", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestUpdatePolicyMissingCategory(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := bytes.NewBufferString(`{"action":"allow"}`)
	r := httptest.NewRequest(http.MethodPut, "/api/policies/", body)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
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
	r := httptest.NewRequest(http.MethodPost, "/api/stats/reset", nil)
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
		r := httptest.NewRequest(c.method, c.path, nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: code = %d", c.method, c.path, w.Code)
		}
	}
}

func TestCORSPreflight(t *testing.T) {
	srv, _, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodOptions, "/api/policies", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("code = %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("CORS header missing")
	}
}
