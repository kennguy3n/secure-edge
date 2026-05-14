package profile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestParseAndValidate(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name:    "valid minimal",
			raw:     `{"name":"acme","version":"1.0.0"}`,
			wantErr: false,
		},
		{
			name: "valid with categories and thresholds",
			raw: `{
				"name":"acme",
				"version":"1.0.0",
				"managed":true,
				"categories":{"AI Chat Blocked":"deny","AI Allowed":"allow"},
				"dlp_thresholds":{"threshold_critical":1,"threshold_high":2}
			}`,
			wantErr: false,
		},
		{
			name:    "missing name",
			raw:     `{"version":"1.0.0"}`,
			wantErr: true,
		},
		{
			name:    "invalid category action",
			raw:     `{"name":"acme","categories":{"AI Allowed":"forbid"}}`,
			wantErr: true,
		},
		{
			name:    "negative threshold",
			raw:     `{"name":"acme","dlp_thresholds":{"threshold_high":-1}}`,
			wantErr: true,
		},
		{
			name:    "not json",
			raw:     `not json`,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(`{"name":"acme","managed":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !p.Managed || p.Name != "acme" {
		t.Fatalf("unexpected profile: %+v", p)
	}

	if _, err := LoadFromFile(""); err == nil {
		t.Fatalf("expected error for empty path")
	}
	if _, err := LoadFromFile(filepath.Join(dir, "nope.json")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoadFromURL(t *testing.T) {
	// httptest.NewTLSServer binds to 127.0.0.1, which the production
	// SSRF guard rejects. Stub the hook out for the duration of this
	// test so we can exercise the happy / error paths through HTTPS
	// without standing up a non-loopback TLS endpoint.
	orig := hostCheck
	hostCheck = func(_ context.Context, _ string) error { return nil }
	t.Cleanup(func() { hostCheck = orig })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"acme","version":"1.0.0"}`))
		case "/bad":
			w.WriteHeader(http.StatusInternalServerError)
		case "/huge":
			// Stream a body larger than maxProfileBytes.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"x","_pad":"`))
			big := strings.Repeat("a", maxProfileBytes+1024)
			_, _ = w.Write([]byte(big))
			_, _ = w.Write([]byte(`"}`))
		case "/bad-json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":`))
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	p, err := LoadFromURL(ctx, srv.Client(), srv.URL+"/ok")
	if err != nil {
		t.Fatalf("ok: %v", err)
	}
	if p.Name != "acme" {
		t.Fatalf("unexpected: %+v", p)
	}

	if _, err := LoadFromURL(ctx, srv.Client(), srv.URL+"/bad"); err == nil {
		t.Fatalf("expected error on 5xx")
	}
	if _, err := LoadFromURL(ctx, srv.Client(), srv.URL+"/huge"); err == nil {
		t.Fatalf("expected error on oversized response")
	}
	if _, err := LoadFromURL(ctx, srv.Client(), srv.URL+"/bad-json"); err == nil {
		t.Fatalf("expected error on malformed json")
	}
	if _, err := LoadFromURL(ctx, srv.Client(), ""); err == nil {
		t.Fatalf("expected error on empty url")
	}
	if _, err := LoadFromURL(ctx, srv.Client(), "ftp://example.com/p.json"); err == nil {
		t.Fatalf("expected error on non-http scheme")
	}
}

// TestLoadFromURL_RejectsHTTPScheme pins the P0-2 HTTPS-only guard.
// A profile document is a load-bearing security artefact (it can flip
// the agent into managed mode, lock the device, and rewrite category
// policies) and must not be subject to in-flight modification by a
// network attacker. A plain http:// scheme is rejected unconditionally.
func TestLoadFromURL_RejectsHTTPScheme(t *testing.T) {
	orig := hostCheck
	hostCheck = func(_ context.Context, _ string) error { return nil }
	t.Cleanup(func() { hostCheck = orig })

	cases := []string{
		"http://mdm.example.com/profile.json",
		"http://127.0.0.1/profile.json",
		"http://[::1]/profile.json",
	}
	for _, rawURL := range cases {
		_, err := LoadFromURL(context.Background(), nil, rawURL)
		if err == nil {
			t.Errorf("%s: expected scheme error, got nil", rawURL)
			continue
		}
		if !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: error %q must mention https", rawURL, err)
		}
	}
}

// TestLoadFromURL_RejectsPrivateOrLoopbackHosts pins the P0-2 SSRF
// guard. A managed profile is fetched on agent startup as well as on
// every rule update; without this guard a hostile `profile_url` (or a
// fleet operator whose own MDM has been compromised) could trick the
// agent into talking to internal services on the same host or LAN.
//
// We exercise literal IP rejection here so the test doesn't depend on
// the host's DNS being able to resolve a public name; the resolver
// path is covered by TestLoadFromURL_RejectsHostnameResolvingToPrivate.
func TestLoadFromURL_RejectsPrivateOrLoopbackHosts(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/profile.json",
		"https://127.1.2.3/profile.json",
		"https://[::1]/profile.json",
		"https://10.0.0.1/profile.json",
		"https://10.255.255.255/profile.json",
		"https://172.16.0.1/profile.json",
		"https://172.31.255.254/profile.json",
		"https://192.168.0.1/profile.json",
		"https://192.168.255.254/profile.json",
		"https://169.254.169.254/profile.json", // AWS / Azure IMDS
		"https://[fc00::1]/profile.json",       // unique-local IPv6
		"https://[fe80::1]/profile.json",       // link-local IPv6
		"https://0.0.0.0/profile.json",
		"https://[::]/profile.json",
	}
	for _, rawURL := range cases {
		_, err := LoadFromURL(context.Background(), nil, rawURL)
		if err == nil {
			t.Errorf("%s: expected SSRF rejection, got nil", rawURL)
			continue
		}
		if !strings.Contains(err.Error(), "private/loopback") {
			t.Errorf("%s: error %q must mention private/loopback", rawURL, err)
		}
	}
}

// TestLoadFromURL_RejectsHostnameResolvingToPrivate exercises the
// resolver branch of the SSRF guard: a benign-looking hostname whose
// DNS resolution happens to return a loopback / RFC1918 address is
// still rejected. This is the DNS-rebinding flavour of SSRF — without
// it, a public hostname could legitimately return 127.0.0.1 and the
// agent would happily POST a profile fetch through localhost.
func TestLoadFromURL_RejectsHostnameResolvingToPrivate(t *testing.T) {
	origResolver := profileResolver
	profileResolver = func(_ context.Context, host string) ([]string, error) {
		if host == "mdm-rebinder.example.com" {
			return []string{"127.0.0.1"}, nil
		}
		return nil, errors.New("unexpected host")
	}
	t.Cleanup(func() { profileResolver = origResolver })

	_, err := LoadFromURL(context.Background(), nil, "https://mdm-rebinder.example.com/profile.json")
	if err == nil {
		t.Fatalf("expected SSRF rejection for hostname resolving to 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "private/loopback") {
		t.Fatalf("error %q must mention private/loopback", err)
	}
}

func TestHolder(t *testing.T) {
	h := NewHolder(nil)
	if h.Get() != nil {
		t.Fatalf("expected nil for unset holder")
	}
	if h.Locked() {
		t.Fatalf("nil profile must not be locked")
	}

	if err := h.Set(&Profile{Name: "acme"}); err != nil {
		t.Fatalf("set unlocked: %v", err)
	}
	if h.Locked() {
		t.Fatalf("unmanaged profile must not be locked")
	}

	managed := &Profile{Name: "acme", Managed: true, Categories: map[string]string{"AI Allowed": "allow"}}
	if err := h.Set(managed); err != nil {
		t.Fatalf("set managed: %v", err)
	}
	if !h.Locked() {
		t.Fatalf("managed profile must be locked")
	}

	got := h.Get()
	if !got.Managed || got.Categories["AI Allowed"] != "allow" {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	// Mutating the snapshot must not affect the holder.
	got.Categories["AI Allowed"] = "deny"
	if h.Get().Categories["AI Allowed"] != "allow" {
		t.Fatalf("Get should return a defensive copy")
	}

	if err := h.Set(&Profile{}); err == nil {
		t.Fatalf("Set should reject invalid profile")
	}

	// Concurrent reads while a writer flips the profile should not race.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = h.Get()
				_ = h.Locked()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		_ = h.Set(&Profile{Name: "acme", Managed: i%2 == 0})
	}
	wg.Wait()
}

// fakePolicyStore implements profile.PolicyStore in memory.
type fakePolicyStore struct {
	policies  map[string]string
	dlp       DLPConfigSnapshot
	setPolicy func(category, action string) error
}

func newFakePolicyStore() *fakePolicyStore {
	return &fakePolicyStore{policies: map[string]string{}}
}

func (f *fakePolicyStore) SetPolicy(_ context.Context, category, action string) error {
	if f.setPolicy != nil {
		if err := f.setPolicy(category, action); err != nil {
			return err
		}
	}
	f.policies[category] = action
	return nil
}

func (f *fakePolicyStore) GetDLPConfig(_ context.Context) (DLPConfigSnapshot, error) {
	return f.dlp, nil
}

func (f *fakePolicyStore) SetDLPConfig(_ context.Context, cfg DLPConfigSnapshot) error {
	f.dlp = cfg
	return nil
}

type fakeReloader struct{ called bool }

func (r *fakeReloader) Reload(_ context.Context) error {
	r.called = true
	return nil
}

func TestApply(t *testing.T) {
	store := newFakePolicyStore()
	store.dlp = DLPConfigSnapshot{ThresholdCritical: 9, HotwordBoost: 9}

	reload := &fakeReloader{}
	p := &Profile{
		Name:    "acme",
		Managed: true,
		Categories: map[string]string{
			"AI Chat Blocked": "deny",
			"AI Allowed":      "allow",
		},
		DLPThresholds: &DLPThresholds{ThresholdCritical: 1, EntropyBoost: 3},
	}

	if err := p.Apply(context.Background(), ApplyOptions{
		PolicyStore: store, Reloader: reload,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if store.policies["AI Chat Blocked"] != "deny" {
		t.Fatalf("policy AI Chat Blocked not applied: %v", store.policies)
	}
	if store.dlp.ThresholdCritical != 1 {
		t.Fatalf("threshold_critical not applied: %+v", store.dlp)
	}
	// HotwordBoost was preserved because the profile didn't override it (zero value).
	if store.dlp.HotwordBoost != 9 {
		t.Fatalf("hotword_boost should be preserved when profile leaves it 0: %+v", store.dlp)
	}
	if store.dlp.EntropyBoost != 3 {
		t.Fatalf("entropy_boost not applied: %+v", store.dlp)
	}
	if !reload.called {
		t.Fatalf("reloader should have been called")
	}

	// nil profile → error
	var nilProf *Profile
	if err := nilProf.Apply(context.Background(), ApplyOptions{PolicyStore: store}); err == nil {
		t.Fatalf("expected error on nil profile")
	}

	// nil store → error
	if err := p.Apply(context.Background(), ApplyOptions{}); err == nil {
		t.Fatalf("expected error on nil store")
	}

	// underlying error propagates
	boom := newFakePolicyStore()
	boom.setPolicy = func(_, _ string) error { return errors.New("boom") }
	if err := p.Apply(context.Background(), ApplyOptions{PolicyStore: boom}); err == nil {
		t.Fatalf("expected error to propagate")
	}
}

// TestApplyDLPSink locks in the propagation contract for the live
// DLP pipeline: when a profile carries DLP thresholds, Apply must
// invoke the DLPSink callback with the merged snapshot so the live
// pipeline stays in sync with what's persisted in SQLite.
func TestApplyDLPSink(t *testing.T) {
	t.Run("fires with merged snapshot", func(t *testing.T) {
		store := newFakePolicyStore()
		store.dlp = DLPConfigSnapshot{ThresholdCritical: 9, HotwordBoost: 9}

		var got DLPConfigSnapshot
		var calls int
		sink := func(c DLPConfigSnapshot) {
			calls++
			got = c
		}

		p := &Profile{
			DLPThresholds: &DLPThresholds{ThresholdCritical: 1, EntropyBoost: 3},
		}
		if err := p.Apply(context.Background(), ApplyOptions{
			PolicyStore: store, DLPSink: sink,
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if calls != 1 {
			t.Fatalf("expected DLPSink to fire exactly once, got %d", calls)
		}
		if got.ThresholdCritical != 1 {
			t.Fatalf("sink threshold_critical: got %d want 1", got.ThresholdCritical)
		}
		if got.HotwordBoost != 9 {
			t.Fatalf("sink hotword_boost: zero override should preserve existing, got %d want 9", got.HotwordBoost)
		}
		if got.EntropyBoost != 3 {
			t.Fatalf("sink entropy_boost: got %d want 3", got.EntropyBoost)
		}
	})

	t.Run("nil sink is a no-op", func(t *testing.T) {
		store := newFakePolicyStore()
		p := &Profile{
			DLPThresholds: &DLPThresholds{ThresholdCritical: 5},
		}
		if err := p.Apply(context.Background(), ApplyOptions{
			PolicyStore: store, // DLPSink intentionally nil
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	})

	t.Run("no DLP thresholds means sink is not called", func(t *testing.T) {
		store := newFakePolicyStore()
		var calls int
		sink := func(DLPConfigSnapshot) { calls++ }
		p := &Profile{
			Categories: map[string]string{"AI Allowed": "allow"},
		}
		if err := p.Apply(context.Background(), ApplyOptions{
			PolicyStore: store, DLPSink: sink,
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if calls != 0 {
			t.Fatalf("sink should not fire when profile carries no DLP thresholds, got %d", calls)
		}
	})
}
