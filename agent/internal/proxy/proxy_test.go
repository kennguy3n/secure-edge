package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
)

// fakeScanner is a deterministic DLPScanner stand-in. If blockOn
// substring appears anywhere in the scanned content, it returns
// Blocked=true with patternName.
type fakeScanner struct {
	blockOn     string
	patternName string
	calls       atomic.Int64
}

func (f *fakeScanner) Scan(_ context.Context, content string) dlp.ScanResult {
	f.calls.Add(1)
	if f.blockOn != "" && strings.Contains(content, f.blockOn) {
		return dlp.ScanResult{Blocked: true, PatternName: f.patternName, Score: 9}
	}
	return dlp.ScanResult{}
}

// fakeStats counts calls so tests can verify aggregate counters
// flow through.
type fakeStats struct {
	scans  atomic.Int64
	blocks atomic.Int64
}

func (f *fakeStats) BumpDLP(_ context.Context, blocked bool) error {
	f.scans.Add(1)
	if blocked {
		f.blocks.Add(1)
	}
	return nil
}

// newTestCA creates a CA backed by a temp directory.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

func TestServer_RejectsNilDeps(t *testing.T) {
	ca := newTestCA(t)
	cases := []struct {
		name    string
		ca      *CA
		policy  PolicyChecker
		scanner DLPScanner
	}{
		{"nil ca", nil, PolicyCheckerFunc(func(string) bool { return false }), &fakeScanner{}},
		{"nil policy", ca, nil, &fakeScanner{}},
		{"nil scanner", ca, PolicyCheckerFunc(func(string) bool { return false }), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.ca, tc.policy, tc.scanner, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestServer_HTTPRequestNonTier2PassesThrough(t *testing.T) {
	// Spin up a fake upstream that returns 200 OK with a sentinel
	// body, then run the proxy against it for a domain the policy
	// does not classify as Tier 2.
	const sentinel = "upstream body sentinel"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, sentinel)
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "should-never-trigger", patternName: "x"}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) bool { return false }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != sentinel {
		t.Errorf("body = %q, want %q", string(body), sentinel)
	}
	if scanner.calls.Load() != 0 {
		t.Errorf("scanner called %d times for non-Tier-2 host", scanner.calls.Load())
	}
	if srv.ScansTotal() != 0 {
		t.Errorf("scans counter = %d, want 0", srv.ScansTotal())
	}
}

func TestServer_HTTPRequestTier2ScannedAndAllowed(t *testing.T) {
	const sentinel = "harmless content"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key"}
	stats := &fakeStats{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) bool { return true }), scanner, stats)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader(sentinel))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if scanner.calls.Load() != 1 {
		t.Errorf("scanner calls = %d, want 1", scanner.calls.Load())
	}
	if got := srv.ScansTotal(); got != 1 {
		t.Errorf("ScansTotal = %d, want 1", got)
	}
	if got := srv.BlocksTotal(); got != 0 {
		t.Errorf("BlocksTotal = %d, want 0", got)
	}
	if got := stats.scans.Load(); got != 1 {
		t.Errorf("stats scans = %d, want 1", got)
	}
	if got := stats.blocks.Load(); got != 0 {
		t.Errorf("stats blocks = %d, want 0", got)
	}
}

func TestServer_HTTPRequestTier2Blocked451(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream must never be reached on a blocked request")
		_, _ = io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "AKIAIOSFODNN7EXAMPLE", patternName: "AWS Access Key"}
	stats := &fakeStats{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) bool { return true }), scanner, stats)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("payload AKIAIOSFODNN7EXAMPLE moredata"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode body: %v (body=%q)", err, string(body))
	}
	if decoded["blocked"] != true {
		t.Errorf("blocked = %v", decoded["blocked"])
	}
	if decoded["pattern_name"] != "AWS Access Key" {
		t.Errorf("pattern_name = %v", decoded["pattern_name"])
	}
	if got := srv.ScansTotal(); got != 1 {
		t.Errorf("ScansTotal = %d, want 1", got)
	}
	if got := srv.BlocksTotal(); got != 1 {
		t.Errorf("BlocksTotal = %d, want 1", got)
	}
	if got := stats.blocks.Load(); got != 1 {
		t.Errorf("stats blocks = %d, want 1", got)
	}
}

func TestServer_HTTPSConnectPassthroughNoDecryption(t *testing.T) {
	// Spin up a TLS upstream with a one-off cert that is not trusted
	// by either the proxy CA or the system roots. If the proxy were
	// MITM'ing the connection, the goproxy leaf would be signed by
	// the proxy CA and the client (configured to trust ONLY that
	// upstream's cert) would reject the handshake. Conversely, when
	// the proxy passes the CONNECT through opaquely the client sees
	// the genuine upstream cert and the handshake succeeds.
	const sentinel = "tunnel content"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, sentinel)
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) bool { return false }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	upstreamCerts := upstream.Certificate()
	pool := x509.NewCertPool()
	pool.AddCert(upstreamCerts)

	tlsCfg := &tls.Config{RootCAs: pool}
	client := proxyClient(t, proxySrv.URL, tlsCfg)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != sentinel {
		t.Errorf("body = %q, want %q", string(body), sentinel)
	}
	if scanner.calls.Load() != 0 {
		t.Errorf("scanner called %d times on opaque tunnel", scanner.calls.Load())
	}
}

func TestServer_HTTPSConnectTier2DecryptedAndBlocked(t *testing.T) {
	// Build an https upstream that records the request body. The
	// proxy MITM-decrypts the CONNECT, sees a DLP match, and returns
	// 451 — the upstream handler must never see the request.
	upstreamHit := atomic.Bool{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = io.WriteString(w, "should not reach upstream")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: "SECRETPLACEHOLDER", patternName: "Test Pattern"}
	srv, err := New(ca, PolicyCheckerFunc(func(_ string) bool { return true }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	// Trust the proxy's Root CA so the MITM'd leaf validates client-
	// side. Without this the client would reject the handshake.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	tlsCfg := &tls.Config{RootCAs: pool}

	client := proxyClient(t, proxySrv.URL, tlsCfg)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL,
		strings.NewReader("body has SECRETPLACEHOLDER inside"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451", resp.StatusCode)
	}
	if upstreamHit.Load() {
		t.Error("upstream was hit despite DLP block")
	}
	if srv.BlocksTotal() != 1 {
		t.Errorf("BlocksTotal = %d, want 1", srv.BlocksTotal())
	}
}

func TestServer_ListenAndServeLifecycle(t *testing.T) {
	ca := newTestCA(t)
	srv, err := New(ca,
		PolicyCheckerFunc(func(_ string) bool { return false }),
		&fakeScanner{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.Running() {
		t.Fatal("Running should be false before ListenAndServe")
	}

	addr := "127.0.0.1:" + freePort(t)
	if err := srv.ListenAndServe(addr); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !srv.Running() {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.Running() {
		t.Fatal("Running stayed false after ListenAndServe")
	}
	if srv.ListenAddr() != addr {
		t.Errorf("ListenAddr = %q, want %q", srv.ListenAddr(), addr)
	}

	// Second ListenAndServe should fail.
	if err := srv.ListenAndServe(addr); err == nil {
		t.Error("second ListenAndServe should error")
	}
}

// proxyClient builds an http.Client whose transport routes everything
// through the proxy at proxyURL. When tlsCfg is nil the client uses
// InsecureSkipVerify so plain GETs against httptest backends still
// work without trust roots — overridden when tlsCfg is supplied.
func proxyClient(t *testing.T, proxyURL string, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	cfg := tlsCfg
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(u),
			TLSClientConfig: cfg,
		},
		Timeout: 5 * time.Second,
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 0: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// boundedReader returns 1 MiB of data per Read call so the test can
// detect whether readScanBody fully buffered the body (peak heap)
// vs. streamed it (constant heap). We hand it 4 GiB total. If
// io.ReadAll is reintroduced this test will OOM on the CI runner;
// the streaming path completes in milliseconds with ~maxScanBytes
// of resident memory.
type boundedReader struct {
	total int64
	read  int64
	chunk []byte
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.read >= r.total {
		return 0, io.EOF
	}
	remaining := r.total - r.read
	n := int64(len(p))
	if n > int64(len(r.chunk)) {
		n = int64(len(r.chunk))
	}
	if n > remaining {
		n = remaining
	}
	copy(p, r.chunk[:n])
	r.read += n
	return int(n), nil
}

func (r *boundedReader) Close() error { return nil }

// TestReadScanBody_OverCapStreams pins the P1-3 invariant: a body
// larger than maxScanBytes returns exactly maxScanBytes of scan
// bytes and the replacement reader streams the remainder (so the
// scan path doesn't have to fit the whole body in RAM at once).
//
// We send 4 GiB of zeros and verify:
//   - readScanBody returns len(buf) == maxScanBytes (no over-read)
//   - reading the replacement back yields exactly 4 GiB
//   - peak resident heap growth stays below 64 MiB (well under the
//     full body size, ruling out the old io.ReadAll path)
func TestReadScanBody_OverCapStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-GiB streaming test in -short mode")
	}
	const total int64 = 4 * 1024 * 1024 * 1024 // 4 GiB
	chunk := make([]byte, 1024*1024)           // 1 MiB filled with zeros
	req := &http.Request{Body: &boundedReader{total: total, chunk: chunk}}

	var before, after runtimeMemStats
	readMemStats(&before)

	buf, replacement, err := readScanBody(req)
	if err != nil {
		t.Fatalf("readScanBody: %v", err)
	}
	if got := len(buf); got != maxScanBytes {
		t.Fatalf("len(buf) = %d, want maxScanBytes = %d", got, maxScanBytes)
	}

	// Drain the replacement and count its size — must equal `total`
	// to prove the streamed remainder isn't being silently truncated.
	streamed, err := io.Copy(io.Discard, replacement)
	if err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if streamed != total {
		t.Fatalf("streamed bytes = %d, want %d (body was truncated)", streamed, total)
	}
	if err := replacement.Close(); err != nil {
		t.Fatalf("replacement.Close: %v", err)
	}
	// Second close must be a no-op (idempotent).
	if err := replacement.Close(); err != nil {
		t.Fatalf("replacement.Close (second): %v", err)
	}

	readMemStats(&after)
	// Allow generous slack — we only care that we didn't buffer
	// the whole body. maxScanBytes (4 MiB) + GC noise is far below
	// 64 MiB; the old io.ReadAll path would have allocated ~4 GiB.
	// HeapAlloc may also shrink (GC ran between snapshots), which is
	// a passing outcome; only signed-positive growth counts.
	const memCap = 64 * 1024 * 1024
	if after.HeapAlloc > before.HeapAlloc {
		if delta := after.HeapAlloc - before.HeapAlloc; delta > memCap {
			t.Fatalf("heap grew by %d bytes; readScanBody must not buffer the full body", delta)
		}
	}
}

// TestServer_ListenAndServe_AppliesFullTimeouts pins every wall-clock
// budget set on the proxy's *http.Server. The proxy fronts goproxy
// for real HTTPS uploads, so the timeouts here are larger than the
// loopback control API but still bounded — a slowloris / write-stall
// must not be able to hold a listener thread forever. A regression
// (a future edit deleting one of these fields) would not surface in
// any other test, hence this dedicated field-check.
func TestServer_ListenAndServe_AppliesFullTimeouts(t *testing.T) {
	ca := newTestCA(t)
	srv, err := New(ca,
		PolicyCheckerFunc(func(_ string) bool { return false }),
		&fakeScanner{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	addr := "127.0.0.1:" + freePort(t)
	if err := srv.ListenAndServe(addr); err != nil {
		t.Fatalf("ListenAndServe: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// Wait for the listener to come up before peeking at the server.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !srv.Running() {
		time.Sleep(10 * time.Millisecond)
	}

	httpSrv := srv.httpServerForTest()
	if httpSrv == nil {
		t.Fatal("httpServerForTest returned nil")
	}
	if got, want := httpSrv.ReadHeaderTimeout, 10*time.Second; got != want {
		t.Errorf("ReadHeaderTimeout = %v, want %v", got, want)
	}
	if got, want := httpSrv.ReadTimeout, 30*time.Second; got != want {
		t.Errorf("ReadTimeout = %v, want %v", got, want)
	}
	if got, want := httpSrv.WriteTimeout, 30*time.Second; got != want {
		t.Errorf("WriteTimeout = %v, want %v", got, want)
	}
	if got, want := httpSrv.IdleTimeout, 120*time.Second; got != want {
		t.Errorf("IdleTimeout = %v, want %v", got, want)
	}
	if got, want := httpSrv.MaxHeaderBytes, 16<<10; got != want {
		t.Errorf("MaxHeaderBytes = %d, want %d", got, want)
	}
}
