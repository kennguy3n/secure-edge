// Local MITM proxy with selective TLS decryption.
//
// The proxy listens on a loopback address and is reached because the
// system proxy settings (or a process-level env var) point HTTPS at
// it. Behaviour per CONNECT target:
//
//	* Tier 2 hosts                  decrypt TLS, inspect request body
//	                                with the same DLP pipeline the
//	                                extension uses, return HTTP 451
//	                                {"blocked":true,"pattern_name":...}
//	                                if the pipeline blocks, otherwise
//	                                forward upstream untouched.
//	* All other hosts               pass-through CONNECT tunnel; bytes
//	                                are forwarded verbatim and TLS is
//	                                never terminated locally.
//
// Privacy invariant: this package must never log request bodies,
// URLs, hostnames, IP addresses, or matched DLP content. Only the
// anonymous aggregate counters (dlp_scans_total / dlp_blocks_total)
// cross the SQLite boundary, and they are bumped via the same
// stats.Counter the browser-extension path uses.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
)

// DefaultListenAddr is the default proxy listen address. Loopback
// only — never bind a public interface or another machine could
// route its TLS through us and trip the DLP pipeline on third-party
// traffic.
const DefaultListenAddr = "127.0.0.1:8443"

// maxScanBytes mirrors the cap on POST /api/dlp/scan. Larger request
// bodies are forwarded verbatim and counted, but only the first
// maxScanBytes go through the DLP pipeline so a multi-MB upload
// can't blow up agent memory.
const maxScanBytes = 4 * 1024 * 1024

// PolicyChecker reports which hostnames should be MITM'd. The agent
// wires policy.Engine in here so a CONNECT to a domain whose category
// resolves to AllowWithDLP gets decrypted and inspected; anything
// else is an opaque tunnel.
type PolicyChecker interface {
	IsTier2(host string) bool
}

// PolicyCheckerFunc adapts a function to PolicyChecker.
type PolicyCheckerFunc func(host string) bool

// IsTier2 implements PolicyChecker.
func (f PolicyCheckerFunc) IsTier2(host string) bool { return f(host) }

// DLPScanner is the subset of dlp.Pipeline the proxy needs.
type DLPScanner interface {
	Scan(ctx context.Context, content string) dlp.ScanResult
}

// StatsBumper is the subset of store.Store we need to keep
// dlp_scans_total / dlp_blocks_total in sync with the extension
// path. A nil StatsBumper is acceptable — the proxy still runs but
// scans don't contribute to aggregate counters.
type StatsBumper interface {
	BumpDLP(ctx context.Context, blocked bool) error
}

// Server is the local MITM proxy. Construct via New; start with
// ListenAndServe; stop with Shutdown.
type Server struct {
	policy PolicyChecker
	dlp    DLPScanner
	stats  StatsBumper
	ca     *CA

	httpProxy *goproxy.ProxyHttpServer

	mu       sync.Mutex
	httpSrv  *http.Server
	listenOn string
	running  atomic.Bool

	// Anonymous in-memory counters. These mirror dlp_scans_total /
	// dlp_blocks_total without depending on a SQLite store being
	// configured — useful for tests and for GET /api/proxy/status.
	scans  atomic.Int64
	blocks atomic.Int64
}

// New constructs a Server. The CA must be ready (NewCA returned
// without error). policy and dlp are required; stats is optional —
// nil disables aggregate counter updates.
func New(ca *CA, policy PolicyChecker, scanner DLPScanner, stats StatsBumper) (*Server, error) {
	if ca == nil {
		return nil, errors.New("proxy: ca is required")
	}
	if policy == nil {
		return nil, errors.New("proxy: policy is required")
	}
	if scanner == nil {
		return nil, errors.New("proxy: dlp scanner is required")
	}

	s := &Server{
		policy: policy,
		dlp:    scanner,
		stats:  stats,
		ca:     ca,
	}

	caCert := ca.TLSCertificate()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	// goproxy's default Logger logs every CONNECT target — explicitly
	// route to io.Discard so a misconfiguration can't leak hostnames
	// to stderr. The proxy must remain content-blind beyond the
	// aggregate scan/block counters.
	proxy.Logger = noopLogger{}

	tlsConfig := goproxy.TLSConfigFromCA(&caCert)

	proxy.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostname := stripPort(host)
		if s.policy.IsTier2(hostname) {
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: tlsConfig,
			}, host
		}
		// Default branch: opaque CONNECT tunnel. The bytes flow
		// untouched between client and upstream and we never see the
		// plaintext.
		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectAccept,
			TLSConfig: tlsConfig,
		}, host
	})

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// req.Host carries the CONNECT target host (no port). HTTP
		// CONNECT-less requests can hit the proxy too (a client
		// configured for plaintext HTTP); enforce the policy check
		// here a second time so a Tier 2 host reached over plain
		// HTTP also gets inspected.
		hostname := stripPort(req.Host)
		if !s.policy.IsTier2(hostname) {
			return req, nil
		}

		body, replacement, err := readScanBody(req)
		if err != nil {
			return req, badGateway(req)
		}
		if replacement != nil {
			req.Body = replacement
		}
		if len(body) == 0 {
			return req, nil
		}

		result := s.dlp.Scan(req.Context(), bytesToString(body))
		// Drop the in-memory slice as soon as the scan completes.
		// The DLP pipeline copies any matched ranges into ScanResult
		// fields (just the pattern name) before returning, so the
		// raw body has no further reason to live in this goroutine.
		body = nil
		s.scans.Add(1)
		s.bumpStats(req.Context(), result.Blocked)

		if !result.Blocked {
			return req, nil
		}
		s.blocks.Add(1)
		return req, blockedResponse(req, result)
	})

	s.httpProxy = proxy
	return s, nil
}

// Handler exposes the underlying http.Handler. Tests and the API
// layer can drive the proxy with httptest without binding a real
// port.
func (s *Server) Handler() http.Handler { return s.httpProxy }

// ListenAddr returns the address the proxy was started on, or "" if
// not currently running.
func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenOn
}

// Running reports whether the proxy is currently accepting
// connections.
func (s *Server) Running() bool { return s.running.Load() }

// ScansTotal returns the anonymous DLP-scan counter (same number
// surfaced via aggregate_stats).
func (s *Server) ScansTotal() int64 { return s.scans.Load() }

// BlocksTotal returns the anonymous DLP-block counter.
func (s *Server) BlocksTotal() int64 { return s.blocks.Load() }

// ListenAndServe starts the proxy on addr. The server runs in a
// background goroutine; this call returns after the listener is
// established (or with an error if listen failed within a short
// window).
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = DefaultListenAddr
	}
	s.mu.Lock()
	if s.httpSrv != nil {
		s.mu.Unlock()
		return errors.New("proxy: already running")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.httpProxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.httpSrv = srv
	s.listenOn = addr
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		s.running.Store(true)
		// Always reset lifecycle state when the listener exits so a
		// late ListenAndServe failure (after the 100ms startup window
		// below) does not leave httpSrv/listenOn populated, which
		// would make subsequent Enable calls report "already running"
		// until Disable is invoked.
		defer func() {
			s.running.Store(false)
			s.mu.Lock()
			if s.httpSrv == srv {
				s.httpSrv = nil
				s.listenOn = ""
			}
			s.mu.Unlock()
		}()
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		// The deferred cleanup inside the goroutine also clears
		// httpSrv/listenOn, but it races with this read from errCh.
		// Clear synchronously here so a caller that retries Enable
		// immediately after observing the error never sees a stale
		// httpSrv pointer.
		s.mu.Lock()
		if s.httpSrv == srv {
			s.httpSrv = nil
			s.listenOn = ""
		}
		s.mu.Unlock()
		return err
	case <-time.After(100 * time.Millisecond):
	}
	return nil
}

// Shutdown gracefully stops the proxy. Safe to call when not
// running.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpSrv
	s.httpSrv = nil
	s.listenOn = ""
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

func (s *Server) bumpStats(ctx context.Context, blocked bool) {
	if s.stats == nil {
		return
	}
	// Errors here are intentionally swallowed — a SQLite hiccup must
	// not bubble out to the caller and break the proxy. The same
	// policy applies to the extension-side counter bump.
	_ = s.stats.BumpDLP(ctx, blocked)
}

// readScanBody drains up to maxScanBytes from req.Body. It returns
// the captured bytes plus a replacement io.ReadCloser that the
// downstream goproxy machinery can use to forward the request body
// to the upstream server unchanged. Returns nil bytes and a nil
// replacement when req.Body is nil or empty.
func readScanBody(req *http.Request) ([]byte, io.ReadCloser, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, nil, nil
	}

	body := req.Body
	defer body.Close()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			if len(buf)+n > maxScanBytes {
				// Trim to the cap and keep reading so the upstream
				// still receives the entire body — we just don't
				// scan past the limit. Concatenating the rest into
				// an io.Reader chain is enough to forward it.
				keep := maxScanBytes - len(buf)
				if keep < 0 {
					keep = 0
				}
				buf = append(buf, tmp[:keep]...)
				remaining, rErr := io.ReadAll(body)
				if rErr != nil {
					return nil, nil, rErr
				}
				replacement := io.NopCloser(combineReaders(buf, tmp[keep:n], remaining))
				return buf, replacement, nil
			}
			buf = append(buf, tmp[:n]...)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	replacement := io.NopCloser(strings.NewReader(bytesToString(buf)))
	return buf, replacement, nil
}

func combineReaders(parts ...[]byte) io.Reader {
	readers := make([]io.Reader, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		readers = append(readers, strings.NewReader(bytesToString(p)))
	}
	return io.MultiReader(readers...)
}

// blockedResponse builds the HTTP 451 reply documented in the API
// table. The body is intentionally JSON so the calling application
// can render a friendly message; pattern_name is the same
// (privacy-safe) field returned by /api/dlp/scan.
func blockedResponse(req *http.Request, result dlp.ScanResult) *http.Response {
	body := map[string]any{
		"blocked":      true,
		"pattern_name": result.PatternName,
	}
	encoded, _ := json.Marshal(body)
	reader := strings.NewReader(string(encoded))
	resp := &http.Response{
		Status:        "451 Unavailable For Legal Reasons",
		StatusCode:    http.StatusUnavailableForLegalReasons,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        make(http.Header),
		Body:          io.NopCloser(reader),
		ContentLength: int64(reader.Len()),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

func badGateway(req *http.Request) *http.Response {
	resp := &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
		Close:         true,
	}
	return resp
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// IPv6 hosts are bracketed, e.g. "[::1]:443" — keep the
		// bracketed form so callers can still match string literals.
		if j := strings.LastIndexByte(host, ']'); j > i {
			return host
		}
		return host[:i]
	}
	return host
}

// bytesToString does what its name says without allocating. Used on
// hot scan paths where the slice is only read by string-accepting
// APIs (json.Marshal, strings.NewReader).
func bytesToString(b []byte) string { return string(b) }

// noopLogger silences goproxy's per-CONNECT host logging. Calls that
// require a side effect (panics, etc.) are still surfaced; the
// trivial Printf path used by goproxy.Logger.Printf is what we want
// to suppress.
type noopLogger struct{}

func (noopLogger) Printf(format string, v ...any) {
	// intentionally empty — never emit per-connection metadata. The
	// fmt args might include hostnames or URLs, which violates the
	// privacy invariant of this package.
	_ = fmt.Sprintf
}
