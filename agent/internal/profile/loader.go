package profile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxProfileBytes caps the profile document size at 1 MiB. A profile
// is a small JSON document — anything larger is almost certainly a
// misconfigured rule file or a hostile response that should not be
// silently buffered into memory.
const maxProfileBytes = 1 << 20 // 1 MiB

// DefaultHTTPTimeout is the timeout used by LoadFromURL when callers
// don't supply their own *http.Client.
const DefaultHTTPTimeout = 30 * time.Second

// LoadFromFile reads a profile JSON document from disk and validates it.
//
// A non-nil v enforces the operator's configured trust posture on
// the parsed profile before it is returned: see Verifier.Verify for
// the trust matrix. Pass nil to skip verification entirely (callers
// that intentionally don't want signature enforcement, e.g. unit
// tests that build their own Profile in memory). A non-nil Verifier
// with no public key configured is the operator-friendly
// backwards-compatible posture (warn once + accept).
func LoadFromFile(path string, v *Verifier) (*Profile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("profile: load path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %q: %w", path, err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if v != nil {
		if err := v.Verify(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// LoadFromURL fetches a profile JSON document from rawURL via HTTPS GET
// and validates it. client may be nil; the default client uses
// DefaultHTTPTimeout.
//
// A non-nil v enforces the operator's configured trust posture on
// the parsed profile after the body has been read and validated:
// see Verifier.Verify for the trust matrix. Pass nil to skip
// verification entirely (callers that intentionally don't want
// signature enforcement). A non-nil Verifier with no public key
// configured is the operator-friendly backwards-compatible posture
// (warn once + accept).
//
// The URL must use the https:// scheme — plain HTTP profile fetches
// are rejected because a profile is a load-bearing security document
// (it can flip the agent into managed mode, lock the device, and
// rewrite category policies) and must not be subject to in-flight
// modification. Profile hosts whose DNS resolution maps to loopback or
// RFC1918 / link-local / unique-local addresses are also rejected to
// keep this code path from being used as an SSRF primitive against
// internal services on the same machine or LAN.
func LoadFromURL(ctx context.Context, client *http.Client, rawURL string, v *Verifier) (*Profile, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("profile: url is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("profile: parse url %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("profile: url scheme must be https")
	}
	if err := hostCheck(ctx, u.Hostname()); err != nil {
		return nil, err
	}

	if client == nil {
		client = &http.Client{
			Timeout:       DefaultHTTPTimeout,
			CheckRedirect: redirectGuard(ctx),
			Transport:     pinnedDialTransport(),
		}
	} else {
		// Defensive: a caller-supplied client may have neither its
		// own redirect hook nor its own Transport. The two guard
		// invariants are independent — we patch each one only if
		// the caller hasn't already configured it.
		clone := *client
		if clone.CheckRedirect == nil {
			// Defensive: a caller-supplied client without its own
			// redirect hook is the common case (config.Load, tests,
			// etc.). Without this the Go default follows up to 10
			// hops with no per-hop validation — see redirectGuard
			// for the bypass it closes. We don't overwrite a
			// caller's own CheckRedirect because that would clobber
			// custom policies (e.g. tests that intentionally
			// short-circuit redirects); the contract is "this
			// loader guards redirects unless you bring your own
			// policy".
			clone.CheckRedirect = redirectGuard(ctx)
		}
		if clone.Transport == nil {
			clone.Transport = pinnedDialTransport()
		}
		client = &clone
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("profile: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("profile: GET %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("profile: GET %q: status %d", rawURL, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("profile: read body: %w", err)
	}
	if len(raw) > maxProfileBytes {
		return nil, fmt.Errorf("profile: response exceeds %d bytes", maxProfileBytes)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if v != nil {
		if err := v.Verify(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// hostCheck is the SSRF guard used by LoadFromURL. Exposed as a
// package-level var so the test in this package can install a
// loopback-allowing fake without spinning up real DNS or a
// non-loopback HTTPS server. Production code never assigns to it.
var hostCheck = checkProfileHost

// profileResolver is the host-to-IP resolver used by checkProfileHost.
// It is var-typed so tests can swap in a deterministic fake without
// having to mock DNS for the whole package.
var profileResolver = func(ctx context.Context, host string) ([]string, error) {
	r := net.Resolver{}
	return r.LookupHost(ctx, host)
}

// checkProfileHost resolves host and rejects it if any of the resolved
// addresses fall inside a private / loopback / link-local / unique-local
// range. The check is applied before the HTTPS request is issued so a
// hostile profile_url cannot be used to coerce the agent into talking
// to internal services on the same machine or LAN (SSRF).
//
// Rejecting host=="" is intentional: a profile URL without a hostname
// is structurally invalid for an HTTPS fetch.
func checkProfileHost(ctx context.Context, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("profile: url host is empty")
	}
	// Reject literal IPs that are private before we even try to
	// resolve them — saves a DNS lookup on the fast-fail path.
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return errors.New("profile: private/loopback IP not allowed")
		}
		return nil
	}
	addrs, err := profileResolver(ctx, host)
	if err != nil {
		return fmt.Errorf("profile: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("profile: resolve %q: no addresses", host)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return errors.New("profile: private/loopback IP not allowed")
		}
	}
	return nil
}

// redirectGuard returns a CheckRedirect function that re-runs the
// SSRF guard on every hop and rejects scheme downgrades. The default
// http.Client follows up to 10 redirects with no per-hop validation,
// so an attacker-controlled HTTPS origin could 302 to
// http://169.254.169.254/… (cloud IMDS) or any RFC1918 address and
// the agent would still fire the request — exactly what the initial
// hostCheck call was meant to prevent.
//
// We use the LoadFromURL caller's ctx (rather than req.Context()) so
// the DNS lookup for the redirect target is bounded by the same
// deadline that bounds the overall fetch.
func redirectGuard(ctx context.Context) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		// Cap the chain length defensively. Go's default is 10 but we
		// don't trust attacker-controlled redirects to ever be deep.
		if len(via) >= 5 {
			return fmt.Errorf("profile: redirect chain too long (%d hops)", len(via))
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("profile: redirect to non-https scheme %q is not allowed", req.URL.Scheme)
		}
		if err := hostCheck(ctx, req.URL.Hostname()); err != nil {
			return err
		}
		return nil
	}
}

// pinnedDialTransport returns an *http.Transport whose DialContext
// performs DNS resolution itself, validates every returned IP against
// isBlockedIP, and then dials a validated IP directly. The original
// req.URL.Host is preserved on the wire (which keeps the Host header
// and TLS SNI pointing at the configured profile URL), but the
// underlying TCP connection is forced onto an address that has passed
// the SSRF blocklist.
//
// This closes the time-of-check / time-of-use gap that the existing
// hostCheck() alone leaves open: hostCheck resolves once at the start
// of LoadFromURL, then Go's default Transport resolves *again* when
// it actually dials, and a hostile DNS server can return a different
// (loopback / RFC1918) address on the second lookup. By doing the
// dial-time resolution inside one DialContext callback we both
// validate and dial the same address, which a DNS-rebinding attack
// cannot bypass.
//
// dialTimeout / TLS handshake / response-header timeouts mirror
// http.DefaultTransport's relevant values so a stuck profile host
// can't hang the boot indefinitely.
func pinnedDialTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		// Conservative connection-pool sizing. The agent never
		// loads more than one profile URL concurrently so a deep
		// pool would be wasted; we still allow keep-alive so a
		// future poll loop can reuse the connection cheaply.
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("profile: split host:port %q: %w", addr, err)
			}
			// Literal IP fast path: still apply the blocklist
			// but skip the DNS round trip. Matches the
			// checkProfileHost short-circuit.
			if ip := net.ParseIP(host); ip != nil {
				if isBlockedIP(ip) {
					return nil, errors.New("profile: private/loopback IP not allowed")
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			addrs, err := profileResolver(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("profile: resolve %q: %w", host, err)
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("profile: resolve %q: no addresses", host)
			}
			// Pin the first non-blocked address. Iterating in
			// the resolver's returned order matches what the
			// default transport would do and lets operators
			// steer resolution through /etc/hosts when needed
			// for staging; any single blocked address fails
			// the whole dial closed.
			for _, a := range addrs {
				ip := net.ParseIP(a)
				if ip == nil {
					continue
				}
				if isBlockedIP(ip) {
					return nil, errors.New("profile: private/loopback IP not allowed")
				}
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if derr == nil {
					return conn, nil
				}
				// Try next address; surface the last error
				// if every option dials-fails.
				err = derr
			}
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("profile: resolve %q: no usable addresses", host)
		},
	}
}

// isBlockedIP reports whether ip falls inside one of the address
// ranges a profile_url is not allowed to resolve into. The list mirrors
// the SSRF-guard cheat-sheet entries:
//
//   - IPv4 loopback (127.0.0.0/8) and IPv6 loopback (::1)
//   - RFC1918 (10/8, 172.16/12, 192.168/16)
//   - IPv4 link-local (169.254.0.0/16) and IPv6 link-local (fe80::/10)
//   - Unique-local IPv6 (fc00::/7)
//   - The zero address (0.0.0.0 / ::) and multicast / unspecified
//
// net.IP's helpers cover loopback / link-local / multicast / unspecified
// directly; the RFC1918 ranges and unique-local block are explicit.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// IsPrivate (Go 1.17+) covers RFC1918 and fc00::/7 for us.
	if ip.IsPrivate() {
		return true
	}
	return false
}
