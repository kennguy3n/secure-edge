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
func LoadFromFile(path string) (*Profile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("profile: load path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %q: %w", path, err)
	}
	return Parse(raw)
}

// LoadFromURL fetches a profile JSON document from rawURL via HTTPS GET
// and validates it. client may be nil; the default client uses
// DefaultHTTPTimeout.
//
// The URL must use the https:// scheme — plain HTTP profile fetches
// are rejected because a profile is a load-bearing security document
// (it can flip the agent into managed mode, lock the device, and
// rewrite category policies) and must not be subject to in-flight
// modification. Profile hosts whose DNS resolution maps to loopback or
// RFC1918 / link-local / unique-local addresses are also rejected to
// keep this code path from being used as an SSRF primitive against
// internal services on the same machine or LAN.
func LoadFromURL(ctx context.Context, client *http.Client, rawURL string) (*Profile, error) {
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
		client = &http.Client{Timeout: DefaultHTTPTimeout}
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
	return Parse(raw)
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
