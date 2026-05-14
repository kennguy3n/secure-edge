//go:build !darwin && !windows

package tamper

import "context"

// platformProxyCheckImpl is the fallback for Linux / BSD / any other
// non-darwin, non-windows target. We trust the standard
// http_proxy/https_proxy environment variables here — the agent's
// installer sets them in /etc/environment and refreshes them in tests
// by re-reading the variables every check. Replacing the previous
// pair of per-platform stubs with a single impl removes the
// switch-on-runtime.GOOS in proxy_check.go entirely; the build tag on
// this file (and on proxy_darwin.go / proxy_windows.go) is what makes
// the dispatch.
func platformProxyCheckImpl(_ context.Context, expected string) (bool, error) {
	return proxyCheckEnv(expected), nil
}
