//go:build !darwin && !windows

package tamper

import "context"

// proxyCheckDarwin and proxyCheckWindows are stubs on non-darwin /
// non-windows builds so platformProxyCheck's switch compiles. They
// fall back to the env-var heuristic.
func proxyCheckDarwin(_ context.Context, expected string) (bool, error) {
	return proxyCheckEnv(expected), nil
}

func proxyCheckWindows(_ context.Context, expected string) (bool, error) {
	return proxyCheckEnv(expected), nil
}
