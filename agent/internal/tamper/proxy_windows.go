//go:build windows

package tamper

import (
	"context"
	"os/exec"
	"strings"
)

// platformProxyCheckImpl shells out to `netsh winhttp show proxy` to
// inspect the system-wide WinHTTP proxy. The agent installer
// configures both this and the per-user IE proxy.
func platformProxyCheckImpl(ctx context.Context, expected string) (bool, error) {
	cmd := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), expected), nil
}
