package proxy

import (
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCA_GenerateSelfSignedRoot(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := NewCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	root := ca.Certificate()
	if root == nil {
		t.Fatal("root cert is nil")
	}
	if !root.IsCA {
		t.Error("root is not marked as CA")
	}
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("root missing KeyUsageCertSign")
	}
	if root.Subject.CommonName == "" {
		t.Error("root CN is empty")
	}

	// Root must verify against itself (self-signed).
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := root.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("self-verify root: %v", err)
	}

	// On-disk private key must not be world-readable.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("ca key mode = %v, want owner-only", info.Mode().Perm())
	}
}

func TestCA_ReuseExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	first, err := NewCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCA (first): %v", err)
	}
	second, err := NewCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("NewCA (second): %v", err)
	}

	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Fatalf("second NewCA regenerated the root (serials differ)")
	}
	if !first.Certificate().Equal(second.Certificate()) {
		t.Error("reloaded root differs from on-disk root")
	}
	// And the loaded key must actually be ECDSA (the one we wrote).
	if _, ok := any(second.rootKey).(*ecdsa.PrivateKey); !ok {
		t.Fatalf("reloaded key is not *ecdsa.PrivateKey")
	}
}

func TestCA_IssueLeafSignedByRoot(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	leaf, err := ca.IssueLeaf("example.com")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatal("leaf has nil Leaf field")
	}

	if leaf.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("leaf CN = %q", leaf.Leaf.Subject.CommonName)
	}
	if !containsString(leaf.Leaf.DNSNames, "example.com") {
		t.Errorf("leaf DNSNames = %v", leaf.Leaf.DNSNames)
	}

	// Leaf must validate against the Root CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("verify leaf: %v", err)
	}
}

func TestCA_IssueLeafCachesWithinTTL(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	a, err := ca.IssueLeaf("foo.test")
	if err != nil {
		t.Fatalf("IssueLeaf #1: %v", err)
	}
	b, err := ca.IssueLeaf("foo.test")
	if err != nil {
		t.Fatalf("IssueLeaf #2: %v", err)
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) != 0 {
		t.Fatalf("cache miss: second call re-signed (serials differ)")
	}
	if ca.CacheSize() != 1 {
		t.Errorf("cache size = %d, want 1", ca.CacheSize())
	}
}

func TestCA_IssueLeafReSignsAfterTTL(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Pre-populate the cache with an entry far older than leafTTL.
	leaf, err := ca.signLeaf("aged.test", time.Now().Add(-2*leafTTL))
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	ca.mu.Lock()
	ca.cache["aged.test"] = cachedLeaf{
		cert:     leaf,
		issuedAt: time.Now().Add(-2 * leafTTL),
	}
	ca.mu.Unlock()

	fresh, err := ca.IssueLeaf("aged.test")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if fresh.Leaf.SerialNumber.Cmp(leaf.Leaf.SerialNumber) == 0 {
		t.Fatalf("expected re-sign after TTL but got cached cert")
	}
}

func TestCA_IssueLeafConcurrent(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	const goroutines = 32
	const perGoroutine = 4

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			host := "concurrent" + string(rune('A'+(i%8))) + ".test"
			for j := 0; j < perGoroutine; j++ {
				if _, err := ca.IssueLeaf(host); err != nil {
					t.Errorf("IssueLeaf: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	if got := ca.CacheSize(); got > 8 {
		t.Errorf("cache size = %d, want <= 8 (one per distinct host)", got)
	}
}

func TestCA_RejectsEmptyPaths(t *testing.T) {
	if _, err := NewCA("", "/tmp/k"); err == nil {
		t.Error("expected error for empty cert path")
	}
	if _, err := NewCA("/tmp/c", ""); err == nil {
		t.Error("expected error for empty key path")
	}
}

func TestCA_IssueLeafRejectsEmptyHost(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if _, err := ca.IssueLeaf(""); err == nil {
		t.Error("expected error for empty host")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestCA_LoadRejectsWorldReadableKey confirms loadCA refuses to read
// a Root CA key whose mode bits include group / world access. A
// permissive on-disk key is the entire attack surface for proxy
// trust forgery; the unit test pins the failure path so an edit
// that accidentally drops the os.Stat check (or relaxes the bitmask)
// re-introduces the vulnerability with a visible regression.
//
// Mode bits are not a meaningful access-control mechanism on Windows
// (NTFS ACLs are), so the check itself is a no-op there and the test
// would be flaky against a tightly-mocked filesystem; we skip on
// windows for the same reason checkKeyPermissions does.
func TestCA_LoadRejectsWorldReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("CA key permission check is a no-op on Windows")
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Bootstrap a real CA on disk with the canonical 0600 key.
	if _, err := NewCA(certPath, keyPath); err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Widen the key mode to world-readable and try to reload.
	// loadCA must refuse — every subsequent leaf signed by this
	// key would otherwise be forgeable by any user who can read
	// the file.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := loadCA(certPath, keyPath)
	if err == nil {
		t.Fatal("loadCA accepted a world-readable key; expected error")
	}
	if !strings.Contains(err.Error(), "must be 0600 or stricter") {
		t.Errorf("error message = %q; expected the documented permission diagnostic", err.Error())
	}
}

// TestCA_ReuseAfterChmodFailsLoad is the operator-facing version of
// the previous test: NewCA on a path that already has a wider-mode
// key on disk must also refuse, even though it would otherwise hit
// the loadCA fast path. The check lives at the top of loadCA, which
// NewCA calls when both files already exist.
func TestCA_ReuseAfterChmodFailsLoad(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("CA key permission check is a no-op on Windows")
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Bootstrap, then widen.
	if _, err := NewCA(certPath, keyPath); err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := NewCA(certPath, keyPath); err == nil {
		t.Fatal("second NewCA accepted a group-readable key; expected error")
	}
}
