// Per-device Root CA + on-the-fly leaf certificate issuance.
//
// On first run, NewCA generates a self-signed ECDSA P-256 Root CA and
// writes it to disk (cert + key, mode 0600). Subsequent runs load the
// existing files instead of regenerating, so the user only has to
// install the CA in the system trust store once.
//
// IssueLeaf signs a leaf certificate for the requested host using the
// Root CA. Leaves are cached in memory by hostname and evicted after
// leafTTL (default 1h) — a long-lived agent that proxies many domains
// would otherwise grow its cert pool unbounded.
//
// Privacy invariant: hostnames passed to IssueLeaf are kept in process
// memory only. They are never logged, persisted, or emitted with
// counters; the only persisted state from this file is the singleton
// Root CA at the configured path.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// leafTTL is how long a generated leaf certificate stays in the
	// in-memory cache before IssueLeaf re-signs a fresh one. The leaf
	// itself is signed with a longer validity (leafValidity) so the
	// TLS client never sees an expired cert mid-connection.
	leafTTL = 1 * time.Hour

	// rootValidity is how long the generated Root CA is valid for.
	// Long enough that operator key rotation is the lifecycle event,
	// not certificate expiry.
	rootValidity = 10 * 365 * 24 * time.Hour

	// leafValidity is the X.509 validity period stamped onto each
	// generated leaf. Browsers reject leaves with absurdly long
	// validity, so this is kept short (7 days) — the TTL above
	// guarantees re-issuance every hour anyway.
	leafValidity = 7 * 24 * time.Hour
)

// CA is the per-device root certificate authority and its in-memory
// leaf-cert cache. Methods are safe for concurrent use.
type CA struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootDER  []byte // raw bytes of rootCert (= rootCert.Raw)

	certPath string
	keyPath  string

	mu    sync.Mutex
	cache map[string]cachedLeaf
}

type cachedLeaf struct {
	cert     tls.Certificate
	issuedAt time.Time
}

// NewCA loads the CA at (certPath, keyPath) if both files exist, or
// generates a fresh self-signed Root CA and writes it to disk.
//
// Parent directories of certPath / keyPath are created with 0700
// permissions if they don't already exist. The private key is written
// with 0600 permissions; the public cert with 0644.
func NewCA(certPath, keyPath string) (*CA, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("proxy: ca cert/key paths required")
	}

	if fileExists(certPath) && fileExists(keyPath) {
		return loadCA(certPath, keyPath)
	}

	cert, key, err := generateRoot()
	if err != nil {
		return nil, err
	}

	if err := writeCA(certPath, keyPath, cert, key); err != nil {
		return nil, err
	}

	// writeCA writes the key with 0600, but a hostile umask or a
	// stale file from a previous install with weaker permissions
	// can still leave the file world-readable. Re-stat after the
	// write so a misconfigured target directory fails closed
	// instead of producing a usable CA that the next loadCA call
	// would also refuse — symmetric with the check at the top of
	// loadCA above.
	if err := checkKeyPermissions(keyPath); err != nil {
		return nil, err
	}

	return &CA{
		rootCert: cert,
		rootKey:  key,
		rootDER:  cert.Raw,
		certPath: certPath,
		keyPath:  keyPath,
		cache:    make(map[string]cachedLeaf),
	}, nil
}

// CertPath returns the disk location of the Root CA public cert.
func (c *CA) CertPath() string { return c.certPath }

// KeyPath returns the disk location of the Root CA private key.
func (c *CA) KeyPath() string { return c.keyPath }

// Certificate returns the parsed Root CA certificate. Callers must
// not mutate the returned value.
func (c *CA) Certificate() *x509.Certificate { return c.rootCert }

// TLSCertificate returns the Root CA as a tls.Certificate suitable
// for handing to goproxy as its signing CA.
func (c *CA) TLSCertificate() tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{c.rootDER},
		PrivateKey:  c.rootKey,
		Leaf:        c.rootCert,
	}
}

// IssueLeaf returns a leaf certificate for host, signed by the Root
// CA. Leaves are cached for leafTTL; the second call for the same
// host within the TTL returns the cached value without re-signing.
func (c *CA) IssueLeaf(host string) (tls.Certificate, error) {
	if host == "" {
		return tls.Certificate{}, errors.New("proxy: empty host")
	}

	now := time.Now()

	c.mu.Lock()
	if entry, ok := c.cache[host]; ok && now.Sub(entry.issuedAt) < leafTTL {
		c.mu.Unlock()
		return entry.cert, nil
	}
	c.mu.Unlock()

	leaf, err := c.signLeaf(host, now)
	if err != nil {
		return tls.Certificate{}, err
	}

	c.mu.Lock()
	c.cache[host] = cachedLeaf{cert: leaf, issuedAt: now}
	// Evict any other entries that have aged out. Bounded sweep keeps
	// the cache from growing without limit on a long-running agent.
	for h, e := range c.cache {
		if now.Sub(e.issuedAt) >= leafTTL {
			delete(c.cache, h)
		}
	}
	c.mu.Unlock()

	return leaf, nil
}

// CacheSize returns the number of currently cached leaf certificates.
// Test-only helper; the production code does not depend on this.
func (c *CA) CacheSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

func (c *CA) signLeaf(host string, now time.Time) (tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("proxy: leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &leafKey.PublicKey, c.rootKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("proxy: sign leaf: %w", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("proxy: parse leaf: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der, c.rootDER},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}, nil
}

func generateRoot() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: root key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Secure Edge Local CA",
			Organization: []string{"Secure Edge"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: self-sign root: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy: parse root: %w", err)
	}
	return cert, key, nil
}

// checkKeyPermissions confirms the on-disk Root CA private key is
// readable only by its owner. Anything broader (group, world) lets a
// second user on the same machine read the key and forge TLS leaves
// for every Tier-2 domain the agent proxies — the exact attack the
// per-device CA exists to constrain. The check is a no-op on Windows
// because POSIX-style mode bits are not the access-control mechanism
// there; the WriteFile call still hands the file out with 0600
// equivalent ACLs, and the platform itself is what we trust for
// per-user isolation.
func checkKeyPermissions(keyPath string) error {
	fi, err := os.Stat(keyPath)
	if err != nil {
		return fmt.Errorf("proxy: stat ca key: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	mode := fi.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Errorf("proxy: ca key %s has mode %04o; must be 0600 or stricter (group/other bits must be zero)", keyPath, mode)
	}
	return nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	// The on-disk key is the entire trust root for the proxy's
	// TLS interception path; refuse to load it when a wider mode
	// has crept in (e.g. an operator chmod'd the directory to
	// fix a permission bug and accidentally weakened the key).
	// loadCA is the choke point for every subsequent leaf
	// signature so this single check covers the proxy server,
	// the controller's Enable() retries, and any unit-test path
	// that reuses an existing CA on disk.
	if err := checkKeyPermissions(keyPath); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("proxy: read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("proxy: read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("proxy: ca cert: no PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse ca cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("proxy: ca key: no PEM EC PRIVATE KEY block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse ca key: %w", err)
	}

	return &CA{
		rootCert: cert,
		rootKey:  key,
		rootDER:  cert.Raw,
		certPath: certPath,
		keyPath:  keyPath,
		cache:    make(map[string]cachedLeaf),
	}, nil
}

func writeCA(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	for _, p := range []string{certPath, keyPath} {
		dir := filepath.Dir(p)
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("proxy: mkdir %s: %w", dir, err)
		}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("proxy: write ca cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("proxy: marshal ca key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("proxy: write ca key: %w", err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("proxy: random serial: %w", err)
	}
	return n, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
