package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manifest is the on-disk + over-the-wire description of a rule
// bundle. The agent fetches one of these from RuleUpdateURL on every
// poll and compares it against the locally-installed version.
//
// Signature is the hex-encoded Ed25519 signature over the JSON
// serialisation of the body — i.e. the manifest with the
// `signature` field omitted (see CanonicalForSigning). It's
// optional: when an operator has not configured a public key, the
// updater falls back to per-file SHA-256 checks only. The field is
// always emitted on the wire so signed and unsigned manifests share
// one struct.
type Manifest struct {
	Version   string         `json:"version"`
	Files     []ManifestFile `json:"files"`
	Signature string         `json:"signature,omitempty"`
}

// ManifestFile is a single rule file. Either an explicit URL or a path
// relative to the manifest's URL is accepted. SHA256 is required so the
// updater can verify each file before atomically replacing the local copy.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url,omitempty"`
}

// VersionStore is the subset of *store.Store the Updater needs.
// Keeping it as an interface lets updater_test.go drive the updater
// with an in-memory implementation.
type VersionStore interface {
	CurrentRuleVersion(ctx context.Context) (string, error)
	AppendRuleVersion(ctx context.Context, version string) error
}

// ReloadFunc is called after one or more rule files have been updated.
// Implementations typically call engine.Reload and pipeline.Rebuild.
type ReloadFunc func(ctx context.Context) error

// Options configures a new Updater.
type Options struct {
	// ManifestURL is the absolute HTTP(S) URL of manifest.json. An
	// empty value disables the updater.
	ManifestURL string

	// PollInterval defaults to 6 hours when zero.
	PollInterval time.Duration

	// RulesDir is the directory rule files are downloaded into. Each
	// ManifestFile.Name is resolved as RulesDir/Name; absolute names
	// are rejected to keep us inside the rules directory.
	RulesDir string

	// HTTPClient is the client used for manifest + file fetches. If
	// nil, a default *http.Client with a 30s timeout is used.
	HTTPClient *http.Client

	// Store is used to record the current manifest version. May be nil
	// when version persistence is not required (e.g. tests).
	Store VersionStore

	// Reload is invoked after any file was replaced. May be nil.
	Reload ReloadFunc

	// PublicKey is the Ed25519 public key the updater verifies the
	// manifest signature against. When nil, the updater accepts
	// unsigned manifests (logging a one-time warning on first
	// fetch) and falls back to per-file SHA-256 checks only. When
	// non-nil, an unsigned or mis-signed manifest is rejected
	// outright before any file is downloaded.
	PublicKey ed25519.PublicKey

	// Now returns the current time; injected for tests. Defaults to time.Now.
	Now func() time.Time
}

// DefaultPollInterval is the polling cadence used when Options.PollInterval is zero.
const DefaultPollInterval = 6 * time.Hour

// Updater periodically fetches a manifest and applies delta updates to
// the locally-installed rule files. Safe for concurrent use.
type Updater struct {
	opts Options

	mu                   sync.RWMutex
	currentVersion       string
	lastCheck            time.Time
	nextCheck            time.Time
	unsignedWarned       bool
	signedButNoKeyWarned bool
	// tier2Hosts is the resolved set of Tier-2 (DLP-inspected) hosts
	// that the engine is currently treating as paste / fetch targets.
	// The extension's dynamic-hosts updater reads this list from
	// GET /api/rules/status so its content_scripts.matches can stay
	// in sync with the agent's resolved tier without a manifest push.
	tier2Hosts []string
}

// New constructs an Updater. Returns an error when ManifestURL is empty
// or RulesDir is empty / not a directory.
func New(opts Options) (*Updater, error) {
	if strings.TrimSpace(opts.ManifestURL) == "" {
		return nil, errors.New("updater: ManifestURL is required")
	}
	if strings.TrimSpace(opts.RulesDir) == "" {
		return nil, errors.New("updater: RulesDir is required")
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Updater{opts: opts}, nil
}

// Status is a snapshot of the updater's bookkeeping fields. Returned by
// the GET /api/rules/status handler.
//
// CurrentVersion / RuleVersion: both fields carry the same value. The
// extension's dynamic-hosts updater reads `rule_version` from this
// endpoint; the original Electron tray reads `current_version`. Adding
// `RuleVersion` instead of renaming preserves both consumers.
//
// Tier2Hosts: the resolved set of Tier-2 (DLP-inspected) hosts. The
// extension uses this to keep its content_scripts.matches in sync with
// the agent's resolved tier without a manifest push.
type Status struct {
	CurrentVersion string    `json:"current_version"`
	RuleVersion    string    `json:"rule_version"`
	LastCheck      time.Time `json:"last_check"`
	NextCheck      time.Time `json:"next_check"`
	UpdateURL      string    `json:"update_url"`
	Tier2Hosts     []string  `json:"tier2_hosts"`
}

// Status returns a snapshot of the updater's bookkeeping fields.
func (u *Updater) Status() Status {
	u.mu.RLock()
	defer u.mu.RUnlock()
	// Defensive copy so a caller can't mutate the updater's internal
	// slice through the returned Status value. make([]string, 0)
	// returns a non-nil empty slice when u.tier2Hosts is nil, so the
	// JSON encoder renders it as `[]` (which the extension's
	// `body?.tier2_hosts ?? []` shortcut depends on — see
	// extension/src/background/dynamic-hosts.ts and the contract test
	// TestStatus_JSONShape below).
	hosts := make([]string, len(u.tier2Hosts))
	copy(hosts, u.tier2Hosts)
	return Status{
		CurrentVersion: u.currentVersion,
		RuleVersion:    u.currentVersion,
		LastCheck:      u.lastCheck,
		NextCheck:      u.nextCheck,
		UpdateURL:      u.opts.ManifestURL,
		Tier2Hosts:     hosts,
	}
}

// SetTier2Hosts records the resolved set of Tier-2 (DLP-inspected)
// hosts so it can be surfaced through GET /api/rules/status to the
// extension. Called by the agent's main.go on startup and whenever a
// rule reload / profile update changes the tier mapping.
//
// hosts is copied — callers may mutate the input slice after this
// returns. A nil or zero-length input is stored as nil internally
// (saves one allocation when no hosts are configured); the
// non-nil-empty-slice guarantee that the extension and TestStatus_JSONShape
// rely on is enforced on the read side via make([]string, len(...))
// in Status(), not here.
func (u *Updater) SetTier2Hosts(hosts []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(hosts) == 0 {
		u.tier2Hosts = nil
		return
	}
	cp := make([]string, len(hosts))
	copy(cp, hosts)
	u.tier2Hosts = cp
}

// Result describes the outcome of one update cycle.
type Result struct {
	Updated         bool   `json:"updated"`
	Version         string `json:"version"`
	FilesDownloaded int    `json:"files_downloaded"`
}

// Start runs CheckNow on ctx's goroutine immediately, then again on
// every PollInterval until ctx is cancelled.
func (u *Updater) Start(ctx context.Context) {
	// One eager check at startup so a manifest update that landed
	// while the agent was down is applied without waiting a full
	// poll interval.
	if _, err := u.CheckNow(ctx); err != nil {
		// Log to stderr — we don't want to wedge agent startup on
		// transient network errors.
		fmt.Fprintf(os.Stderr, "rule updater: initial check failed: %v\n", err)
	}
	ticker := time.NewTicker(u.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := u.CheckNow(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "rule updater: check failed: %v\n", err)
			}
		}
	}
}

// CheckNow runs one update cycle. It is safe to call concurrently —
// the lock around the bookkeeping fields prevents torn reads from
// Status, and the filesystem writes use os.Rename for atomic
// replacement so a concurrent reader of the rule files always sees a
// consistent version.
func (u *Updater) CheckNow(ctx context.Context) (Result, error) {
	now := u.opts.Now()
	u.mu.Lock()
	u.lastCheck = now
	u.nextCheck = now.Add(u.opts.PollInterval)
	current := u.currentVersion
	if current == "" && u.opts.Store != nil {
		// Prefer the persisted value on first call after restart.
		if v, err := u.opts.Store.CurrentRuleVersion(ctx); err == nil {
			u.currentVersion = v
			current = v
		}
	}
	u.mu.Unlock()

	manifest, err := u.fetchManifest(ctx)
	if err != nil {
		return Result{}, err
	}

	count, err := u.applyManifest(ctx, manifest)
	if err != nil {
		return Result{}, err
	}

	versionChanged := manifest.Version != current

	// Reload the live engines *before* recording the new version in
	// memory or in the store. If the reload fails — bad pattern in
	// the new file, syntax error in a rules list, etc — `current`
	// stays pointing at the old version so the next poll will retry
	// the reload (versionChanged will still be true even though all
	// downloaded files match SHAs on disk). Persisting the new
	// version up front would mark the cycle "successful", leave the
	// engine running on the previous rule set, and skip the reload
	// indefinitely (until the manifest version bumps again).
	needsReload := (count > 0 || versionChanged) && u.opts.Reload != nil
	if needsReload {
		if err := u.opts.Reload(ctx); err != nil {
			return Result{}, fmt.Errorf("reload: %w", err)
		}
	}

	u.mu.Lock()
	u.currentVersion = manifest.Version
	u.mu.Unlock()

	if versionChanged && u.opts.Store != nil {
		if err := u.opts.Store.AppendRuleVersion(ctx, manifest.Version); err != nil {
			return Result{}, fmt.Errorf("persist version: %w", err)
		}
	}

	return Result{
		Updated:         count > 0 || versionChanged,
		Version:         manifest.Version,
		FilesDownloaded: count,
	}, nil
}

// fetchManifest issues GET ManifestURL and decodes the response.
func (u *Updater) fetchManifest(ctx context.Context) (Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.opts.ManifestURL, nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest request: %w", err)
	}
	resp, err := u.opts.HTTPClient.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("manifest fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest read: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest decode: %w", err)
	}
	if strings.TrimSpace(m.Version) == "" {
		return Manifest{}, errors.New("manifest: empty version")
	}
	if len(m.Files) == 0 {
		return Manifest{}, errors.New("manifest: no files")
	}
	if err := u.verifyManifestSignature(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// verifyManifestSignature enforces the configured trust posture on
// the freshly-fetched manifest.
//
//   - When a PublicKey is configured: the manifest MUST carry a
//     well-formed Ed25519 signature over its canonical body and
//     that signature must verify. Either an empty signature or a
//     verification failure is rejected before any file is
//     downloaded — an unverified manifest could replace every rule
//     on disk with attacker-chosen content.
//   - When no PublicKey is configured: the manifest is accepted
//     even without a signature. We log one warning per Updater
//     instance on the first such fetch so an operator who forgot
//     to wire the key sees a breadcrumb in the agent logs without
//     us spamming the log on every poll.
func (u *Updater) verifyManifestSignature(m Manifest) error {
	if len(u.opts.PublicKey) == 0 {
		if strings.TrimSpace(m.Signature) == "" {
			u.mu.Lock()
			warned := u.unsignedWarned
			u.unsignedWarned = true
			u.mu.Unlock()
			if !warned {
				log.Printf("rules: rule_update_public_key not configured " +
					"and manifest is unsigned; falling back to per-file " +
					"SHA-256 checks only (configure a public key to enable " +
					"end-to-end manifest verification)")
			}
			return nil
		}
		// Signed-but-no-key configured: the upstream is signing
		// manifests but this agent has not been told what to verify
		// against, so verification is skipped on the trust path the
		// publisher already set up. Without this log an operator who
		// deployed signatures to most agents but forgot the key on
		// some would see no breadcrumb that those agents are still
		// running unverified. One warning per Updater instance.
		u.mu.Lock()
		warned := u.signedButNoKeyWarned
		u.signedButNoKeyWarned = true
		u.mu.Unlock()
		if !warned {
			log.Printf("rules: manifest carries a signature but " +
				"rule_update_public_key is not configured on this " +
				"agent; signature verification is being skipped " +
				"(configure the matching public key to enable " +
				"verification)")
		}
		return nil
	}
	if strings.TrimSpace(m.Signature) == "" {
		return errors.New("manifest: signature required (rule_update_public_key configured)")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("manifest: invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest: invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	body, err := CanonicalForSigning(m)
	if err != nil {
		return fmt.Errorf("manifest: canonicalize: %w", err)
	}
	if !ed25519.Verify(u.opts.PublicKey, body, sig) {
		return errors.New("manifest: signature verification failed")
	}
	return nil
}

// CanonicalForSigning returns the byte sequence that the manifest
// signer signs over and that the updater verifies. The signature
// field itself is omitted from the canonical body — otherwise the
// signer would have to fixed-point its own input. Field order is
// fixed by Go's encoding/json (declaration order on the struct) so
// a signer and verifier built from the same Manifest type agree
// without an explicit "canonicalisation" library.
func CanonicalForSigning(m Manifest) ([]byte, error) {
	// Note on the shallow copy: stripped.Files shares its backing
	// array with m.Files. Safe here because json.Marshal only
	// reads the slice and CanonicalForSigning is never called on
	// a Manifest that is being mutated concurrently (the only
	// writers are deserialisation in fetchManifest and the signer
	// tool, both of which finish before this is called). A deep
	// copy would defeat the point of the function being cheap.
	stripped := Manifest{Version: m.Version, Files: m.Files}
	return json.Marshal(stripped)
}

// applyManifest iterates manifest.Files, compares each against the
// locally-installed file's SHA256, downloads any mismatches, and
// atomically replaces the local copy. Returns the number of files that
// were actually downloaded + replaced.
func (u *Updater) applyManifest(ctx context.Context, m Manifest) (int, error) {
	if err := os.MkdirAll(u.opts.RulesDir, 0o755); err != nil {
		return 0, fmt.Errorf("rules dir: %w", err)
	}

	count := 0
	for _, f := range m.Files {
		// Defence in depth: reject any path traversal in the manifest.
		if f.Name == "" || strings.ContainsAny(f.Name, "/\\") || f.Name == ".." || strings.HasPrefix(f.Name, ".") {
			return count, fmt.Errorf("rule %q: invalid name", f.Name)
		}
		if len(f.SHA256) != 64 {
			return count, fmt.Errorf("rule %q: invalid sha256", f.Name)
		}

		dest := filepath.Join(u.opts.RulesDir, f.Name)
		existing, err := fileSHA256(dest)
		if err == nil && strings.EqualFold(existing, f.SHA256) {
			continue // delta: file unchanged, skip download
		}

		fileURL, err := u.resolveFileURL(f)
		if err != nil {
			return count, fmt.Errorf("rule %q: %w", f.Name, err)
		}

		if err := u.downloadAndReplace(ctx, fileURL, dest, f.SHA256); err != nil {
			return count, fmt.Errorf("rule %q: %w", f.Name, err)
		}
		count++
	}
	return count, nil
}

// resolveFileURL returns the absolute URL for a ManifestFile. An
// explicit URL wins; otherwise the file's URL is interpreted as
// "manifest.json's parent directory + file Name", which lets a host
// serve a flat directory of rules without listing each URL.
func (u *Updater) resolveFileURL(f ManifestFile) (string, error) {
	if f.URL != "" {
		return f.URL, nil
	}
	base, err := url.Parse(u.opts.ManifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest URL: %w", err)
	}
	ref, err := base.Parse(f.Name)
	if err != nil {
		return "", fmt.Errorf("resolve rule URL: %w", err)
	}
	return ref.String(), nil
}

// downloadAndReplace fetches src, writes it to a temp file in the
// destination's directory, verifies its SHA256 matches wantHex, and
// only then renames the temp file over the destination. A mismatched
// or short download leaves the existing file untouched.
func (u *Updater) downloadAndReplace(ctx context.Context, src, dst, wantHex string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return fmt.Errorf("download request: %w", err)
	}
	resp, err := u.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".rule-*.tmp")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op when Rename succeeds

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 16*1024*1024)); err != nil {
		tmp.Close()
		return fmt.Errorf("download copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("temp close: %w", err)
	}

	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantHex) {
		return fmt.Errorf("sha256 mismatch: want %s got %s", wantHex, gotHex)
	}

	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// fileSHA256 returns the lower-case hex SHA256 of the file at path, or
// "" + os.ErrNotExist when the file is missing.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
