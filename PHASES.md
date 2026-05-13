# ShieldNet Secure Edge — Implementation Phases

## Phase 1: DNS Blocking + Electron Tray (MVP)

**Covers:** Tiers 1, 3, 4 fully. Basic system tray presence. Zero-logging architecture.

### Deliverables
- [x] Go agent binary with embedded DNS resolver (`miekg/dns`)
- [x] SQLite database with `rulesets`, `category_policies`, `aggregate_stats` tables (no alert_events)
- [x] Policy engine: load rule files, match domains, return NXDOMAIN or forward
- [x] Anonymous counter system: increment `dns_blocks_total` on block, `dns_queries_total` on any query
- [x] Local HTTP API (`/api/policies`, `/api/stats`, `/api/status`)
- [x] Bundled rule files: `ai_chat_blocked.txt`, `phishing.txt`, `social.txt`, `news.txt`
- [x] Electron tray app (hidden window, tray icon only)
- [x] Tray context menu: Status, Open Settings, Quit
- [x] Settings page: per-category policy toggles (Block / Allow)
- [x] Status page: anonymous aggregate stats display (total blocks, uptime)
- [x] Platform DNS configuration scripts (macOS, Windows, Linux)
- [x] Basic installer for one platform (Linux `.deb` or macOS `.pkg`)

### Architecture
```
Go Agent:      DNS resolver + Policy engine + SQLite (config+counters) + HTTP API
Electron:      Tray icon + Settings BrowserWindow (on-demand)
Rules:         Bundled .txt files loaded at startup
Logging:       NONE for user access. Operational errors only to stderr.
```

---

## Phase 2: Browser Extension + Layered DLP Pipeline (Tier 2 Browser)

**Covers:** Tier 2 for browser-based AI tool usage. High-accuracy, privacy-preserving DLP.

### Deliverables

#### DLP Pipeline Core (Go agent)
- [x] Content type classifier (code/data/credentials/natural language heuristics)
- [x] Aho-Corasick automaton builder from pattern prefixes (e.g., `cloudflare/ahocorasick`)
- [x] Single-pass prefix scan returning candidate locations
- [x] Candidate-only regex validation
- [x] Hotword proximity checker (scan N chars around match for context keywords)
- [x] Shannon entropy calculator for secret/key candidates
- [x] Exclusion rule engine (dictionary + regex suppressions)
- [x] Multi-signal scoring system with configurable weights
- [x] Per-severity threshold configuration (`/api/dlp/config` endpoint)
- [x] `/api/dlp/scan` endpoint — receives content, runs pipeline, returns block/allow + pattern name

#### DLP Rule Files
- [x] `dlp_patterns.json` — extended format with `prefix`, `hotwords`, `hotword_window`, `entropy_min`, `severity`, `min_matches`
- [x] `dlp_exclusions.json` — dictionary and regex exclusions per pattern (or global)
- [x] Scoring thresholds config in `dlp_config` SQLite table

#### Browser Extension
- [x] Chrome extension (Manifest V3) with content scripts for Tier 2 AI domains
- [x] Firefox extension (WebExtensions) port
- [x] Safari Web Extension port (Xcode wrapper via `xcrun safari-web-extension-converter`; HTTP-only since Safari has no Native Messaging)
- [x] Native Messaging host configuration for extension ↔ agent communication
- [x] Extension intercepts: paste events, form submissions, fetch/XHR requests
- [x] Ephemeral block notification: shows pattern name only, no matched content, auto-dismisses

#### Integration
- [x] Anonymous DLP counters: `dlp_scans_total`, `dlp_blocks_total` (no content/domain stored)
- [x] Category toggles extended to three-state: Allow / Allow + Inspect / Block
- [x] Automaton rebuilt when rules update (triggered by `/api/rules/update`)

### Privacy Guarantees
- DLP scan content is received via HTTP POST, scanned in-memory, and response sent. The request body is garbage-collected. Never written to disk.
- Block notifications show "AWS Access Key pattern detected" — NOT the actual key or matched content.
- The extension stores no history of scanned pages or content.
- DLP scoring details (individual signal scores) are returned in the HTTP response for the notification, then discarded. Not persisted.

### DLP Pipeline Performance Budget

| Step | Time Budget | Memory Budget |
|------|------------|---------------|
| Content classification | < 10 μs | 0 (stack only) |
| Aho-Corasick scan | < 100 μs (typical paste) | ~100 KB (automaton, built once) |
| Regex validation (candidates) | < 500 μs | Negligible |
| Scoring (hotwords + entropy + exclusions) | < 200 μs | ~100 KB (exclusion hash sets) |
| **Total** | **< 1 ms** | **~200 KB** |

---

## Phase 3: Rule Updates + Multi-Platform Installers

**Covers:** Server-side rule distribution (including DLP patterns + exclusions). Production-ready packaging.

### Deliverables
- [x] Rule updater: polls `manifest.json` from configurable URL (default: GitHub Releases)
- [x] Manifest format: version, checksums (SHA256), file list (includes `dlp_patterns.json` + `dlp_exclusions.json`)
- [x] Delta updates: only download changed rule files
- [x] On rule update: rebuild Aho-Corasick automaton and exclusion hash sets
- [x] Electron auto-update via `electron-updater` (Squirrel on Windows, zip on macOS)
- [x] macOS installer: `.pkg` via `pkgbuild` + `productbuild`
- [x] Windows installer: MSI via WiX Toolset
- [x] Linux installers: `.deb` + `.rpm` via `nfpm`
- [x] CI/CD pipeline: GitHub Actions for cross-platform builds
- [ ] Code signing for macOS (Developer ID) and Windows (Authenticode) — deferred until signing certificates are provisioned

### Rule Server (Minimal)
```
Static file host serving:
  GET /manifest.json       → version + checksums
  GET /rules/{filename}    → individual rule files (domain lists + dlp_patterns.json + dlp_exclusions.json)
```

No processing, no auth, no user data. Can be a GitHub repo with tagged releases.
The rule server has NO knowledge of which devices downloaded which rules.

DLP accuracy improvements (new patterns, new exclusions) are distributed through this
mechanism without requiring an agent binary update.

---

## Phase 4: Optional MITM Proxy (Tier 2 Full Coverage)

**Covers:** Tier 2 for non-browser traffic (CLI tools, IDE plugins, API calls).

### Deliverables
- [x] Go MITM proxy (`elazarl/goproxy`) on `127.0.0.1:8443`
- [x] Per-device Root CA generation (`crypto/x509`, ECDSA P-256)
- [x] Platform-specific CA trust installation (automated scripts)
- [x] Platform-specific system proxy configuration
- [x] Selective inspection: only Tier 2 domains decrypt TLS; all other traffic tunneled (CONNECT)
- [x] DLP scanning of decrypted request bodies through the same layered pipeline (in-memory only)
- [x] "Enable Advanced DLP" setup wizard in Electron UI
- [x] Certificate pinning bypass list (known pinned apps)

### Privacy Notes
- The proxy decrypts TLS ONLY for Tier 2 domains. All other traffic passes through as opaque CONNECT tunnels.
- Decrypted content is scanned through the layered DLP pipeline in-memory and immediately discarded.
- No access log. No connection log. No request/response capture.
- The proxy increments `dlp_scans_total` and `dlp_blocks_total` counters only.

---

## Phase 5: Enterprise Features + Hardening

**Covers:** Features for managed deployments.

### Deliverables
- [x] Configuration profiles: JSON-based policy profiles downloadable from server
- [x] Tamper detection: alert if DNS settings or proxy are changed externally (ephemeral notification only)
- [x] Agent health heartbeat to optional central server (sends ONLY: "agent alive, version X" — no access data)
- [x] Export aggregate stats as JSON (counters only, no access data)
- [x] Custom rule file support (admin adds company-specific domains)
- [x] Custom DLP patterns and exclusions via local override files
- [x] DLP scoring threshold tuning UI in Electron settings
- [x] Allowlist/blocklist override UI
- [x] Performance profiling and optimization pass
- [x] Documentation: admin guide, user guide, rule contribution guide, DLP pattern authoring guide (`docs/`)
- [x] Privacy audit: internal code review + automated SQLite-sweep test of zero-logging guarantees (`agent/internal/store/privacy_test.go`); third-party external audit deferred to post-1.0 release.
- [x] DLP accuracy audit: measure false positive/negative rates against test corpus (`agent/internal/dlp/accuracy_test.go`, FP < 10%, FN < 5%; current measurement 0/0)
- [x] Accessibility audit of Electron UI (`docs/accessibility.md`)
- [ ] Code signing of release artifacts — deferred until Apple Developer ID, Windows code-signing certificate, and Linux package-signing GPG key are provisioned.

### Enterprise Privacy Boundary
Even in enterprise mode, the agent NEVER sends access logs, domain lists, DLP match details,
or user activity to a central server. The heartbeat endpoint receives only: agent version, OS
type, and aggregate counters. An enterprise admin can see "Device X has blocked 142 requests
total" but cannot see WHAT was blocked or WHAT content triggered DLP.

---

## Phase 6: Hardening, Ecosystem Expansion & Community

**Covers:** Pattern coverage, engine performance, browser-extension UX, platform
hardening, accessibility, test rigor, and the community files an open-source
project needs.

### DLP pattern expansion
- [x] Terraform provider credentials (Terraform Cloud, Spacelift, env0, Scalr)
- [x] Container registry credentials (Harbor, Quay, ECR, GCR)
- [x] Secret-manager response detection (AWS Secrets Manager, Azure Key Vault, GCP)
- [x] OAuth2 / OIDC token patterns (Auth0, Keycloak, Okta)
- [x] IaC hardcoded secrets (Ansible vault, Puppet eyaml, Chef data bags)
- [x] Package manager tokens (RubyGems, Composer, NuGet, Hex.pm, Pub.dev, CocoaPods)

### Engine and performance
- [x] Content-size adaptive scanning (`large_content_threshold` config)
- [x] Pattern category grouping (`category` field, disable-by-category)
- [x] Short-lived scan-result LRU cache (5s TTL, content-hash keyed, never persisted)
- [x] Concurrent regex evaluation for >10 KiB payloads, with a `pipeline_bench_test.go` benchmark

### Browser extension
- [x] Drag-and-drop interceptor for AI-tool textareas
- [x] Dynamic content-script registration so Tier-2 host updates apply without an extension reload
- [x] Extension options page (status, rule version, verbose-toast toggle)
- [x] Optional clipboard scanning, off by default, per-host toggle

### Platform hardening
- [x] Agent self-update via GitHub Releases with SHA-256 + Ed25519 signature verification
- [x] Graceful shutdown that waits for in-flight DNS queries and DLP scans
- [x] `/api/status` enriched with Go runtime stats, goroutine count, rule mtimes, and pattern count
- [x] Configurable token-bucket rate limit on `/api/dlp/scan`

### Electron UI
- [x] Dark mode tuned for WCAG 2.1 AA contrast against the dark surface palette
- [x] Read-only Rules page surfacing rule version, pattern count, and on-disk mtimes
- [x] First-run setup wizard
- [x] In-memory recent-blocks list on the Status page (last 10, never persisted)

### Testing and quality
- [x] End-to-end DNS test that drives the real resolver with a stock client
- [x] Playwright-based extension integration harness (out-of-band install)
- [x] Go native fuzzing of `Pipeline.Scan`
- [x] CI coverage profile + 80% floor on `agent/internal/dlp/`

### Documentation and community
- [x] `CONTRIBUTING.md`
- [x] `CHANGELOG.md` following Keep a Changelog
- [x] `.github/ISSUE_TEMPLATE/` and `PULL_REQUEST_TEMPLATE.md`
- [x] `SECURITY.md` with responsible disclosure process

---

## Difficulty Assessment

| Component | Difficulty | Notes |
|-----------|-----------|-------|
| DNS blocking agent | Easy | ~500 lines Go |
| Rule file format + updater | Easy | One-entry-per-line text files; simple HTTP GET |
| SQLite config store (no logging) | Easy | Simpler than logged version — fewer tables, less I/O |
| Anonymous counter system | Easy | Atomic integer increments, periodic flush |
| Electron tray (minimal) | Easy | ~300 lines main process |
| Content type classifier | Easy | ~100 lines of string heuristics |
| Aho-Corasick prefix scanner | Easy | Library handles it; ~50 lines integration |
| Hotword proximity checker | Easy | Substring scan within window; ~80 lines |
| Shannon entropy calculator | Easy | ~20 lines of arithmetic |
| Exclusion rule engine | Easy-Medium | Hash set + regex; ~200 lines |
| Multi-signal scoring system | Medium | Configurable weights, threshold logic; ~300 lines |
| Browser extension (Tier 2) | Medium | ~2000 lines TypeScript |
| Settings UI | Medium | Per-category three-state toggles + anonymous stats (no Reports page) |
| Local MITM proxy | Medium | ~1000 lines Go (goproxy handles TLS) |
| Cross-platform installers | Medium | Three separate pipelines |
| DLP pattern tuning | Hard | Ongoing quality problem — but layered pipeline + community exclusions significantly reduce false positives compared to flat regex |
| Preventing user bypass | Hard | Inherent limitation without MDM |
| Keeping AI tool list current | Hard | Community maintenance IS the product |
| Privacy audit | Hard | Needs thorough review of all code paths to ensure no accidental logging |
