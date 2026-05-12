# ShieldNet Secure Edge — Progress Tracker

> Last updated: 2026-05-12

## Overall Status

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: DNS Blocking + Electron Tray | Not Started | 0% |
| Phase 2: Browser Extension + Layered DLP Pipeline | Not Started | 0% |
| Phase 3: Rule Updates + Installers | Not Started | 0% |
| Phase 4: MITM Proxy (Optional) | Not Started | 0% |
| Phase 5: Enterprise Features | Not Started | 0% |

## Phase 1 Detailed Breakdown

### Go Agent Core
- [ ] Project scaffolding (`cmd/agent/main.go`, `internal/` structure)
- [ ] Configuration loader (YAML config for upstream DNS, ports, rule paths)
- [ ] DNS resolver implementation (`miekg/dns`, listen on 127.0.0.1:53)
- [ ] Rule file parser (one-domain-per-line `.txt` files)
- [ ] In-memory domain lookup (hash map)
- [ ] Policy engine (category → action mapping)
- [ ] SQLite database setup (`modernc.org/sqlite`, WAL mode)
- [ ] Database migrations (rulesets, category_policies, aggregate_stats, dlp_config — NO alert_events)
- [ ] Anonymous counter system (atomic in-memory counters, periodic SQLite flush)
- [ ] Local HTTP API server (net/http)
- [ ] API: `GET /api/status` — agent health, uptime
- [ ] API: `GET /api/policies` — list category policies
- [ ] API: `PUT /api/policies/:category` — update policy action
- [ ] API: `GET /api/stats` — anonymous aggregate counters
- [ ] API: `POST /api/stats/reset` — reset counters
- [ ] Privacy review: confirm no domain/IP/URL is written to disk anywhere

### Electron Tray App
- [ ] Electron project setup with electron-builder
- [ ] Main process: create tray icon (all platforms)
- [ ] Tray context menu: Status, Open Settings, Quit
- [ ] Settings BrowserWindow (created on-demand, destroyed on close)
- [ ] Settings page: list categories with policy toggles
- [ ] Status page: anonymous aggregate stats display (total blocks, uptime)
- [ ] Status indicator in tray icon (green = running, red = error)
- [ ] IPC to Go agent via localhost HTTP

### Bundled Rules
- [ ] `rules/ai_chat_blocked.txt` — blocked AI chatbot domains
- [ ] `rules/ai_code_blocked.txt` — blocked AI code assistant domains
- [ ] `rules/ai_allowed.txt` — enterprise-approved AI endpoints
- [ ] `rules/ai_chat_dlp.txt` — AI tools requiring DLP inspection
- [ ] `rules/phishing.txt` — phishing domains
- [ ] `rules/social.txt` — social media domains
- [ ] `rules/news.txt` — news domains
- [ ] `rules/manifest.json` — version and file list

### Platform Integration
- [ ] macOS: DNS configuration script
- [ ] macOS: LaunchDaemon plist
- [ ] Windows: DNS configuration script (netsh)
- [ ] Windows: Service registration
- [ ] Linux: resolv.conf / systemd-resolved configuration
- [ ] Linux: systemd unit file

### Packaging
- [ ] Linux `.deb` package (nfpm)
- [ ] Basic CI: build + test on GitHub Actions

## Phase 2 Detailed Breakdown

### DLP Pipeline Core
- [ ] Content type classifier (code/data/credentials/natural language)
- [ ] Aho-Corasick automaton builder from pattern prefixes
- [ ] Single-pass prefix scan returning candidate locations
- [ ] Candidate-only regex validation
- [ ] Hotword proximity checker (configurable window size)
- [ ] Shannon entropy calculator
- [ ] Exclusion rule engine (dictionary exact match + regex + proximity)
- [ ] Multi-signal scoring aggregator
- [ ] Per-severity threshold engine (configurable via API + SQLite)
- [ ] `/api/dlp/scan` endpoint
- [ ] `/api/dlp/config` GET/PUT endpoints
- [ ] Automaton rebuild on rule file change
- [ ] Unit tests: each pipeline step independently
- [ ] Integration test: full pipeline with known patterns + known false positives

### DLP Rule Files
- [ ] `rules/dlp_patterns.json` — extended pattern format (prefix, hotwords, hotword_window, entropy_min, severity, min_matches)
- [ ] Seed patterns: AWS Access Key, AWS Secret Key, GitHub PAT, GitHub OAuth Token, Slack Token, Google API Key, Stripe Secret Key, Private Key Block, JWT, Generic API Key, Email Addresses (bulk), Phone Numbers (bulk), SSN, Credit Card (Luhn-validated)
- [ ] `rules/dlp_exclusions.json` — exclusion rules per pattern + global dictionary
- [ ] Seed exclusions: `example.com`, `test.com`, `localhost`, `AKIAIOSFODNN7EXAMPLE`, `your-api-key`, `<your_token_here>`, `CHANGEME`, `placeholder`, `xxx`, `dummy`, `sample`
- [ ] Schema validation for `dlp_patterns.json` and `dlp_exclusions.json` at load time

### Browser Extension
- [ ] Chrome extension scaffolding (Manifest V3)
- [ ] Firefox extension scaffolding (WebExtensions)
- [ ] Content script: paste event interception
- [ ] Content script: form submit interception
- [ ] Content script: fetch/XMLHttpRequest interception
- [ ] Native Messaging host manifest (per-platform install paths)
- [ ] Background service worker: bridge to Native Messaging
- [ ] Domain allowlist: only inject on Tier 2 AI tool domains
- [ ] Ephemeral block notification UI (pattern name only, auto-dismiss)
- [ ] User override prompt ("Send anyway" with timeout) — optional, configurable per deployment
- [ ] Extension store packaging: Chrome `.crx`, Firefox `.xpi`

### Integration
- [ ] Category toggles in Settings UI extended to three-state (Allow / Allow + Inspect / Block)
- [ ] DLP threshold tuning UI in Settings (per-severity sliders)
- [ ] Aggregate counters: `dlp_scans_total`, `dlp_blocks_total` flushed periodically
- [ ] End-to-end test: paste of test AWS key → blocked → counter incremented → no content on disk

### Privacy Verification
- [ ] Audit: trace DLP scan content through code paths, confirm no `os.WriteFile`/`db.Exec` writes content
- [ ] Audit: extension storage (`chrome.storage`) contains no scanned content
- [ ] Audit: notification text contains pattern name only, no matched content
- [ ] Audit: log statements scrubbed of user-traffic data

## Phase 3 Detailed Breakdown

### Rule Distribution
- [ ] Manifest schema (`manifest.json`: version, list of files, SHA256 checksums)
- [ ] Rule updater goroutine (configurable interval, default 6h)
- [ ] Delta download: skip files whose checksum matches local
- [ ] Atomic rule swap (download to tmp, validate, then rename)
- [ ] Trigger Aho-Corasick automaton rebuild and exclusion set rebuild on update
- [ ] Trigger DNS in-memory blocklist rebuild on update
- [ ] `POST /api/rules/update` endpoint for manual trigger
- [ ] Manifest signing (Ed25519 detached signature) — optional, future-proofing
- [ ] GitHub Release as default rule source

### Installers
- [ ] macOS `.pkg` (pkgbuild + productbuild)
- [ ] macOS: notarization workflow (Developer ID + altool)
- [ ] Windows `.msi` (WiX Toolset)
- [ ] Windows: Authenticode code signing in CI
- [ ] Linux `.deb` (nfpm) — completed in Phase 1, polish here
- [ ] Linux `.rpm` (nfpm)
- [ ] Electron auto-update (`electron-updater`) on macOS + Windows

### CI/CD
- [ ] GitHub Actions: cross-platform build matrix (macOS, Windows, Linux)
- [ ] GitHub Actions: release workflow (tag push → build all platforms → attach artifacts)
- [ ] Smoke tests on each platform installer

## Phase 4 Detailed Breakdown

### Local MITM Proxy
- [ ] `goproxy` integration on `127.0.0.1:8443`
- [ ] Per-device Root CA generation at first run
- [ ] Selective TLS decryption: only Tier 2 domains; everything else opaque CONNECT
- [ ] Wire DLP pipeline into proxy request handler (in-memory scan)
- [ ] Certificate pinning bypass list (apps that pin and would break)

### Platform CA Trust + Proxy Config
- [ ] macOS: `security add-trusted-cert` automation + System Keychain install
- [ ] macOS: `networksetup -setsecurewebproxy` automation
- [ ] Windows: `certutil -addstore Root` automation
- [ ] Windows: Internet Options proxy registry config
- [ ] Linux: `/usr/local/share/ca-certificates/` + `update-ca-certificates`
- [ ] Linux: per-app proxy hints (Firefox, Chrome) since system proxy varies

### Setup Wizard
- [ ] "Enable Advanced DLP" wizard in Electron settings page
- [ ] Step 1: explain trade-offs (TLS decryption for Tier 2 only)
- [ ] Step 2: trigger CA install (admin prompt)
- [ ] Step 3: trigger proxy config
- [ ] Step 4: validation ping through proxy
- [ ] Uninstall path: remove CA, remove proxy config

### Privacy Verification
- [ ] Confirm proxy logs nothing per request
- [ ] Confirm CONNECT tunnels for non-Tier-2 traffic are not inspected
- [ ] Confirm decrypted content paths terminate at DLP scan + GC

## Phase 5 Detailed Breakdown

### Enterprise Configuration
- [ ] Config profile schema (JSON) — categories, DLP thresholds, custom domains, custom patterns
- [ ] `POST /api/profile/apply` endpoint (admin-signed profile)
- [ ] Optional heartbeat to central server (version + counters only — no access data)
- [ ] Aggregate stats JSON export endpoint
- [ ] Custom rule file support (admin-supplied `.txt` lists)
- [ ] Custom DLP pattern/exclusion local overrides
- [ ] DLP threshold tuning UI in Settings

### Tamper Detection
- [ ] Detect DNS settings reverted externally → ephemeral notification + counter
- [ ] Detect proxy settings reverted externally → ephemeral notification + counter
- [ ] Detect CA removed → ephemeral notification + counter

### Hardening
- [ ] Performance profiling pass (pprof, allocation review)
- [ ] DLP accuracy benchmark suite (true positive + false positive corpus)
- [ ] Privacy audit checklist + third-party review
- [ ] Accessibility audit of Electron settings UI
- [ ] Documentation: admin guide, user guide, rule contribution guide, DLP pattern authoring guide
- [ ] Security disclosure policy (SECURITY.md)

## Risk Tracker

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| DLP false positive rate erodes user trust | High | High | Layered pipeline (content classification + hotwords + entropy + exclusions + scoring) + community-updatable exclusions |
| Users bypass agent (change DNS, disable extension) | Medium | Medium | Tamper detection counter; MDM for managed deployments; tray-icon health indicator |
| AI tool domain list staleness | High | Medium | Community PRs to rule files; rule distribution decoupled from binary releases |
| Naive privacy "logging" creeps back in via debug/error paths | Medium | High | Audit checklist in each phase; lint rule banning `log.Printf` with user-traffic data; privacy review gate before each release |
| Aho-Corasick automaton growth from many patterns | Low | Low | Cap pattern count; profile memory at rule load; reject overly large rule sets |
| MITM proxy breaks pinned apps | High | Medium | Pinning bypass list; per-app opt-in; proxy is opt-in feature in Phase 4 |
| Cross-platform installer drift | Medium | Medium | CI matrix; smoke tests per platform; codified signing workflows |
