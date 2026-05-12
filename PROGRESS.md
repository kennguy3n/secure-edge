# ShieldNet Secure Edge — Progress Tracker

> Last updated: 2026-05-12

## Overall Status

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: DNS Blocking + Electron Tray | Complete | 100% |
| Phase 2: Browser Extension + Layered DLP Pipeline | In Progress | ~60% |
| Phase 3: Rule Updates + Installers | Not Started | 0% |
| Phase 4: MITM Proxy (Optional) | Not Started | 0% |
| Phase 5: Enterprise Features | Not Started | 0% |

## Phase 1 Detailed Breakdown

### Go Agent Core
- [x] Project scaffolding (`cmd/agent/main.go`, `internal/` structure)
- [x] Configuration loader (YAML config for upstream DNS, ports, rule paths)
- [x] DNS resolver implementation (`miekg/dns`, listen on 127.0.0.1:53)
- [x] Rule file parser (one-domain-per-line `.txt` files)
- [x] In-memory domain lookup (hash map)
- [x] Policy engine (category → action mapping)
- [x] SQLite database setup (`modernc.org/sqlite`, WAL mode)
- [x] Database migrations (rulesets, category_policies, aggregate_stats, dlp_config — NO alert_events)
- [x] Anonymous counter system (atomic in-memory counters, periodic SQLite flush)
- [x] Local HTTP API server (net/http)
- [x] API: `GET /api/status` — agent health, uptime
- [x] API: `GET /api/policies` — list category policies
- [x] API: `PUT /api/policies/:category` — update policy action
- [x] API: `GET /api/stats` — anonymous aggregate counters
- [x] API: `POST /api/stats/reset` — reset counters
- [x] Privacy review: confirm no domain/IP/URL is written to disk anywhere

### Electron Tray App
- [x] Electron project setup with electron-builder
- [x] Main process: create tray icon (all platforms)
- [x] Tray context menu: Status, Open Settings, Quit
- [x] Settings BrowserWindow (created on-demand, destroyed on close)
- [x] Settings page: list categories with policy toggles
- [x] Status page: anonymous aggregate stats display (total blocks, uptime)
- [x] Status indicator in tray icon (green = running, red = error)
- [x] IPC to Go agent via localhost HTTP

### Bundled Rules
- [x] `rules/ai_chat_blocked.txt` — blocked AI chatbot domains
- [x] `rules/ai_code_blocked.txt` — blocked AI code assistant domains
- [x] `rules/ai_allowed.txt` — enterprise-approved AI endpoints
- [x] `rules/ai_chat_dlp.txt` — AI tools requiring DLP inspection
- [x] `rules/phishing.txt` — phishing domains
- [x] `rules/social.txt` — social media domains
- [x] `rules/news.txt` — news domains
- [x] `rules/manifest.json` — version and file list

### Platform Integration
- [x] macOS: DNS configuration script
- [x] macOS: LaunchDaemon plist
- [x] Windows: DNS configuration script (netsh)
- [x] Windows: Service registration
- [x] Linux: resolv.conf / systemd-resolved configuration
- [x] Linux: systemd unit file

### Packaging
- [x] Linux `.deb` package (nfpm)
- [x] Basic CI: build + test on GitHub Actions

## Phase 2 Detailed Breakdown

### DLP Pipeline Core
- [x] Content type classifier (code/data/credentials/natural language)
- [x] Aho-Corasick automaton builder from pattern prefixes
- [x] Single-pass prefix scan returning candidate locations
- [x] Candidate-only regex validation
- [x] Hotword proximity checker (configurable window size)
- [x] Shannon entropy calculator
- [x] Exclusion rule engine (dictionary exact match + regex + proximity)
- [x] Multi-signal scoring aggregator
- [x] Per-severity threshold engine (configurable via API + SQLite)
- [x] `/api/dlp/scan` endpoint
- [x] `/api/dlp/config` GET/PUT endpoints
- [x] Automaton rebuild on rule file change
- [x] Unit tests: each pipeline step independently
- [x] Integration test: full pipeline with known patterns + known false positives

### DLP Rule Files
- [x] `rules/dlp_patterns.json` — extended format with prefix, hotwords, hotword_window, entropy_min, severity, score_weight, min_matches
- [x] `rules/dlp_exclusions.json` — dictionary and regex exclusions per pattern and global
- [x] Default patterns: AWS keys, GitHub tokens, GitLab tokens, Google API keys, Slack tokens, private keys (PEM), email addresses (bulk), phone numbers (bulk), SSN, credit card numbers, source code heuristics, internal URL patterns
- [x] Default exclusions: test/example/placeholder/dummy strings, @example.com emails, 000-00-0000 SSN, known public keys

### Browser Extension
- [x] Chrome extension project setup (Manifest V3)
- [x] Content script: intercept paste events on Tier 2 AI tool domains
- [ ] Content script: intercept form submission events
- [ ] Content script: intercept fetch/XHR requests before send
- [ ] Native Messaging host manifest (macOS, Windows, Linux paths)
- [ ] Native Messaging communication with Go agent
- [x] Ephemeral block notification UI (in-page banner, auto-dismiss, shows pattern name only)
- [ ] Firefox WebExtensions port
- [x] Extension popup: connection status to Go agent

### Integration
- [x] Anonymous DLP counters: `dlp_scans_total`, `dlp_blocks_total` added to `aggregate_stats`
- [ ] Category toggles extended to three-state: Allow / Allow + Inspect / Block
- [x] Aho-Corasick automaton rebuild triggered on rule file change
- [x] Privacy review: confirm no scan content, no matched text, no domain is written to disk

## Phase 3 Detailed Breakdown

### Rule Updater
- [ ] HTTP client to poll `manifest.json` from configurable URL
- [ ] Manifest parser: version comparison, SHA256 checksum verification
- [ ] Delta download: only fetch files with changed checksums
- [ ] Atomic file replacement (write temp file, rename)
- [ ] Trigger policy engine + DLP automaton rebuild after rule update
- [ ] Configurable poll interval (default: 6 hours)
- [ ] Manual trigger via `POST /api/rules/update`
- [ ] API: `GET /api/rules/status` — last update time, current version, next check

### Multi-Platform Installers
- [ ] macOS: `.pkg` installer via `pkgbuild` + `productbuild`
- [ ] macOS: post-install script (set DNS, register LaunchDaemon, install Electron tray)
- [ ] macOS: uninstaller script (restore DNS, remove LaunchDaemon, remove files)
- [ ] Windows: MSI installer via WiX Toolset
- [ ] Windows: post-install actions (set DNS via netsh, register service, install tray)
- [ ] Windows: uninstaller (restore DNS, remove service, remove files)
- [ ] Linux: `.deb` package via `nfpm`
- [ ] Linux: `.rpm` package via `nfpm`
- [ ] Linux: post-install script (configure systemd-resolved/resolv.conf, enable systemd unit)
- [ ] Linux: uninstaller (restore DNS config, disable service, remove files)

### CI/CD
- [ ] GitHub Actions workflow: build Go agent (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
- [ ] GitHub Actions workflow: build Electron tray app (macOS, Windows, Linux)
- [ ] GitHub Actions workflow: build browser extensions (Chrome .zip, Firefox .xpi)
- [ ] GitHub Actions workflow: run Go unit tests
- [ ] GitHub Actions workflow: create GitHub Release with all artifacts
- [ ] Electron auto-update via `electron-updater`
- [ ] Code signing: macOS Developer ID (when available)
- [ ] Code signing: Windows Authenticode (when available)

## Phase 4 Detailed Breakdown

### MITM Proxy
- [ ] `elazarl/goproxy` integration on `127.0.0.1:8443`
- [ ] Per-device Root CA generation (`crypto/x509`, RSA 2048 or ECDSA P-256)
- [ ] Dynamic certificate generation for Tier 2 domains
- [ ] CONNECT tunnel passthrough for non-Tier-2 domains (no decryption)
- [ ] Request body extraction from decrypted HTTPS for DLP pipeline
- [ ] DLP pipeline integration (same layered pipeline as browser extension path)
- [ ] Response forwarding after DLP pass
- [ ] Block response page for DLP failures

### CA Trust Installation Scripts
- [ ] macOS: `security add-trusted-cert` automation
- [ ] Windows: `certutil -addstore` automation
- [ ] Linux: copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates`

### System Proxy Configuration Scripts
- [ ] macOS: `networksetup -setsecurewebproxy` for active interfaces
- [ ] Windows: Registry `ProxyServer` + `ProxyEnable` keys
- [ ] Linux: GNOME proxy settings via `gsettings` + KDE via `kwriteconfig5`
- [ ] Environment variable approach: `HTTP_PROXY`/`HTTPS_PROXY` for CLI tools

### Electron UI
- [ ] "Advanced DLP" settings section
- [ ] "Enable Full DLP Protection" wizard (generate CA → install CA → configure proxy)
- [ ] Proxy status indicator in tray menu
- [ ] Certificate pinning bypass list management UI
- [ ] API: `POST /api/proxy/enable` — generate CA, install, configure
- [ ] API: `POST /api/proxy/disable` — remove proxy config, optionally remove CA
- [ ] API: `GET /api/proxy/status` — running, CA installed, proxy configured

## Phase 5 Detailed Breakdown

### Enterprise Configuration
- [ ] JSON-based policy profile format (categories, actions, DLP thresholds, rule update URL)
- [ ] Profile download from server URL
- [ ] Profile application on agent startup
- [ ] Profile lock (prevent local override when managed)
- [ ] API: `GET /api/profile` — current profile
- [ ] API: `POST /api/profile/import` — import profile from URL or file

### Tamper Detection
- [ ] Periodic check: is OS DNS still pointing to 127.0.0.1?
- [ ] Periodic check: is system proxy still configured (if Phase 4 enabled)?
- [ ] Ephemeral tray notification on tamper detection (no persistent log)
- [ ] Tamper counter in `aggregate_stats`

### Agent Heartbeat (Optional)
- [ ] Configurable heartbeat URL (disabled by default)
- [ ] Heartbeat payload: agent version, OS type, aggregate counters ONLY
- [ ] Heartbeat interval: configurable (default: 1 hour)
- [ ] NO access data, NO domain data, NO DLP match details in heartbeat

### Admin Tools
- [ ] Export aggregate stats as JSON
- [ ] Custom rule file support (local override directory)
- [ ] Custom DLP patterns/exclusions override files
- [ ] DLP scoring threshold tuning UI in Electron settings
- [ ] Allowlist/blocklist override UI (add/remove individual domains)

### Quality & Documentation
- [ ] Performance profiling: memory usage, CPU usage, DNS latency benchmarks
- [ ] DLP accuracy benchmarks: false positive/negative rates against test corpus
- [ ] Privacy audit: code review of every disk write path to verify zero access logging
- [ ] Admin guide (installation, configuration, profile management)
- [ ] User guide (what the tray icon means, how to report false positives)
- [ ] Rule contribution guide (how to add domains, DLP patterns, exclusions)
- [ ] DLP pattern authoring guide (hotwords, entropy thresholds, scoring weights)
- [ ] Accessibility audit of Electron UI

## Repository Structure (Planned)

```
secure-edge/
├── README.md
├── PROPOSAL.md
├── ARCHITECTURE.md
├── PHASES.md
├── PROGRESS.md
├── LICENSE
├── agent/                          # Go backend
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go
│   ├── internal/
│   │   ├── config/                 # YAML configuration loader
│   │   ├── dns/                    # Embedded DNS resolver
│   │   ├── policy/                 # Policy engine
│   │   ├── store/                  # SQLite: policies + counters (NO access logs)
│   │   ├── api/                    # HTTP API handlers
│   │   ├── rules/                  # Rule file parser and updater
│   │   ├── stats/                  # Anonymous aggregate counter system
│   │   └── dlp/                    # Layered DLP pipeline
│   │       ├── classifier.go       # Content type classification
│   │       ├── ahocorasick.go      # Prefix automaton builder + scanner
│   │       ├── regex.go            # Candidate regex validation
│   │       ├── hotword.go          # Hotword proximity checker
│   │       ├── entropy.go          # Shannon entropy calculator
│   │       ├── exclusion.go        # Exclusion rule engine
│   │       ├── scorer.go           # Multi-signal scoring aggregator
│   │       └── pipeline.go         # Pipeline orchestrator
│   ├── go.mod
│   └── go.sum
├── electron/                       # Electron tray app
│   ├── main.ts
│   ├── preload.ts
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Settings.tsx        # Policy toggles + DLP config
│   │   │   └── Status.tsx          # Agent health + anonymous stats
│   │   ├── components/
│   │   │   ├── CategoryToggle.tsx
│   │   │   ├── StatsCard.tsx
│   │   │   └── DLPThresholdSlider.tsx
│   │   └── api/
│   │       └── agent.ts
│   ├── package.json
│   └── electron-builder.yml
├── extension/                      # Browser extension (Phase 2)
│   ├── manifest.json
│   ├── src/
│   │   ├── content/                # Content scripts for AI tool pages
│   │   ├── background/             # Service worker
│   │   └── popup/                  # Extension popup UI
│   ├── package.json
│   └── tsconfig.json
├── rules/                          # Bundled rule files
│   ├── manifest.json
│   ├── ai_chat_blocked.txt
│   ├── ai_chat_dlp.txt
│   ├── ai_code_blocked.txt
│   ├── ai_allowed.txt
│   ├── phishing.txt
│   ├── social.txt
│   ├── news.txt
│   ├── dlp_patterns.json
│   └── dlp_exclusions.json
├── scripts/                        # Platform setup scripts
│   ├── macos/
│   │   ├── configure-dns.sh
│   │   ├── install-ca.sh
│   │   ├── configure-proxy.sh
│   │   └── com.secureedge.agent.plist
│   ├── windows/
│   │   ├── configure-dns.ps1
│   │   ├── install-ca.ps1
│   │   └── configure-proxy.ps1
│   └── linux/
│       ├── configure-dns.sh
│       ├── install-ca.sh
│       ├── configure-proxy.sh
│       └── secure-edge.service
└── .github/
    └── workflows/
        ├── build-agent.yml
        ├── build-electron.yml
        ├── build-extension.yml
        └── release.yml
```

## Changelog

### 2026-05-12
- Repository initialized with MIT license
- Project documentation created (README, PROPOSAL, ARCHITECTURE, PHASES, PROGRESS)
- Privacy-first design: zero access logging, anonymous aggregate counters only
- Layered DLP pipeline design: content classification → Aho-Corasick prefix scan → regex validation → hotword/entropy/exclusion scoring
- Phase 1 implementation landed: Go agent (config, rules parser + hash-map lookup, policy engine,
  SQLite store in WAL mode with `rulesets`, `category_policies`, `aggregate_stats`, `rule_versions`,
  `dlp_config` tables — no access/alert tables), atomic anonymous counter system with periodic
  SQLite flush, embedded DNS resolver (`miekg/dns`) returning NXDOMAIN for `deny` and forwarding
  for `allow` / `allow_with_dlp`, and the five Phase 1 HTTP endpoints (`/api/status`,
  `/api/policies`, `/api/policies/:category`, `/api/stats`, `/api/stats/reset`).
- Privacy-audit test (`internal/store/privacy_test.go`) sweeps every text column to assert no
  domain / URL / IP fingerprints reach SQLite after a sequence of DNS events.
- Electron tray shell: hidden-on-startup tray icon with Status / Open Settings / Quit context
  menu, on-demand BrowserWindow that destroys itself on close, React renderer with `Settings`
  and `Status` pages, a localhost HTTP client for the Go agent, and 10-second tray health
  polling that swaps the icon between green/red variants based on agent reachability.
- Six bundled rule files (`ai_chat_blocked.txt`, `ai_code_blocked.txt`, `ai_allowed.txt`,
  `ai_chat_dlp.txt`, `phishing.txt`, `social.txt`).

### 2026-05-12 (Phase 1 finish + Phase 2 DLP core)
- **Bundled rules**: added `rules/news.txt` (29 news domains, leading-dot apex match)
  and `rules/manifest.json` with real SHA256 checksums for every bundled rule file
  (including the new DLP JSON files). This is the wire format the future rule
  updater will compare against to do delta downloads.
- **Platform integration scripts**: `scripts/macos/configure-dns.sh`,
  `scripts/macos/com.secureedge.agent.plist`, `scripts/windows/configure-dns.ps1`,
  `scripts/windows/register-service.ps1`, `scripts/linux/configure-dns.sh`, and
  `scripts/linux/secure-edge.service`. All DNS scripts support `apply`/`restore`
  and the Linux unit hardens via `ProtectSystem=strict`, `NoNewPrivileges`, and
  `CAP_NET_BIND_SERVICE` ambient capability.
- **Packaging**: `agent/nfpm.yaml` plus `agent/scripts/postinstall.sh` and
  `agent/scripts/preremove.sh` for a clean `.deb` install/uninstall cycle that
  drops the binary at `/usr/bin`, config + rules under `/etc/secure-edge`, and
  the systemd unit at `/lib/systemd/system`.
- **CI**: `.github/workflows/ci.yml` runs three jobs on every push/PR — Go
  agent (`make test && make lint && make build`), Electron tray (`npm ci && npm
  run typecheck`), and browser extension (`tsc --noEmit`).
- **DLP pipeline core (`agent/internal/dlp/`)**: 9 source files implementing the
  layered DLP pipeline — `classifier.go`, `ahocorasick.go` (uses
  `github.com/cloudflare/ahocorasick`), `regex.go` (candidate-window
  validation), `hotword.go` (configurable proximity), `entropy.go` (Shannon),
  `exclusion.go` (dictionary exact + proximity + regex), `scorer.go`
  (multi-signal aggregator with multi-match cap), `threshold.go` (per-severity
  block decision), `pipeline.go` (atomic-rebuild orchestrator), plus
  `types.go`, `loader.go`, and a corresponding `*_test.go` file for every
  component. `pipeline_test.go` exercises the full pipeline on true positives
  (`AKIA…` with hotword), known false positives (`AKIAIOSFODNN7EXAMPLE`),
  benign prose, empty content, and very long content (>100 KiB).
- **DLP API endpoints**: `POST /api/dlp/scan` (4 MiB body cap, returns
  `{blocked, pattern_name, score}` — content never persisted), `GET /api/dlp/config`,
  and `PUT /api/dlp/config` (writes through to the `dlp_config` SQLite singleton
  and the live `ThresholdEngine`). Anonymous `dlp_scans_total` /
  `dlp_blocks_total` counters incremented on every scan.
- **DLP rules**: `rules/dlp_patterns.json` with 13 patterns (AWS, GitHub,
  GitLab, Google, Slack, PEM private key, generic API key, bulk email, bulk
  US phone, US SSN, credit card with Luhn-shaped prefixes, source-code
  heuristics, internal/corp URL); `rules/dlp_exclusions.json` with the
  globals + AWS-doc example key + 555-01xx fictional phone numbers + test
  credit cards + RFC 2606 email domains.
- **Browser extension skeleton (`extension/`)**: Manifest V3 with content
  scripts matched at 10 Tier-2 AI domains, a service worker that proxies
  `/api/status` calls for the popup, a minimal popup showing agent
  online/offline + version + uptime, and `paste-interceptor.ts` — captures
  paste events, ships text to `POST /api/dlp/scan`, blocks the paste only
  when the agent says so, falls open on agent outage, and shows a 5-second
  toast carrying the pattern name (sanitised to printable ASCII).
