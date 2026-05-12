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
- [ ] `rules/dlp_patterns.json` — extended format with prefix, hotwords, hotword_window, entropy_min, severity, score_weight, min_matches
- [ ] `rules/dlp_exclusions.json` — dictionary and regex exclusions per pattern and global
- [ ] Default patterns: AWS keys, GitHub tokens, GitLab tokens, Google API keys, Slack tokens, private keys (PEM), email addresses (bulk), phone numbers (bulk), SSN, credit card numbers, source code heuristics, internal URL patterns
- [ ] Default exclusions: test/example/placeholder/dummy strings, @example.com emails, 000-00-0000 SSN, known public keys

### Browser Extension
- [ ] Chrome extension project setup (Manifest V3)
- [ ] Content script: intercept paste events on Tier 2 AI tool domains
- [ ] Content script: intercept form submission events
- [ ] Content script: intercept fetch/XHR requests before send
- [ ] Native Messaging host manifest (macOS, Windows, Linux paths)
- [ ] Native Messaging communication with Go agent
- [ ] Ephemeral block notification UI (in-page banner, auto-dismiss, shows pattern name only)
- [ ] Firefox WebExtensions port
- [ ] Extension popup: connection status to Go agent

### Integration
- [ ] Anonymous DLP counters: `dlp_scans_total`, `dlp_blocks_total` added to `aggregate_stats`
- [ ] Category toggles extended to three-state: Allow / Allow + Inspect / Block
- [ ] Aho-Corasick automaton rebuild triggered on rule file change
- [ ] Privacy review: confirm no scan content, no matched text, no domain is written to disk

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
