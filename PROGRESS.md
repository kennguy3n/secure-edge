# ShieldNet Secure Edge — Progress Tracker

> Last updated: 2026-05-13

## Overall Status

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: DNS Blocking + Electron Tray | Complete | 100% |
| Phase 2: Browser Extension + Layered DLP Pipeline | Complete | 100% |
| Phase 3: Rule Updates + Installers | Complete | 100% |
| Phase 4: MITM Proxy (Optional) | Complete | 100% |
| Phase 5: Enterprise Features | Complete | 100% |

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
- [x] Content script: intercept form submission events
- [x] Content script: intercept fetch/XHR requests before send
- [x] Native Messaging host manifest (macOS, Windows, Linux paths)
- [x] Native Messaging communication with Go agent
- [x] Ephemeral block notification UI (in-page banner, auto-dismiss, shows pattern name only)
- [x] Firefox WebExtensions port
- [x] Safari Web Extension port
- [x] Extension popup: connection status to Go agent

### Integration
- [x] Anonymous DLP counters: `dlp_scans_total`, `dlp_blocks_total` added to `aggregate_stats`
- [x] Category toggles extended to three-state: Allow / Allow + Inspect / Block
- [x] Aho-Corasick automaton rebuild triggered on rule file change
- [x] Privacy review: confirm no scan content, no matched text, no domain is written to disk

## Phase 3 Detailed Breakdown

### Rule Updater
- [x] HTTP client to poll `manifest.json` from configurable URL
- [x] Manifest parser: version comparison, SHA256 checksum verification
- [x] Delta download: only fetch files with changed checksums
- [x] Atomic file replacement (write temp file, rename)
- [x] Trigger policy engine + DLP automaton rebuild after rule update
- [x] Configurable poll interval (default: 6 hours)
- [x] Manual trigger via `POST /api/rules/update`
- [x] API: `GET /api/rules/status` — last update time, current version, next check

### Multi-Platform Installers
- [x] macOS: `.pkg` installer via `pkgbuild` + `productbuild`
- [x] macOS: post-install script (set DNS, register LaunchDaemon, install Electron tray)
- [x] macOS: uninstaller script (restore DNS, remove LaunchDaemon, remove files)
- [x] Windows: MSI installer via WiX Toolset
- [x] Windows: post-install actions (set DNS via netsh, register service, install tray)
- [x] Windows: uninstaller (restore DNS, remove service, remove files)
- [x] Linux: `.deb` package via `nfpm`
- [x] Linux: `.rpm` package via `nfpm`
- [x] Linux: post-install script (configure systemd-resolved/resolv.conf, enable systemd unit)
- [x] Linux: uninstaller (restore DNS config, disable service, remove files)

### CI/CD
- [x] GitHub Actions workflow: build Go agent (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64)
- [x] GitHub Actions workflow: build Electron tray app (macOS, Windows, Linux)
- [x] GitHub Actions workflow: build browser extensions (Chrome .zip, Firefox .xpi)
- [x] GitHub Actions workflow: run Go unit tests
- [x] GitHub Actions workflow: create GitHub Release with all artifacts
- [x] Electron auto-update via `electron-updater`
- [ ] Code signing: macOS Developer ID (when available)
- [ ] Code signing: Windows Authenticode (when available)

## Phase 4 Detailed Breakdown

### MITM Proxy
- [x] `elazarl/goproxy` integration on `127.0.0.1:8443`
- [x] Per-device Root CA generation (`crypto/x509`, ECDSA P-256)
- [x] Dynamic certificate generation for Tier 2 domains (1 h in-memory cache)
- [x] CONNECT tunnel passthrough for non-Tier-2 domains (no decryption)
- [x] Request body extraction from decrypted HTTPS for DLP pipeline
- [x] DLP pipeline integration (same layered pipeline as browser extension path)
- [x] Response forwarding after DLP pass
- [x] Block response page for DLP failures (HTTP 451 + JSON `{blocked, pattern_name}`)

### CA Trust Installation Scripts
- [x] macOS: `security add-trusted-cert` automation
- [x] Windows: `certutil -addstore` automation
- [x] Linux: copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates` (also RHEL `update-ca-trust`)

### System Proxy Configuration Scripts
- [x] macOS: `networksetup -setsecurewebproxy` for active interfaces
- [x] Windows: Registry `ProxyServer` + `ProxyEnable` keys
- [x] Linux: GNOME proxy settings via `gsettings` + KDE via `kwriteconfig5/6`
- [x] Environment variable approach: `HTTP_PROXY`/`HTTPS_PROXY` in `/etc/profile.d/secure-edge-proxy.sh`

### Electron UI
- [x] "Advanced DLP" settings section
- [x] "Enable Full DLP Protection" wizard (generate CA → install CA → configure proxy)
- [x] Proxy status indicator in tray menu
- [x] Certificate pinning bypass list management UI
- [x] API: `POST /api/proxy/enable` — generate CA, install, configure
- [x] API: `POST /api/proxy/disable` — remove proxy config, optionally remove CA
- [x] API: `GET /api/proxy/status` — running, CA installed, proxy configured

## Phase 5 Detailed Breakdown

### Enterprise Configuration
- [x] JSON-based policy profile format (categories, actions, DLP thresholds, rule update URL)
- [x] Profile download from server URL
- [x] Profile application on agent startup
- [x] Profile lock (prevent local override when managed)
- [x] API: `GET /api/profile` — current profile
- [x] API: `POST /api/profile/import` — import profile from URL or file

### Tamper Detection
- [x] Periodic check: is OS DNS still pointing to 127.0.0.1?
- [x] Periodic check: is system proxy still configured (if Phase 4 enabled)?
- [x] Ephemeral tray notification on tamper detection (no persistent log)
- [x] Tamper counter in `aggregate_stats`

### Agent Heartbeat (Optional)
- [x] Configurable heartbeat URL (disabled by default)
- [x] Heartbeat payload: agent version, OS type, aggregate counters ONLY
- [x] Heartbeat interval: configurable (default: 1 hour)
- [x] NO access data, NO domain data, NO DLP match details in heartbeat

### Admin Tools
- [x] Export aggregate stats as JSON
- [x] Custom rule file support (local override directory)
- [x] Custom DLP patterns/exclusions override files
- [x] DLP scoring threshold tuning UI in Electron settings
- [x] Allowlist/blocklist override UI (add/remove individual domains)

### Quality & Documentation
- [x] Performance profiling: memory usage, CPU usage, DNS latency benchmarks
- [x] DLP accuracy benchmarks: false positive/negative rates against test corpus (`agent/internal/dlp/accuracy_test.go`, FP < 10%, FN < 5%)
- [x] Privacy audit: code review of every disk write path to verify zero access logging (`agent/internal/store/privacy_test.go::TestPrivacy_DLPScanContentNotPersisted`)
- [x] Admin guide (`docs/admin-guide.md`)
- [x] User guide (`docs/user-guide.md`)
- [x] Rule contribution guide (`docs/rule-contribution-guide.md`)
- [x] DLP pattern authoring guide (`docs/dlp-pattern-authoring-guide.md`)
- [x] Accessibility audit of Electron UI (`docs/accessibility.md`)

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
│   │   ├── proxy/                  # Phase 4 local MITM proxy (selective TLS
│   │   │                             decryption for Tier-2 hosts only)
│   │   ├── profile/                # Phase 5 enterprise profile loader + lock
│   │   ├── tamper/                 # Phase 5 OS DNS/proxy tamper detector
│   │   └── heartbeat/              # Phase 5 optional outbound heartbeat
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
│   ├── manifest.json               # Chrome MV3
│   ├── manifest.firefox.json       # Firefox MV3
│   ├── manifest.safari.json        # Safari Web Extension (Xcode wrapper via xcrun)
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
├── docs/                           # End-user / operator documentation
│   ├── admin-guide.md
│   ├── user-guide.md
│   ├── rule-contribution-guide.md
│   ├── dlp-pattern-authoring-guide.md
│   └── accessibility.md
├── SECURITY_RULES.md               # Reference table of every DLP pattern
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

### 2026-05-13 (Phase 5 completion — DLP coverage, audits, docs)
- **Expanded DLP patterns (`rules/dlp_patterns.json`)** with ~95 new
  real-world rules across 15 ecosystems: Java (Maven/Gradle creds,
  JDBC URLs, Spring config, keystores, AWS SDK), Rust (Cargo registry,
  Crates.io, Rocket secret keys, password literals), Frontend
  (Firebase web config, React `REACT_APP_`, Next.js `NEXT_PUBLIC_`,
  Vite `VITE_`, Angular `environment.ts`, Webpack DefinePlugin),
  Desktop (Tauri signing keys, Electron Forge / Builder publish
  tokens), AI/ML (OpenAI project / svcacct / user keys, Anthropic,
  HuggingFace, Cohere, Replicate, Pinecone, Mistral, W&B, LangSmith,
  Together, Groq), iOS (APNs `.p8`, App Store Connect, Cocoapods,
  Xcode Cloud, Team ID), Android (`google-services.json`, signing
  store password, Play Console JSON, `local.properties`), Flutter /
  React Native (Expo, EAS, CodePush, Fastlane Match, Dart `.env`),
  Databases (Postgres / MySQL / MongoDB SRV / Redis / MSSQL / SQLite
  PRAGMA / Cassandra / Elasticsearch URLs), Cloud infrastructure
  (Cloudflare, DigitalOcean, Vercel, Netlify, Supabase, Pulumi, Helm,
  Terraform, Docker registry, K8s Secret YAML), CI/CD (CircleCI,
  Travis, Jenkins, Azure DevOps, GitLab, Bitbucket), messaging
  (Discord bot tokens, Telegram, Vonage), payment (PayPal, Square,
  Braintree, Adyen, Plaid, Coinbase), auth/identity (Auth0, Okta,
  OneLogin, Keycloak, Firebase Admin SDK, Supabase JWT, Clerk),
  password-in-code across Python / JS / TS / Java / Rust / Go / Swift
  / Kotlin / Dart. Matching `rules/dlp_exclusions.json` entries cover
  documented placeholder values, test fixtures, RFC 2606 reserved
  domains, and `${{ secrets.* }}` template literals. Manifest
  checksums regenerated in `rules/manifest.json`. Total patterns
  shipped: **139** across **20** categories — see `SECURITY_RULES.md`.
- **DLP accuracy benchmarks (`agent/internal/dlp/accuracy_test.go`)**:
  50-sample corpus (25 TP + 25 TN) covering every new ecosystem.
  Runs the full `Pipeline.Scan()` for each sample and asserts
  `FP rate < 10%` and `FN rate < 5%`. Current measurement: 25 TP /
  25 TN, 0 FP, 0 FN.
- **Privacy audit (`agent/internal/store/privacy_test.go`)** extended
  with `TestPrivacy_DLPScanContentNotPersisted` — runs an
  `AggregateStats` update against the full DLP scan path, then sweeps
  every text column in every SQLite table for forbidden content
  (scan text, matched secret value, pattern names, prefixes). Confirms
  the agent never persists scan content or match details to disk.
- **Expanded integration test
  (`agent/internal/dlp/integration_extended_test.go`)** scans a ~10 KB
  benign document that embeds one secret per category in filler text,
  asserts every embedded secret is detected with an allowed pattern
  name, and enforces a performance budget of 50 ms (median of 5 runs)
  in non-race builds — relaxed to 1.5 s under `-race` via the
  build-tagged `raceEnabled` flag. Production hot-path scans of ~5 KB
  inputs typically run in ~5-10 ms on a developer workstation; the
  test budget is set to catch order-of-magnitude regressions while
  tolerating shared CI runner jitter.
- **Documentation suite** added under `docs/`:
  `admin-guide.md`, `user-guide.md`, `rule-contribution-guide.md`,
  `dlp-pattern-authoring-guide.md`, `accessibility.md`, plus the
  top-level `SECURITY_RULES.md` reference table.
- **Accessibility audit + fixes for the Electron tray UI**: top
  navigation is now `role="tablist"` / `role="tab"` with roving
  `tabIndex` and `aria-selected`; every icon-only and short-label
  button has an explicit `aria-label`; the agent status banner and
  feedback toasts use `role="status"` / `role="alert"` with
  appropriate `aria-live`; form inputs in the Admin Overrides section
  have visually-hidden `<label>` elements via a new `.sr-only`
  utility; explicit `:focus-visible` ring added in `styles.css`
  meeting WCAG 2.1 SC 2.4.7. Findings and verification steps recorded
  in `docs/accessibility.md`.

### 2026-05-13 (Phase 5 enterprise rollout)
- **Expanded DLP patterns (`rules/dlp_patterns.json`)** with real-world
  cloud credentials: AWS secret access key / session token / ARN / MWS;
  Azure storage account key, AD client secret, SAS token, connection
  string, DevOps PAT, subscription ID; GCP service-account JSON, OAuth2
  client secret, Firebase FCM server key; plus Stripe, Twilio,
  SendGrid, Mailchimp, npm, PyPI, Heroku, JWT, generic DB connection
  string, password-in-assignment, HashiCorp Vault, Datadog. Each entry
  ships with a literal `prefix` for the Aho-Corasick scan, severity,
  hotwords, and where relevant `require_hotword`/`entropy_min`. Matching
  exclusions added in `rules/dlp_exclusions.json`. Manifest checksums
  regenerated.
- **Enterprise configuration profiles (`agent/internal/profile/`)**:
  JSON profile schema, `LoadFromFile`/`LoadFromURL` with a 1 MiB cap
  and 30s HTTP timeout, `Profile.Apply()` writes the policy and DLP
  thresholds back through the existing `store.Store`, `Holder.Locked()`
  blocks `PUT /api/policies/:category` and `PUT /api/dlp/config` when
  `managed=true`. API: `GET /api/profile`, `POST /api/profile/import`.
  Wired in `cmd/agent/main.go` via `loadProfileOnStartup` (local file
  takes precedence over URL when both are configured). Comprehensive
  tests in `profile_test.go` and `handlers_test.go`.
- **Tamper detection (`agent/internal/tamper/`)**: `Detector` periodic
  check (default 60s) of OS DNS + system proxy. Platform-specific
  probes via build tags — `/etc/resolv.conf` on Linux/BSD,
  `networksetup -getdnsservers` on macOS, `netsh interface ipv4 show
  dnsservers` on Windows; proxy probes use env vars on Linux/BSD,
  `networksetup -get{web,securewebp}roxy` on macOS, `netsh winhttp
  show proxy` on Windows. Counter `tamper_detections_total` added via
  additive migration in `store.Store`. Electron tray balloon notifies
  on transition without persisting any event. API: `GET /api/tamper/status`.
- **Agent heartbeat (`agent/internal/heartbeat/`)**: optional, disabled
  by default (URL=""). Payload is exactly
  `{agent_version, os_type, os_arch, aggregate_counters}` — tests
  assert no URL / domain / IP / DLP-match field is ever serialised.
  Configurable interval (default 1h), errors swallowed so a flaky
  collector never blocks the agent.
- **Admin override tools**: `agent/internal/rules/override.go`
  manages `rules/local/allow.txt` / `block.txt` with mutual
  exclusivity + atomic temp-rename writes; sources are merged into
  `policy.Engine` on startup without mutating bundled files.
  `agent/internal/dlp/override.go` merges
  `rules/local/dlp_patterns_override.json` and
  `dlp_exclusions_override.json` on top of bundled rules
  (same-name pattern replaces, others append). New API:
  `GET /api/rules/override`, `POST /api/rules/override`,
  `DELETE /api/rules/override/:domain`, `GET /api/stats/export`.
- **Electron Settings UI** (`electron/src/pages/Settings.tsx`): DLP
  scoring sliders (threshold_{critical,high,medium,low}, hotword
  boost, entropy boost/penalty, exclusion penalty, multi-match
  boost) call `PUT /api/dlp/config`. Allow/block override form +
  per-domain remove buttons. UI auto-disables every input when the
  current profile reports `managed=true`.
- **Performance benchmarks**: `pipeline_bench_test.go`,
  `resolver_bench_test.go`, `stats_bench_test.go` with results
  captured in `BENCHMARKS.md` at the repo root. Hot-path scan stays
  sub-25µs on small payloads; counter increment is 3ns.

### 2026-05-12 (Phase 4 + Safari extension)
- **Phase 4 local MITM proxy (`agent/internal/proxy/`)**: `proxy.go`
  wraps `github.com/elazarl/goproxy` on `127.0.0.1:8443`. CONNECT
  requests for non-Tier-2 hosts are routed through an opaque tunnel
  (no decryption, no log); Tier-2 hosts (policy =
  `allow_with_dlp`) are MITM-decrypted and request bodies run
  through the existing `dlp.Pipeline`. A DLP block returns HTTP 451
  with JSON `{blocked, pattern_name}`. `ca.go` generates a
  per-device ECDSA P-256 Root CA at first run (default
  `~/.secure-edge/ca.{crt,key}`), then signs short-lived leaf certs
  on demand and caches them for one hour. `controller.go` owns the
  Enable/Disable/Status lifecycle and reports anonymous
  `dlp_scans_total` / `dlp_blocks_total` counters via the existing
  aggregate-stats path. `proxy_test.go`, `ca_test.go`,
  `controller_test.go`, and a new `integration_test.go` cover both
  paths end-to-end and assert that nothing the user typed (body,
  URL, Host header) ever reaches stdout/stderr.
- **Proxy API**: new endpoints in `agent/internal/api/server.go` —
  `POST /api/proxy/enable` (generates CA, starts listener, returns
  CA cert path for trust install), `POST /api/proxy/disable`
  (stops listener, optional `remove_ca`), and
  `GET /api/proxy/status` (`{running, ca_installed, listen_addr,
  dlp_scans_total, dlp_blocks_total}`). The controller is wired
  through `proxyAdapter` in `cmd/agent/main.go` so the listener
  shares the policy engine + DLP pipeline with the extension path.
- **CA trust + system proxy scripts** (`scripts/{macos,windows,linux}/`):
  `install-ca.sh` / `install-ca.ps1` add the CA to the platform
  trust store (`security add-trusted-cert`, `certutil -addstore`,
  `update-ca-certificates`/`update-ca-trust`) and the matching
  remove subcommands undo it. `configure-proxy.sh` /
  `configure-proxy.ps1` flip the system HTTPS proxy to
  `127.0.0.1:8443` via `networksetup`, the IE registry hive (GNOME
  `gsettings`, KDE `kwriteconfig5/6`, and `/etc/profile.d` for
  POSIX env-var consumers), with `restore` subcommands.
- **Electron Proxy page (`electron/src/pages/ProxySettings.tsx`)**:
  "Advanced DLP (Local Proxy)" wizard that calls `POST
  /api/proxy/enable`, shows the platform-appropriate install
  command for the CA + the matching `configure-proxy` command, and
  polls `GET /api/proxy/status` every 5 s. Tray now carries
  "Proxy: Active / Inactive" alongside the existing health check,
  and the main process polls the proxy status on the same 10 s
  cadence.
- **Safari Web Extension port (`extension/manifest.safari.json` +
  `extension/scripts/build-safari.mjs`)**: MV3 manifest with
  Safari-specific `browser_specific_settings` and a build script
  that copies `dist/` to `dist-safari/`, swaps in the Safari
  manifest, and wraps the result with `xcrun
  safari-web-extension-converter`. Safari has no Native Messaging,
  so the extension exclusively uses the existing
  `127.0.0.1:8080/api/dlp/scan` HTTP fallback; the agent's CORS
  allowlist now also accepts `safari-web-extension://<UUID>` and
  `moz-extension://<UUID>` origins
  (`agent/internal/api/server.go`).
- **Tests added**: `agent/internal/proxy/{proxy,ca,controller,integration}_test.go`
  cover CONNECT passthrough, Tier-2 MITM + DLP block, counter
  increments, lifecycle idempotency, and the "no content ever
  leaks to stdout/stderr" privacy invariant;
  `agent/internal/api/handlers_test.go` adds the proxy
  enable/disable/status cases plus the new `safari-web-extension://`
  + `moz-extension://` CORS cases;
  `extension/src/background/__tests__/safari-fallback.test.ts`
  verifies the scan client falls through to HTTP when
  `chrome.runtime.connectNative` is undefined.

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

### 2026-05-12 (Phase 2 finish + Phase 3)
- **Form / fetch / XHR interception (`extension/src/content/`)**: new
  `form-interceptor.ts` (listens for `submit` on the 10 Tier-2 domains,
  scans concatenated `<textarea>` + `<input type=text>` values, blocks
  and surfaces the same toast as paste), `network-interceptor.ts`
  (monkey-patches `window.fetch` and `XMLHttpRequest.prototype.send`,
  scans bodies > 50 bytes), and a shared `scan-client.ts` /
  `toast.ts` layer the paste interceptor was refactored onto. Routing
  prefers Native Messaging through the service worker and falls back
  to `127.0.0.1:8080/api/dlp/scan`.
- **Native Messaging (`extension/native-messaging/` +
  `extension/src/background/native-messaging.ts` +
  `agent/internal/api/nativemsg.go`)**: Chrome host manifest
  (`com.secureedge.agent.json`) plus `install.sh` (macOS/Linux) and
  `install.ps1` (Windows) installers. The background service worker
  owns a persistent `chrome.runtime.connectNative` port, queues per-
  request timeouts (1500 ms), and falls back to HTTP when the port
  closes. The agent's `nativemsg.go` implements the 4-byte little-
  endian length-prefix protocol on stdin/stdout and dispatches scan
  requests through the same `dlp.Pipeline.Scan()` used by the HTTP
  endpoint. New `--native-messaging` flag on the agent binary serves
  the protocol without standing up the DNS / API server.
- **Firefox port (`extension/manifest.firefox.json` +
  `extension/scripts/build-firefox.mjs`)**: MV3 manifest with
  `browser_specific_settings.gecko` and a `npm run build:firefox`
  script that drops a Firefox-ready bundle into `dist-firefox/`.
- **Three-state CategoryToggle (`electron/src/components/CategoryToggle.tsx`)**:
  Allow / Allow + Inspect / Block segmented control wired to the
  existing `allow` / `allow_with_dlp` / `deny` action values.
- **Rule updater (`agent/internal/rules/updater.go`)**: periodic
  manifest poller (default 6 h) with delta downloads, SHA256
  verification, atomic `os.Rename` replacement, path-traversal
  rejection, and a reload callback that refreshes both the policy
  engine and the live DLP pipeline. Version history persisted to a
  new `rule_versions` SQLite table via `store.CurrentRuleVersion` /
  `store.AppendRuleVersion`. Configurable through new `config.yaml`
  fields `rule_update_url`, `rule_update_interval`, `rules_dir`.
- **Rule updater API**: `POST /api/rules/update` triggers an
  immediate check and returns `{updated, version, files_downloaded}`;
  `GET /api/rules/status` returns the current version, last/next check
  times, and configured manifest URL. Both 503 when the updater is
  not configured.
- **Installers**: macOS `scripts/macos/build-pkg.sh` (pkgbuild +
  productbuild) plus `postinstall.sh` / `uninstall.sh`; Windows
  `scripts/windows/secure-edge.wxs` (WiX v4) + `build-msi.ps1` +
  `postinstall.ps1` + `uninstall.ps1`; Linux `scripts/linux/`
  postinstall, preremove, `build-packages.sh` (nfpm deb + rpm), and a
  stand-alone uninstaller.
- **CI/CD release pipeline (`.github/workflows/release.yml`)**:
  triggered on `v*` tags. Matrix-builds the Go agent for
  linux/{amd64,arm64}, darwin/{amd64,arm64}, windows/amd64; the
  Electron tray on macOS / Linux / Windows runners; the browser
  extension as a Chrome `.zip` and Firefox `.xpi`; the native
  installers per platform; and publishes everything to a GitHub
  Release via `softprops/action-gh-release@v2` with auto-generated
  notes. Electron auto-update is wired through `electron-updater` and
  surfaced as an "Update available" entry in the tray context menu.
- **Tests added**: `agent/internal/rules/updater_test.go` (13
  scenarios — fresh install, delta skip, tampered SHA256 rejection,
  atomic replace, version tracking, reload callbacks, path traversal,
  context cancel, explicit URLs, status lifecycle, file hash helper,
  manifest fetch errors, initial check on start);
  `agent/internal/api/nativemsg_test.go` (8 scenarios — framing,
  multiple frames, nil scanner, unknown kind, malformed JSON,
  oversize, context cancel, real `io.Pipe`);
  `agent/internal/api/handlers_test.go` adds 7 cases for the two new
  rules endpoints; `extension/src/content/__tests__/`
  `form-interceptor.test.ts` (5 cases) and
  `network-interceptor.test.ts` (6 cases);
  `extension/src/background/__tests__/native-messaging.test.ts` (5
  cases including reconnect-on-disconnect).
