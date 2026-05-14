# ShieldNet Secure Edge

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![CI](https://github.com/kennguy3n/secure-edge/actions/workflows/ci.yml/badge.svg)](https://github.com/kennguy3n/secure-edge/actions/workflows/ci.yml)
[![Coverage: agent/internal/dlp ≥ 80%](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)](./.github/workflows/ci.yml)

**Open-source, privacy-first AI Data Leakage Prevention for desktop.**

Secure Edge is a cross-platform desktop agent (Windows, macOS, Linux) that blocks unauthorized
AI tools at the DNS level and inspects content sent to approved AI tools via a layered
on-device DLP pipeline. Content reaches the pipeline through a Chrome/Firefox/Safari
browser extension or, for non-browser traffic, an optional local MITM proxy that decrypts
only Tier-2 domains and tunnels everything else opaquely. It runs as a minimal system-tray
app, consumes negligible CPU and memory, and **logs nothing** about user access — only
running aggregate counters.

## Privacy First

The agent stores only:

- **Policy configuration** — which categories are allowed, inspected, or blocked
- **Anonymous aggregate counters** — `dns_queries_total`, `dns_blocks_total`,
  `dlp_scans_total`, `dlp_blocks_total` (integers only, no per-event timestamps)
- **Rule files** — domain lists and DLP patterns

No domain names, URLs, IP addresses, user identifiers, or per-event timestamps are ever written
to disk. DLP block notifications are shown in real time and discarded. The
[`store/privacy_test.go`](./agent/internal/store/privacy_test.go) test sweeps every text column
in the SQLite database and asserts none of those values reach disk.

## Policy Tiers

| Tier | Action | Mechanism |
|------|--------|-----------|
| 1 | Allow | Pass-through, no inspection |
| 2 | Allow + DLP | Forwarded, inspected by the layered DLP pipeline (Phase 2) |
| 3 | Block (AI) | DNS resolver returns NXDOMAIN |
| 4 | Block (Other) | DNS resolver returns NXDOMAIN |

## Quick Start

```bash
git clone https://github.com/kennguy3n/secure-edge.git
cd secure-edge

# Build and run the Go agent (DNS listener + local API on 127.0.0.1:8080).
cd agent
make build
./secure-edge-agent --config ../config.yaml      # or omit --config for defaults

# In a second shell, install and run the Electron tray app.
cd electron
npm install
npm run build
npm start
```

Binding `127.0.0.1:53` on Linux/macOS requires `sudo` or the `cap_net_bind_service` capability;
pick a higher-numbered `dns_listen` (e.g. `127.0.0.1:5353`) in `config.yaml` for unprivileged
development.

Example `config.yaml`:

```yaml
upstream_dns: "8.8.8.8:53"
dns_listen: "127.0.0.1:5353"
api_listen: "127.0.0.1:8080"
db_path: "secure-edge.db"
stats_flush_interval: 60s
rule_paths:
  - rules/ai_chat_blocked.txt
  - rules/ai_code_blocked.txt
  - rules/ai_allowed.txt
  - rules/ai_chat_dlp.txt
  - rules/phishing.txt
  - rules/social.txt
  - rules/news.txt
dlp_patterns: rules/dlp_patterns.json     # optional — enables /api/dlp/*
dlp_exclusions: rules/dlp_exclusions.json # optional

# Phase 3 rule updater. Leaving rule_update_url blank disables the
# updater; everything else (DNS, policies, DLP) keeps working.
rule_update_url: ""                       # e.g. https://example.com/manifest.json
rule_update_interval: 6h                  # cadence; default 6h
rules_dir: rules                          # output dir for downloaded rule files

# Phase 4 local MITM proxy. proxy_enabled=false (default) leaves the
# listener stopped — /api/proxy/enable can start it at runtime.
proxy_listen: "127.0.0.1:8443"
proxy_enabled: false
ca_cert_path: ""                          # default ~/.secure-edge/ca.crt
ca_key_path: ""                           # default ~/.secure-edge/ca.key
proxy_pinning_bypass: []                  # hostnames to tunnel even if Tier-2
                                          # (e.g. apps that pin a specific CA)

# Phase 6 DLP engine tuning. Omitting a field keeps the built-in default.
# large_content_threshold: 51200   # bytes; skip low/medium patterns above this
# dlp_cache_ttl_seconds: 5         # 0 disables the scan-result cache
# dlp_cache_capacity: 256          # max cache entries
# dlp_rate_limit_per_sec: 100      # 0 disables the /api/dlp/scan rate limiter
# dlp_disabled_categories: []      # e.g. ["PII"] to disable a category

# Agent self-update. Both fields required to enable.
# agent_update_manifest_url: ""    # e.g. https://github.com/.../manifest.json
# agent_update_public_key: ""      # hex-encoded Ed25519 public key
```

Leaving `dlp_patterns` blank disables the DLP pipeline and returns `503` from
the `/api/dlp/*` endpoints; everything else (DNS, policies, stats) keeps
working. Likewise, leaving `rule_update_url` blank returns `503` from
`/api/rules/*`.

## Project Structure

```
secure-edge/
├── README.md            PROPOSAL.md  ARCHITECTURE.md  PHASES.md  PROGRESS.md
├── CONTRIBUTING.md      CHANGELOG.md  SECURITY.md  SECURITY_RULES.md  LICENSE
├── agent/                            # Go backend (single static binary)
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── api/                      # HTTP API server + handlers + ratelimit.go (Phase 6 token bucket)
│   │   ├── config/                   # YAML configuration loader
│   │   ├── dlp/                      # Layered DLP pipeline (Phase 2) + cache.go (Phase 6 LRU)
│   │   ├── dns/                      # Embedded DNS resolver (miekg/dns)
│   │   ├── heartbeat/                # Optional outbound heartbeat (Phase 5)
│   │   ├── policy/                   # Policy engine
│   │   ├── profile/                  # Enterprise profile loader + lock (Phase 5)
│   │   ├── proxy/                    # Selective MITM proxy (Phase 4)
│   │   ├── rules/                    # Rule-file parser + lookup + updater + admin override (Phase 3/5)
│   │   ├── stats/                    # Anonymous aggregate counters
│   │   ├── store/                    # SQLite (modernc.org/sqlite, WAL)
│   │   ├── tamper/                   # OS DNS/proxy tamper detector (Phase 5)
│   │   └── updater/                  # Agent self-update (Phase 6)
│   ├── nfpm.yaml                     # .deb packaging
│   ├── scripts/{post,pre}*.sh
│   ├── go.mod / go.sum
│   └── Makefile                      # build / test / lint targets
├── electron/                         # System-tray app (Electron + React)
│   ├── main.ts                       # Tray icon, health polling, BrowserWindow
│   ├── preload.ts                    # Secure contextBridge
│   ├── src/
│   │   ├── pages/{Settings,Status,ProxySettings,Rules,Setup}.tsx
│   │   ├── components/{CategoryToggle,StatsCard}.tsx
│   │   └── api/agent.ts              # HTTP client for the Go agent
│   ├── package.json
│   └── electron-builder.yml
├── extension/                        # Chrome / Firefox / Safari Manifest V3 companion
│   ├── manifest.json                 # Chrome MV3
│   ├── manifest.firefox.json         # Firefox MV3 (browser_specific_settings)
│   ├── manifest.safari.json          # Safari Web Extension (wrapped via xcrun)
│   ├── native-messaging/             # Native Messaging host manifest + installers
│   ├── src/
│   │   ├── background/               # service-worker.ts, native-messaging.ts, dynamic-hosts.ts
│   │   ├── content/                  # paste-, form-, network-, drag-, clipboard-* interceptors + scan-client.ts + toast.ts
│   │   ├── options/                  # Extension options page
│   │   └── popup/                    # Toolbar popup status UI
│   ├── tests/integration/            # Playwright smoke tests
│   ├── scripts/{build-firefox,build-safari}.mjs
│   ├── package.json
│   └── tsconfig.json
├── rules/                            # Bundled domain lists + DLP rules
│   ├── ai_chat_blocked.txt   ai_chat_dlp.txt   ai_code_blocked.txt
│   ├── ai_allowed.txt        phishing.txt      social.txt
│   ├── news.txt              manifest.json
│   ├── dlp_patterns.json
│   └── dlp_exclusions.json
├── docs/                             # Operator + contributor documentation
│   ├── admin-guide.md
│   ├── user-guide.md
│   ├── rule-contribution-guide.md
│   ├── dlp-pattern-authoring-guide.md
│   └── accessibility.md
├── scripts/                          # Platform install / DNS / proxy scripts
│   ├── macos/                        # build-pkg.sh, postinstall.sh, uninstall.sh,
│   │                                 # configure-dns.sh, install-ca.sh,
│   │                                 # configure-proxy.sh,
│   │                                 # com.secureedge.agent.plist
│   ├── windows/                      # secure-edge.wxs, build-msi.ps1,
│   │                                 # postinstall.ps1, uninstall.ps1,
│   │                                 # configure-dns.ps1, register-service.ps1,
│   │                                 # install-ca.ps1, configure-proxy.ps1
│   └── linux/                        # build-packages.sh, postinstall.sh,
│                                     # preremove.sh, uninstall.sh,
│                                     # configure-dns.sh, install-ca.sh,
│                                     # configure-proxy.sh, secure-edge.service
└── .github/
    ├── ISSUE_TEMPLATE/               # bug_report.md + feature_request.md
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        ├── ci.yml                    # Go + Electron + extension typecheck + tests
        └── release.yml               # multi-arch builds + GitHub Release on tags
```

## API

Local HTTP API on `127.0.0.1:8080` (configurable):

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/api/status`              | Agent status, uptime, version, Go runtime stats, DLP pattern count, rule file mtimes |
| GET    | `/api/policies`            | List `[category, action]` rows |
| PUT    | `/api/policies/:category`  | Update an action; triggers policy reload |
| GET    | `/api/stats`               | Aggregate counters (integers only) |
| POST   | `/api/stats/reset`         | Reset all counters to zero |
| POST   | `/api/dlp/scan`            | Scan `{content}` through the DLP pipeline; returns `{blocked, pattern_name, score}`. Content is processed in memory and never persisted. |
| GET    | `/api/dlp/config`          | Current DLP scoring weights and per-severity thresholds |
| PUT    | `/api/dlp/config`          | Update DLP scoring weights and thresholds |
| POST   | `/api/rules/update`        | Trigger an immediate rule-manifest check; returns `{updated, version, files_downloaded}` |
| GET    | `/api/rules/status`        | Current rule version + last/next check time + manifest URL |
| POST   | `/api/proxy/enable`        | Generate the per-device CA if missing and start the local MITM proxy; returns `{ca_cert_path}` for OS trust install |
| POST   | `/api/proxy/disable`       | Stop the local MITM proxy; pass `{"remove_ca": true}` to also delete the CA files |
| GET    | `/api/proxy/status`        | `{running, ca_installed, listen_addr, dlp_scans_total, dlp_blocks_total}` |
| GET    | `/api/profile`             | Current enterprise profile, or 404 if none is loaded |
| POST   | `/api/profile/import`      | Import a profile from `{url}` or `{profile}` body and apply it; locks local policy edits when `managed=true` |
| GET    | `/api/tamper/status`       | `{dns_ok, proxy_ok, last_check, detections_total}` from the tamper detector |
| GET    | `/api/stats/export`        | Downloadable JSON envelope `{agent_version, os_type, os_arch, exported_at, stats}` |
| GET    | `/api/rules/override`      | List the admin allow/block override sets |
| POST   | `/api/rules/override`      | Add `{domain, list:"allow"\|"block"}` to the override store; moves between lists if needed |
| DELETE | `/api/rules/override/:domain` | Remove an override regardless of list |
| GET    | `/api/agent/update-check`  | Check whether a newer agent release is published on the configured manifest channel. Returns 503 when no updater is wired. |
| POST   | `/api/agent/update`        | Download the latest agent release, verify its SHA-256 + Ed25519 signature, and stage it for restart. |

`action` is one of `allow`, `allow_with_dlp`, `deny`.

The DLP endpoints return `503 Service Unavailable` when the agent is started
without a `dlp_patterns` config entry (Phase 1 deployments). The `/api/rules/*`
endpoints return `503` when `rule_update_url` is blank. The `/api/proxy/*`
endpoints return `503` when the proxy controller has not been configured (e.g.
agents built without `proxy_listen`).

The extension prefers to reach the agent through Chrome Native Messaging
(no CORS, survives air-gapped networks) and falls back to direct HTTP to
`127.0.0.1:8080` when the native host is unavailable. Install the host
manifest with `extension/native-messaging/install.sh` (macOS/Linux) or
`install.ps1` (Windows). Safari Web Extensions have no Native Messaging,
so the Safari port uses the HTTP fallback exclusively; the agent's CORS
allowlist accepts `chrome-extension://`, `moz-extension://`, and
`safari-web-extension://` origins.

## Enterprise Features (Phase 5)

Optional features for managed deployments — every one of them
honours the same privacy invariant as the base agent.

- **Configuration profiles.** Set `profile_path` or `profile_url` in
  `config.yaml`; the JSON profile (`name`, `version`, `managed`,
  `categories`, `dlp`) is applied on startup. When `managed=true`,
  `PUT /api/policies/:category` and `PUT /api/dlp/config` return
  `403 Forbidden` and the Electron settings UI disables every input.
- **Tamper detection.** Background goroutine (default 60s) checks
  that OS DNS still points at the agent and, when the local MITM
  proxy is enabled, that the system proxy still points at
  `127.0.0.1:8443`. Transitions bump `tamper_detections_total` in
  the existing `aggregate_stats` row; the tray surfaces an
  ephemeral balloon — *no* per-event log on disk.
- **Optional heartbeat.** Set `heartbeat_url` to enable. Payload is
  exactly `{agent_version, os_type, os_arch, aggregate_counters}`
  — no URL, domain, IP, or DLP-match data is ever serialised. Tests
  in `agent/internal/heartbeat/heartbeat_test.go` assert this on
  the JSON wire format.
- **Admin overrides.** Drop files into `rules/local/` (allow.txt,
  block.txt, dlp_patterns_override.json, dlp_exclusions_override.json)
  to add company-specific rules without touching bundled files. The
  Electron Settings page has an allow/block UI that writes through
  `POST /api/rules/override` and DLP threshold sliders that hit
  `PUT /api/dlp/config`.
- **Stats export.** `GET /api/stats/export` returns the counter
  snapshot with a `Content-Disposition: attachment` envelope —
  counters only, no access data.

## Testing

```bash
cd agent
make test                 # runs `go test -race ./...`, includes DLP + proxy unit + integration tests
make lint                 # runs `go vet ./...`

cd ../electron
npm run typecheck         # TypeScript strict mode against renderer + main

cd ../extension
npm install && npm run typecheck   # browser-extension Manifest V3 typecheck
npm test                            # node --test on content + background scripts
npm run build:firefox               # Firefox bundle in dist-firefox/
npm run build:safari                # Safari Web Extension (macOS-only; uses xcrun)
```

DLP coverage includes one `*_test.go` per pipeline component
(`classifier`, `ahocorasick`, `regex`, `hotword`, `entropy`, `exclusion`,
`scorer`, `threshold`) plus a `pipeline_test.go` integration test exercising
real AWS keys with hotword context (block), the AWS docs example key
`AKIAIOSFODNN7EXAMPLE` (exclude), benign prose (allow), empty content, and
large content embedding a real-looking key.

Phase 5 tests live alongside the new packages: `profile/`, `tamper/`,
`heartbeat/`, and `rules/override_test.go` / `dlp/override_test.go`
verify the loader-lock interaction, platform-isolated tamper probes
(via build tags), the heartbeat payload shape (assertion: no access /
domain / IP / DLP-match fields ever leak), and admin override
merging without corrupting bundled rules. Performance benchmarks
for the DLP pipeline, DNS resolver, and stats counter live in
`*_bench_test.go` files — see [BENCHMARKS.md](./BENCHMARKS.md).

## DLP Coverage

Secure Edge ships **139** real-world detection patterns across **20**
categories: cloud providers (AWS, Azure, GCP, Google Services),
cloud infrastructure (Cloudflare, DigitalOcean, Vercel, Netlify,
Supabase, Pulumi, Helm, Terraform, Docker, K8s), version control
(GitHub, GitLab, Bitbucket), AI/ML platforms (OpenAI, Anthropic,
HuggingFace, Cohere, Replicate, Pinecone, Mistral, W&B, LangSmith,
Together, Groq), payment processors (Stripe, PayPal, Square,
Braintree, Adyen, Plaid, Coinbase), CI/CD (CircleCI, Travis,
Jenkins), messaging (Slack, Discord, Telegram, Twilio, SendGrid,
Vonage, Mailchimp), auth/identity (Auth0, Okta, OneLogin, Keycloak,
Firebase Admin, Supabase JWT, Clerk), language ecosystems (Java,
Rust, JS/TS, Swift, Kotlin, Dart, Go, Python), mobile (iOS APNs,
Android signing, Flutter / React Native), databases (Postgres,
MySQL, MongoDB, Redis, MSSQL, SQLite, Cassandra, Elasticsearch),
PEM/private keys, JWTs, generic password-in-code, and PII (SSN,
credit cards, emails, phones).

See [SECURITY_RULES.md](./SECURITY_RULES.md) for the complete per-pattern
table (name, severity, prefix, hotword requirement).

## Documentation

- [PROPOSAL.md](./PROPOSAL.md) — scope, privacy model, layered DLP overview
- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, DB schema, API, integration
- [PHASES.md](./PHASES.md) — phased implementation plan
- [PROGRESS.md](./PROGRESS.md) — per-item progress tracker
- [CHANGELOG.md](./CHANGELOG.md) — release-by-release summary
- [CONTRIBUTING.md](./CONTRIBUTING.md) — development setup, PR process, coding standards
- [SECURITY.md](./SECURITY.md) — responsible-disclosure policy
- [BENCHMARKS.md](./BENCHMARKS.md) — DLP pipeline, DNS resolver, and stats counter benchmarks
- [SECURITY_RULES.md](./SECURITY_RULES.md) — per-pattern reference table
- [docs/admin-guide.md](./docs/admin-guide.md) — installation, configuration, profiles, overrides
- [docs/user-guide.md](./docs/user-guide.md) — what the tray icon means, false-positive reporting, privacy summary
- [docs/rule-contribution-guide.md](./docs/rule-contribution-guide.md) — how to add domains and categories
- [docs/dlp-pattern-authoring-guide.md](./docs/dlp-pattern-authoring-guide.md) — DLP schema, scoring, hotwords, entropy, exclusions
- [docs/accessibility.md](./docs/accessibility.md) — Electron UI accessibility audit + verification steps

## Contributing

Contributions are welcome under the MIT license. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for development setup, the PR process, coding standards, and test requirements.

Good first contributions:

- **Rule lists** — add domains (one per line, leading `.` for "include subdomains") to
  `rules/*.txt`.
- **DLP patterns / exclusions** — `rules/dlp_patterns.json`, `rules/dlp_exclusions.json`.
- **Bug reports** — use the GitHub Issues template at
  [`.github/ISSUE_TEMPLATE/bug_report.md`](./.github/ISSUE_TEMPLATE/bug_report.md).

Report security vulnerabilities via the process in [SECURITY.md](./SECURITY.md) — please
do not file public issues for security reports.

## License

[MIT](./LICENSE) — Copyright (c) 2026 [ShieldNet 360](https://www.shieldnet360.com)
