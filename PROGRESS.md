# ShieldNet Secure Edge — Progress Tracker

> Last updated: 2026-05-12

## Overall Status

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1: DNS Blocking + Electron Tray | Not Started | 0% |
| Phase 2: Browser Extension + DLP | Not Started | 0% |
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
- [ ] Database migrations (rulesets, category_policies, aggregate_stats — NO alert_events)
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

## Repository Structure (Planned)

```
secure-edge/
├── README.md
├── PROPOSAL.md
├── ARCHITECTURE.md
├── PHASES.md
├── PROGRESS.md
├── LICENSE
├── agent/                    # Go backend
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go
│   ├── internal/
│   │   ├── config/           # YAML configuration loader
│   │   ├── dns/              # Embedded DNS resolver
│   │   ├── policy/           # Policy engine
│   │   ├── store/            # SQLite: policies + counters (NO access logs)
│   │   ├── api/              # HTTP API handlers
│   │   ├── rules/            # Rule file parser and updater
│   │   ├── stats/            # Anonymous aggregate counter system
│   │   └── dlp/              # DLP pattern scanner (Phase 2)
│   ├── go.mod
│   └── go.sum
├── electron/                 # Electron tray app
│   ├── main.ts
│   ├── preload.ts
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Settings.tsx  # Policy toggles
│   │   │   └── Status.tsx    # Agent health + anonymous stats
│   │   ├── components/
│   │   │   ├── CategoryToggle.tsx
│   │   │   └── StatsCard.tsx
│   │   └── api/
│   │       └── agent.ts
│   ├── package.json
│   └── electron-builder.yml
├── extension/                # Browser extension (Phase 2)
│   ├── manifest.json
│   ├── src/
│   │   ├── content/          # Content scripts for AI tool pages
│   │   ├── background/       # Service worker
│   │   └── popup/            # Extension popup UI
│   ├── package.json
│   └── tsconfig.json
├── rules/                    # Bundled rule files
│   ├── manifest.json
│   ├── ai_chat_blocked.txt
│   ├── ai_chat_dlp.txt
│   ├── ai_code_blocked.txt
│   ├── ai_allowed.txt
│   ├── phishing.txt
│   ├── social.txt
│   ├── news.txt
│   └── dlp_patterns.json
├── scripts/                  # Platform setup scripts
│   ├── macos/
│   ├── windows/
│   └── linux/
└── .github/
    └── workflows/
        └── build.yml
```

## Changelog

### 2026-05-12
- Repository initialized with MIT license
- Project documentation created (README, PROPOSAL, ARCHITECTURE, PHASES, PROGRESS)
- Privacy-first design: zero access logging, anonymous aggregate counters only
