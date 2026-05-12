# ShieldNet Secure Edge

**Open-source, privacy-first AI Data Leakage Prevention for desktop.**

ShieldNet Secure Edge is a cross-platform desktop agent (Windows, macOS, Linux) that prevents
corporate data leakage to unauthorized AI tools. It runs as a minimal system tray application,
consuming negligible CPU and memory, and connects to a server only to download updated rule lists —
or operates entirely offline using bundled open-source rules.

## Privacy First

**Secure Edge does not log what you access.** There is no browsing history, no domain log, no URL
tracking, and no alert event database on the local machine. The agent stores only:

- **Policy configuration** — which categories are allowed, inspected, or blocked
- **Anonymous aggregate counters** — e.g., "12 DNS blocks today", "3 DLP blocks this week"
- **Rule files** — domain lists and DLP patterns

No domain names, URLs, IP addresses, timestamps, or user identifiers are ever written to disk
in association with any access event. DLP block notifications are shown in real-time and then
discarded. This design ensures that even if the device is compromised, there is no browsing
activity to exfiltrate.

## License

MIT — see [LICENSE](./LICENSE).

## What It Does

| Tier | Policy | Mechanism |
|------|--------|-----------|
| 1 | **Allowed AI tools** | Pass-through, no inspection |
| 2 | **Allowed AI tools + DLP** | Allow but block if sensitive data detected (browser extension + optional MITM proxy) |
| 3 | **Blocked AI tools** | Deny at DNS level |
| 4 | **Blocked other categories** | Deny phishing, gambling, social media, etc. at DNS level |

## Design Principles

- **Zero logging** — no browsing history, no domain access logs, no identifiable event data stored locally
- **Lightweight first** — idle memory target < 50 MB (Go agent ~15 MB + Electron tray ~35 MB). CPU near 0% when idle.
- **System tray native** — runs in the status bar on Windows, macOS, and Linux. No visible window unless the user opens settings.
- **Offline-capable** — ships with bundled rule files from this repository. Server sync is optional.
- **Minimal privileges** — DNS blocking requires one-time admin setup; day-to-day operation runs in user space.

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  Desktop Agent                       │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Electron Tray│  │  Go Backend  │  │  Browser   │ │
│  │  (UI shell)  │◄─┤  (core svc)  │  │ Extension  │ │
│  └──────────────┘  │              │  └─────┬──────┘ │
│                    │  DNS Resolver│        │         │
│                    │  Policy Eng. │◄───────┘         │
│                    │  SQLite      │  Native Messaging │
│                    │  (config     │                   │
│                    │   only, no   │                   │
│                    │   access log)│                   │
│                    │  Rule Updater│                   │
│                    └──────┬───────┘                   │
│                           │                          │
│                    ┌──────▼───────┐                   │
│                    │  Local Rules │                   │
│                    │  (.txt files)│                   │
│                    └──────────────┘                   │
└─────────────────────────────────────────────────────┘
         │ (optional HTTPS GET)
         ▼
  ┌──────────────────┐
  │  Rule CDN /      │
  │  GitHub Releases │
  └──────────────────┘
```

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Core Agent | Go 1.22+ | Single static binary, low memory, cross-compiles |
| DNS Resolver | `github.com/miekg/dns` | Mature, lightweight embedded DNS |
| SQLite | `modernc.org/sqlite` | Pure Go, no CGO dependency |
| System Tray UI | Electron (minimal) | Cross-platform tray + webview for settings panel |
| Browser Extension | TypeScript, Manifest V3 | Chrome + Firefox DLP content inspection |
| MITM Proxy (opt-in) | `github.com/elazarl/goproxy` | Tier 2 non-browser traffic |
| Installer | `goreleaser` + `nfpm` (deb/rpm), `pkgbuild` (macOS), WiX (Windows) | Standard per-platform |

## Reused from ShieldNet Gateway

This project reuses **data models and UI patterns** from the ShieldNet Gateway project while
discarding the server infrastructure (Squid, SSH/SFTP, iptables, PostgreSQL, gRPC).

- **Rule file format** — one-entry-per-line text files (e.g., `.facebook.com`, `.deepseek.com`)
- **Rule types** — `dstdomain`, `dst`, `src`, `url_regex`, `dstdom_regex`, `urlpath_regex`
- **Data model** — `WebfilteringRuleset` (name, rule_type, file_path, category) mapped to local SQLite
- **Policy toggle UI** — `PoliciesPage` with per-category switches, adapted to three-state selector
- **Network-to-ruleset assignment** — `NetworkWebfilteringRuleset` M:N model adapted to device-to-ruleset

**Explicitly NOT reused (privacy):**
- `WebFilteringAlertEvent` logging model — we do not log access events
- `SecurityReportsPage` detailed alert tables — replaced with anonymous aggregate stats only

## Rule Distribution

Rules can be loaded from two sources:

1. **Local (default)** — bundled `.txt` rule files shipped with the installer and stored in this repo
2. **Server (optional)** — agent polls a static `manifest.json` from GitHub Releases or a CDN

```
rules/
├── manifest.json
├── ai_chat_blocked.txt
├── ai_chat_dlp.txt
├── ai_code_blocked.txt
├── ai_allowed.txt
├── phishing.txt
├── social.txt
├── news.txt
└── dlp_patterns.json
```

## Quick Start

> **Note:** Not yet implemented. See [PROGRESS.md](./PROGRESS.md) for current status.

```bash
# Clone
git clone https://github.com/kennguy3n/secure-edge.git
cd secure-edge

# Build Go agent
cd agent && go build -o secure-edge ./cmd/agent

# Build Electron tray
cd ../electron && npm install && npm run build

# Run
./secure-edge --config config.yaml
```

## Documentation

- [PROPOSAL.md](./PROPOSAL.md) — Project proposal and scope
- [ARCHITECTURE.md](./ARCHITECTURE.md) — Detailed technical architecture
- [PHASES.md](./PHASES.md) — Implementation phases and milestones
- [PROGRESS.md](./PROGRESS.md) — Current progress tracker

## Contributing

Contributions welcome under the MIT license. Please read the docs above before submitting PRs.
