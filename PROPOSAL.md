# ShieldNet Secure Edge — Project Proposal

## Problem Statement

Employees routinely paste proprietary source code, API keys, customer data, and internal documents
into AI chatbots (ChatGPT, DeepSeek, Claude, Gemini, etc.). Small and medium businesses lack
affordable tools to prevent this — enterprise DLP solutions cost $20-50/user/month and require
complex infrastructure.

At the same time, employees have a reasonable expectation of privacy. Logging every domain they
visit creates a surveillance tool, not a security tool. A data leakage prevention agent should
prevent leakage without creating a browsing history that could itself be leaked.

## Proposed Solution

An open-source, cross-platform desktop agent that:

1. **Blocks** unauthorized AI tools at the DNS level (zero latency overhead for allowed traffic)
2. **Inspects** content sent to approved AI tools via browser extension (and optionally via local proxy)
3. **Shows real-time block notifications** that are immediately discarded (never written to disk)
4. **Updates** rule lists from a central server or runs fully offline with bundled rules
5. **Logs nothing** about what the user accesses — only anonymous aggregate counters

## Privacy Design

### What IS stored locally
- Policy configuration (which categories are allowed/blocked)
- Anonymous aggregate counters: `dns_blocks_total`, `dlp_blocks_total`, `dns_queries_total` (integers only, no timestamps, no domains)
- Rule files (domain lists, DLP patterns)
- Agent configuration (upstream DNS, ports, rule update URL)

### What is NEVER stored locally
- Domain names or URLs accessed by the user
- IP addresses (source or destination)
- Timestamps associated with any access event
- User identifiers associated with access events
- Request/response content
- DLP-matched content (shown in notification, then discarded)

### Privacy guarantee
Even if an attacker gains full disk access to a Secure Edge device, they cannot reconstruct
any browsing history or access patterns from the agent's data. The only observable data is
"this device has blocked N requests total" with no way to determine what, when, or who.

## Target Users

- Small/medium companies (10-500 employees) without enterprise security budgets
- IT administrators who need basic AI usage governance without employee surveillance
- Privacy-conscious organizations adopting AI tools incrementally

## Policy Tiers

| Tier | Action | Example | Mechanism |
|------|--------|---------|-----------|
| 1 | Allow | `azure.openai.com` (enterprise endpoint) | Pass-through |
| 2 | Allow + DLP Inspect | `chat.openai.com`, `claude.ai` | Browser extension scans paste/submit; optional MITM proxy for API calls |
| 3 | Block (AI) | `deepseek.com`, `poe.com` | DNS returns NXDOMAIN |
| 4 | Block (Other) | Phishing, gambling, social media | DNS returns NXDOMAIN |

## What We Reuse from ShieldNet Gateway

### Reusable Assets

| Asset | ShieldNet Source | Secure Edge Usage |
|-------|-----------------|-------------------|
| Rule file format | `/etc/squid/categories/*.txt` — one domain per line | Identical format, stored locally |
| Rule types | `dstdomain`, `dst`, `src`, `url_regex`, etc. | Same taxonomy; `dstdomain` covers ~90% of use cases |
| `WebfilteringRuleset` model | `internal/model/webfiltering_ruleset.go` — GORM model with Name, RuleType, FilePath, Category | Mapped to SQLite schema |
| `RulesetConfig` | Proto message with `ruleset_uuid`, `category`, `enabled` | Extended to three-state: `allow`, `allow_with_dlp`, `deny` |
| `NetworkWebfilteringRuleset` | M:N join model in `internal/model/network_webfiltering_ruleset.go` | Adapted as device-to-profile assignment |
| `PoliciesPage` UI | `src/pages/App/policies/PoliciesPage.tsx` — per-category Switch toggles | Adapted to three-option selector per category |
| `IDSPolicy` hierarchy | `src/api/services/policies.ts` — `IDSPolicy` → `IDSPolicyCategory` → `IDSPolicyRuleset` | Adapted for local policy tree |

### What Is NOT Reused

| Discarded Asset | Reason |
|----------------|--------|
| `WebFilteringAlertEvent` logging | **Privacy** — we do not log access events |
| `SecurityReportsPage` alert tables | **Privacy** — replaced with anonymous aggregate stats |
| Squid proxy management via SSH/SFTP | Replaced by in-process `goproxy` |
| `iptables` NAT rules, `ip route` commands | Not applicable to desktop agent |
| PostgreSQL / Redis | Replaced by local SQLite |
| gRPC server, `internal/service/` layer | Replaced by local HTTP API |

## Extended Policy Model

ShieldNet's `RulesetConfig` only supports `enabled: bool`. Secure Edge extends this to a
three-state action model:

```go
type CategoryPolicy struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Category    string   `json:"category"`       // "AI Chat", "AI Code", "Phishing", etc.
    Action      string   `json:"action"`          // "allow", "allow_with_dlp", "deny"
    RuleType    string   `json:"rule_type"`       // from ShieldNet: "dstdomain", "dst", "url_regex"
    RuleFile    string   `json:"rule_file"`       // "ai_chat.txt"
    DLPPatterns []string `json:"dlp_patterns"`    // regex patterns, only for "allow_with_dlp"
}
```

## Lightweight Design Goals

| Metric | Target | Approach |
|--------|--------|----------|
| Idle memory | < 50 MB total | Go agent ~15 MB + Electron tray hidden ~35 MB |
| Idle CPU | < 0.1% | DNS server event-driven; no polling loops |
| Disk footprint | < 100 MB installed | Single Go binary (~10 MB) + Electron app (~80 MB) + rules (~1 MB) |
| Startup time | < 2 seconds | Go binary starts instantly; Electron tray deferred |
| Network overhead | Near zero | DNS interception is local; rule updates are periodic small HTTP GETs |
| Data at rest | Minimal | No access logs = tiny SQLite DB (config + counters only) |

## Electron Tray App (Minimal Shell)

The Electron app serves exclusively as a **system tray icon + settings window**. It does NOT run
the core logic. Design choices for minimal resource usage:

- **No visible window on startup** — Electron starts hidden, only showing the tray icon
- **Single BrowserWindow** — opened on-demand when user clicks tray → "Settings"
- **IPC to Go agent** — Electron communicates with the Go backend via local HTTP (`127.0.0.1:PORT`)
- **No Chromium rendering when hidden** — the BrowserWindow is destroyed (not hidden) when closed
- **Bundled with `electron-builder`** — produces native installers for all three platforms

## Scope Boundaries

### What This Delivers
- Block employees from accessing unapproved AI chatbots
- Allow approved enterprise AI endpoints
- Detect and block paste of source code, API keys, customer data into AI tools via browser
- Block known phishing/malware domains
- Real-time block notifications (ephemeral, never persisted)
- Anonymous usage stats (total blocks count only)

### What This Does NOT Deliver
- Detailed access logs or browsing history (by design — privacy)
- Per-user or per-domain reporting (by design — privacy)
- Protection against determined technical users who change DNS/proxy settings (needs MDM)
- Content inspection of non-browser AI clients without the optional MITM proxy
- Protection against AI features embedded in allowed SaaS tools (Notion AI, Slack AI)
- File-level DLP (scanning files before upload)
- Mobile device support

## Open Source Strategy

- **License:** MIT
- **Rule lists:** Community-maintained in this repository, accepting PRs
- **Distribution:** GitHub Releases with auto-update via `electron-updater`
- **Server component:** None required. Optional static file hosting for enterprise rule distribution.
