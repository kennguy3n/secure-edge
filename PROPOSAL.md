# ShieldNet Secure Edge — Project Proposal

## Problem Statement

Employees routinely paste proprietary source code, API keys, customer data, and internal documents
into AI chatbots (ChatGPT, DeepSeek, Claude, Gemini, etc.). Small and medium businesses lack
affordable tools to prevent this — enterprise DLP solutions cost $20-50/user/month and require
complex infrastructure.

At the same time, employees have a reasonable expectation of privacy. Logging every domain they
visit creates a surveillance tool, not a security tool. A data leakage prevention agent should
prevent leakage without creating a browsing history that could itself be leaked.

Furthermore, naive regex-based DLP produces unacceptable false positive rates, training employees
to ignore warnings and bypass the tool entirely. Accurate DLP on constrained devices requires a
multi-layered approach — not ML models that consume gigabytes of RAM, but clever composition of
lightweight techniques.

## Proposed Solution

An open-source, cross-platform desktop agent that:

1. **Blocks** unauthorized AI tools at the DNS level (zero latency overhead for allowed traffic)
2. **Inspects** content sent to approved AI tools via a layered DLP pipeline (hotword context, scoring, exclusions, entropy, Aho-Corasick) — running entirely in-memory on-device
3. **Shows real-time block notifications** that are immediately discarded (never written to disk)
4. **Updates** rule lists AND DLP patterns from a central server or runs fully offline with bundled rules
5. **Logs nothing** about what the user accesses — only anonymous aggregate counters

## Privacy Design

### What IS stored locally
- Policy configuration (which categories are allowed/blocked)
- Anonymous aggregate counters: `dns_blocks_total`, `dlp_blocks_total`, `dns_queries_total` (integers only, no timestamps, no domains)
- Rule files (domain lists, DLP patterns, DLP exclusions)
- Agent configuration (upstream DNS, ports, rule update URL)

### What is NEVER stored locally
- Domain names or URLs accessed by the user
- IP addresses (source or destination)
- Timestamps associated with any access event
- User identifiers associated with access events
- Request/response content
- DLP-matched content (shown in notification, then discarded)
- DLP scan results or match details

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
| 2 | Allow + DLP Inspect | `chat.openai.com`, `claude.ai` | Layered DLP pipeline via browser extension; optional MITM proxy for API calls |
| 3 | Block (AI) | `deepseek.com`, `poe.com` | DNS returns NXDOMAIN |
| 4 | Block (Other) | Phishing, gambling, social media | DNS returns NXDOMAIN |

## DLP Accuracy Strategy

### The Problem with Naive Regex

A flat regex like `AKIA[0-9A-Z]{16}` for AWS keys will match random alphanumeric strings,
test fixtures, documentation examples, and actual credentials with equal confidence. This
produces false positive rates of 30-50% in practice, making users distrust and bypass the tool.

### The Solution: Layered Pipeline

Secure Edge uses 7 complementary techniques, each adding negligible cost:

| Strategy | What It Does | Resource Cost |
|----------|-------------|---------------|
| **Content Classification** | Classify paste as code/data/credentials/natural language; apply different pattern subsets | < 10 μs |
| **Aho-Corasick Prefix Scan** | Single-pass O(n) scan for fixed prefixes (AKIA, ghp_, sk-) instead of running all regexes | ~100 KB memory |
| **Full Regex on Candidates** | Only validate candidates from Aho-Corasick, not entire content | Reduced by 80%+ |
| **Hotword Context** | Boost confidence when proximity keywords exist (e.g., "aws" near "AKIA...") | ~free |
| **Entropy Checking** | Shannon entropy validates randomness of secret candidates | O(n) arithmetic |
| **Exclusion Rules** | Suppress matches near "example", "test", "placeholder", etc. | Hash set lookup |
| **Multi-Signal Scoring** | Combine signals into score; block only above threshold per severity | Arithmetic |

**Total overhead:** ~200 KB memory, < 1 ms per scan. All in-memory, all content discarded after.

These techniques are modeled after Google Cloud DLP's production patterns — `HotwordRule`,
`ExclusionRule`, and `InspectConfig.InfoTypeLikelihood` — adapted for fully local execution.

### Community-Updatable Accuracy

DLP patterns (`dlp_patterns.json`) and exclusions (`dlp_exclusions.json`) are distributed via
the same rule update mechanism as domain lists. This means:
- False positive reports → exclusion rules added within hours via rule update
- New secret formats → patterns added without agent binary update
- Community PRs improve accuracy for all users

## Policy Model

Categories are mapped to a three-state action model so the same rule file (e.g., AI chat
domains) can be either allowed, allowed-with-DLP, or denied per deployment:

```go
type CategoryPolicy struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Category    string   `json:"category"`       // "AI Chat", "AI Code", "Phishing", etc.
    Action      string   `json:"action"`          // "allow", "allow_with_dlp", "deny"
    RuleType    string   `json:"rule_type"`       // "dstdomain", "dst", "url_regex"
    RuleFile    string   `json:"rule_file"`       // "ai_chat.txt"
    DLPProfile  string   `json:"dlp_profile"`     // references DLP pattern/exclusion config
}
```

Rule files use a simple one-entry-per-line text format (e.g., `.chat.openai.com`,
`.deepseek.com`). Supported rule types: `dstdomain`, `dst`, `src`, `url_regex`,
`dstdom_regex`, `urlpath_regex` — `dstdomain` covers ~90% of practical use cases.

## Lightweight Design Goals

| Metric | Target | Approach |
|--------|--------|----------|
| Idle memory | < 50 MB total | Go agent ~15 MB + Electron tray hidden ~35 MB |
| DLP pipeline memory | < 200 KB additional | Aho-Corasick automaton ~100 KB + exclusion hash sets ~100 KB |
| Idle CPU | < 0.1% | DNS server event-driven; no polling loops |
| DLP scan latency | < 1 ms per scan | Aho-Corasick + candidate-only regex + scoring |
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
- Detect and block paste of source code, API keys, customer data into AI tools via browser — with high accuracy through layered DLP
- Block known phishing/malware domains
- Real-time block notifications (ephemeral, never persisted)
- Anonymous usage stats (total blocks count only)
- Community-updatable DLP patterns and exclusions for continuous accuracy improvement

### What This Does NOT Deliver
- Detailed access logs or browsing history (by design — privacy)
- Per-user or per-domain reporting (by design — privacy)
- Protection against determined technical users who change DNS/proxy settings (needs MDM)
- Content inspection of non-browser AI clients without the optional MITM proxy
- Protection against AI features embedded in allowed SaaS tools (Notion AI, Slack AI)
- File-level DLP (scanning files before upload)
- Mobile device support
- ML-based content classification (too heavy for desktop agent constraints)

## Open Source Strategy

- **License:** MIT
- **Rule lists:** Community-maintained in this repository, accepting PRs
- **DLP patterns + exclusions:** Community-maintained, updated via rule distribution
- **Distribution:** GitHub Releases with auto-update via `electron-updater`
- **Server component:** None required. Optional static file hosting for enterprise rule distribution.
