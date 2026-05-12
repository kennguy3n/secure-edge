# ShieldNet Secure Edge — Technical Architecture

## System Overview

```mermaid
graph TD
    subgraph "Desktop Agent"
        A["Electron Tray App"] -->|"HTTP localhost"| B["Go Backend Service"]
        B --> C["Policy Engine"]
        C --> D["SQLite Database\n(config + counters only)"]
        C --> E["Rule Updater"]
        E -->|"HTTPS GET"| F["GitHub Releases / CDN"]
        E -->|"or"| G["Local Rule Files"]
    end

    subgraph "Layer 1 - DNS Blocking"
        H["Embedded DNS Resolver"] --> C
        C -->|"NXDOMAIN for Tier 3+4"| H
        C -->|"Forward for Tier 1+2"| H
    end

    subgraph "Layer 2 - DLP Inspection"
        I["Browser Extension"] -->|"Native Messaging"| B
        B -->|"Layered DLP Pipeline"| J["DLP Scanner"]
        J -->|"score above threshold"| K["Block + Ephemeral Notification"]
        J -->|"score below threshold"| L["Allow"]
    end

    subgraph "Layer 3 - MITM Proxy - optional"
        M["Local MITM Proxy\ngoproxy"] --> C
        C -->|"inspect request body"| J
    end
```

## Privacy Architecture

### Data Flow Principle: Process, Don't Persist

Every access event (DNS query, HTTP request, DLP scan) follows this flow:

```mermaid
flowchart LR
    A["Incoming\nrequest"] --> B{"Policy\ncheck"}
    B -->|"allow"| C["Forward\n(no trace)"]
    B -->|"block"| D["Block +\nIncrement counter"]
    B -->|"dlp scan"| E{"Layered\nDLP pipeline"}
    E -->|"score below\nthreshold"| C
    E -->|"score above\nthreshold"| F["Block +\nShow notification +\nIncrement counter"]
    D --> G["Counter: dns_blocks++\n(no domain stored)"]
    F --> H["Counter: dlp_blocks++\n(no content stored)"]
```

**Key invariant:** At no point in the data flow is a domain name, URL, IP address, or request content written to any persistent storage (disk, database, log file). Counters are bare integers. DLP scan content is processed in-memory and garbage-collected immediately after the response is sent.

### What Gets Stored (Exhaustive List)

```
SQLite Database (~4 KB):
├── category_policies     # category → action mapping (e.g., "AI Chat" → "deny")
├── rulesets              # rule file metadata (name, type, path, category)
├── aggregate_stats       # dns_blocks_total: 142, dlp_blocks_total: 7, dns_queries_total: 50321
└── rule_versions         # manifest version string for update tracking

Rule Files (~500 KB):
├── ai_chat_blocked.txt   # domain lists (these are the RULES, not access logs)
├── phishing.txt
├── dlp_patterns.json     # DLP patterns with hotwords, entropy thresholds, scoring weights
└── dlp_exclusions.json   # exclusion rules to suppress false positives

Config File (~1 KB):
└── config.yaml           # upstream DNS, ports, update URL
```

**There is no `alert_events` table. There is no log file. There is no access history.**

## Component Details

### 1. Go Backend Service

The core of the agent. A single statically-compiled Go binary providing:

| Subsystem | Library | Purpose |
|-----------|---------|---------|
| DNS Resolver | `github.com/miekg/dns` | Listens on `127.0.0.1:53`, resolves queries against policy engine |
| HTTP API | `net/http` (stdlib) | Local REST API on `127.0.0.1:{PORT}` for Electron UI and browser extension |
| SQLite Store | `modernc.org/sqlite` | Pure Go SQLite — stores policies, counters, rule metadata. No CGO. No access logs. |
| DLP Pipeline | In-process (see below) | Layered scanner: Aho-Corasick + regex + hotwords + entropy + exclusions + scoring |
| Rule Updater | `net/http` (stdlib) | Polls `manifest.json` for rule version, downloads changed files |
| MITM Proxy | `github.com/elazarl/goproxy` | Optional. Local proxy for Tier 2 non-browser inspection |
| CA Generator | `crypto/x509` (stdlib) | Optional. Generates per-device Root CA for MITM proxy |

**Memory profile:** ~15 MB RSS at idle + ~200 KB for DLP automaton and exclusion sets. DNS server is event-driven (goroutine-per-request, no pre-allocated pools). SQLite WAL mode for minimal lock contention.

**Logging policy:** The Go binary writes operational logs to stderr (startup, errors, config changes). It NEVER logs domain names, URLs, IP addresses, or DLP match content from user traffic. Log level is configurable; in production, only errors are logged.

### 2. Layered DLP Pipeline

The DLP scanner is the core accuracy component. Instead of running all regex patterns against all
content (O(n × p) for n content length and p patterns), it uses a multi-stage pipeline:

```mermaid
flowchart TD
    A["Content arrives\n(paste/submit/fetch)"] --> B["Step 1: Content Classification\n< 10 μs"]
    B --> C["Step 2: Aho-Corasick\nPrefix Scan\nO(n) single pass"]
    C --> D["Step 3: Regex\nValidation\n(candidates only)"]
    D --> E["Step 4: Per-Match Scoring"]
    E --> F{"Step 5:\nScore ≥ threshold?"}
    F -->|"Yes"| G["Block + Notification\n+ Counter++"]
    F -->|"No"| H["Allow"]
    G --> I["Content discarded\nfrom memory"]
    H --> I
```

#### Step 1: Content Type Classification

Fast heuristic classification (< 10 μs) to select the appropriate pattern subset:

| Content Type | Detection Heuristic | Pattern Set |
|-------------|-------------------|-------------|
| Source code | Lines starting with `import`, `function`, `def`, `class`, `const`, `#include` | Internal URLs, env vars, private function names, API keys |
| Structured data | Contains `{`+`}` or consistent CSV delimiters | PII fields, database connection strings |
| Credentials block | Key-value pairs with `=` or `:` | API keys, tokens, passwords |
| Natural language | High space ratio, low symbol density | SSN, phone numbers, bulk email addresses |

**Benefit:** Reduces the active pattern set by 60-70%, both improving speed and reducing false positives from mismatched pattern types.

#### Step 2: Aho-Corasick Multi-Pattern Scan

Instead of running 20+ regexes sequentially, extract the fixed-string prefixes from all patterns
and build an Aho-Corasick automaton at rule load time:

```
Prefixes: "AKIA", "ghp_", "gho_", "sk-", "-----BEGIN", "xox", "eyJ", ...
```

Single-pass scan of content → candidate locations in O(n). Only candidates proceed to Step 3.

**Cost:** ~100 KB memory for automaton (100 patterns). Built once at rule load (~1 ms).

#### Step 3: Regex Validation

Full regex runs only on the candidate substrings identified by Aho-Corasick, not on the entire
content. This reduces regex work by 80%+ for typical content.

#### Step 4: Per-Match Scoring

Each validated match receives a score from multiple signals:

| Signal | Score | Description |
|--------|-------|-------------|
| Regex match | +1 (base) | Pattern matched |
| Hotword proximity | +2 | Context keyword within N characters (e.g., "aws" near AKIA match) |
| High entropy (>4.0) | +1 | Shannon entropy indicates randomness (likely real secret) |
| Low entropy (<3.0) | -2 | Low randomness suggests placeholder/example |
| Multiple matches | +1 each | Bulk data indicator (e.g., 10 email addresses) |
| Structured format | +1 | Match is inside a key-value or JSON structure |
| Exclusion word nearby | -3 | "example", "test", "placeholder", "dummy", "sample" nearby |
| Known false positive | -5 | Match is in exclusion dictionary |

#### Step 5: Threshold Decision

Each severity level has a configurable threshold:

```json
{
  "thresholds": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4
  }
}
```

A "critical" pattern (like an AWS secret key) blocks with just a base match. A "medium" pattern
(like email addresses) requires additional corroboration (multiple matches, hotword, structured format).

#### DLP Pattern Format (Extended)

```json
{
  "patterns": [
    {
      "name": "AWS Access Key",
      "regex": "AKIA[0-9A-Z]{16}",
      "prefix": "AKIA",
      "severity": "critical",
      "hotwords": ["aws", "access_key", "credentials", "iam", "secret"],
      "hotword_window": 200,
      "entropy_min": 3.5
    },
    {
      "name": "Generic API Key",
      "regex": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}",
      "prefix": "api",
      "severity": "high",
      "hotwords": [],
      "hotword_window": 0,
      "entropy_min": 0
    },
    {
      "name": "Email Addresses (bulk)",
      "regex": "([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+)",
      "prefix": "@",
      "severity": "medium",
      "min_matches": 5,
      "hotwords": ["email", "contact", "user", "customer"],
      "hotword_window": 500,
      "entropy_min": 0
    },
    {
      "name": "GitHub Personal Access Token",
      "regex": "ghp_[A-Za-z0-9_]{36}",
      "prefix": "ghp_",
      "severity": "critical",
      "hotwords": ["github", "token", "auth"],
      "hotword_window": 200,
      "entropy_min": 4.0
    },
    {
      "name": "Private Key Block",
      "regex": "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
      "prefix": "-----BEGIN",
      "severity": "critical",
      "hotwords": [],
      "hotword_window": 0,
      "entropy_min": 0
    }
  ]
}
```

#### DLP Exclusion Format

```json
{
  "exclusions": [
    {
      "applies_to": "Email Addresses (bulk)",
      "type": "regex",
      "pattern": "@(example\\.com|test\\.com|localhost|mailinator\\.com)"
    },
    {
      "applies_to": "*",
      "type": "dictionary",
      "words": ["placeholder", "example", "test", "dummy", "sample", "xxx", "your-", "CHANGEME"],
      "window": 50
    },
    {
      "applies_to": "AWS Access Key",
      "type": "dictionary",
      "words": ["AKIAIOSFODNN7EXAMPLE"],
      "match_type": "exact"
    }
  ]
}
```

Community can contribute exclusions via PR to reduce false positives without modifying core patterns.

### 3. Electron Tray Application

Minimal Electron shell for system tray presence and settings UI.

```
electron/
├── main.ts              # Main process: tray icon, IPC, window management
├── preload.ts           # Secure bridge to renderer
├── src/
│   ├── pages/
│   │   ├── Settings.tsx       # Policy toggles (adapted from PoliciesPage)
│   │   └── Status.tsx         # Agent health + anonymous aggregate stats
│   ├── components/
│   │   ├── CategoryToggle.tsx # Three-state: Allow / Allow+Inspect / Block
│   │   └── StatsCard.tsx      # Display aggregate counters
│   └── api/
│       └── agent.ts           # HTTP client to Go backend on localhost
├── package.json
└── electron-builder.yml
```

**Resource strategy:**
- Tray icon created immediately (near-zero overhead)
- `BrowserWindow` created only when user clicks "Open Settings"
- Window is **destroyed** (not hidden) on close to free Chromium memory
- No background renderer processes when window is closed
- Estimated overhead: ~35 MB when window is open, ~5 MB tray-only

**No Reports page.** Since we don't log access events, there is no detailed reports page.
The Status page shows only anonymous counters: "Total blocks: 142 | DLP blocks: 7 | Uptime: 3d 14h".

### 4. Browser Extension (Chrome + Firefox)

TypeScript extension using Manifest V3 (Chrome) and WebExtensions (Firefox).

**Capabilities:**
- Content script injected into Tier 2 AI tool domains only
- Intercepts: `paste` events, form `submit`, `fetch`/`XMLHttpRequest` calls
- Sends content to Go agent's DLP pipeline via Chrome Native Messaging API
- Shows ephemeral notification on block (pattern name only, not matched content)

**Privacy:** The extension does not store any history of scanned content. When the DLP pipeline
blocks content, the notification displays the pattern name (e.g., "AWS Access Key detected") but
does NOT include the actual key or matched content. After the user dismisses the notification, no
trace remains.

### 5. SQLite Database Schema

```sql
-- Rule file metadata (adapted from WebfilteringRuleset model)
CREATE TABLE rulesets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid        TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    rule_type   TEXT NOT NULL DEFAULT 'dstdomain',
    file_path   TEXT NOT NULL,
    category    TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Policy configuration (extended from RulesetConfig bool → three-state)
CREATE TABLE category_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT UNIQUE NOT NULL,
    action      TEXT NOT NULL DEFAULT 'deny',  -- 'allow', 'allow_with_dlp', 'deny'
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Anonymous aggregate counters (NO domain, NO IP, NO timestamp per event)
CREATE TABLE aggregate_stats (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    dns_queries_total   INTEGER NOT NULL DEFAULT 0,
    dns_blocks_total    INTEGER NOT NULL DEFAULT 0,
    dlp_scans_total     INTEGER NOT NULL DEFAULT 0,
    dlp_blocks_total    INTEGER NOT NULL DEFAULT 0,
    last_reset_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Rule update tracking
CREATE TABLE rule_versions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_version TEXT NOT NULL,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- DLP scoring configuration
CREATE TABLE dlp_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    threshold_critical      INTEGER NOT NULL DEFAULT 1,
    threshold_high          INTEGER NOT NULL DEFAULT 2,
    threshold_medium        INTEGER NOT NULL DEFAULT 3,
    threshold_low           INTEGER NOT NULL DEFAULT 4,
    hotword_boost           INTEGER NOT NULL DEFAULT 2,
    entropy_boost           INTEGER NOT NULL DEFAULT 1,
    entropy_penalty         INTEGER NOT NULL DEFAULT -2,
    exclusion_penalty       INTEGER NOT NULL DEFAULT -3,
    multi_match_boost       INTEGER NOT NULL DEFAULT 1,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- NOTE: There is deliberately NO alert_events table.
-- NOTE: There is deliberately NO access_log table.
-- This is a privacy design decision, not an oversight.
```

### 6. DNS Resolver Flow

```mermaid
flowchart TD
    A["DNS Query arrives"] --> B{"Domain in rule files?"}
    B -->|"No"| C["Forward to upstream DNS"]
    B -->|"Yes"| D{"Category policy action?"}
    D -->|"deny"| E["Return NXDOMAIN"]
    D -->|"allow"| C
    D -->|"allow_with_dlp"| C
    C --> F["Return resolved IP"]
    E --> G["Increment dns_blocks_total counter\n(no domain stored)"]
    A --> H["Increment dns_queries_total counter\n(no domain stored)"]
```

**Implementation detail:** The DNS resolver maintains an in-memory hash map of blocked domains
loaded from rule files. Lookup is O(1). Rule files are re-read only when the updater detects a
new version. Counters are atomically incremented in-memory and flushed to SQLite periodically
(e.g., every 60 seconds) to minimize disk I/O.

### 7. Platform-Specific Integration

#### macOS
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | `networksetup -setdnsservers Wi-Fi 127.0.0.1` | Yes (one-time) |
| System proxy (opt) | `networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8443` | Yes (one-time) |
| CA trust (opt) | `security add-trusted-cert` to System Keychain | Yes (one-time) |
| Auto-start | LaunchDaemon plist in `/Library/LaunchDaemons/` | Yes (installer) |
| Installer | `.pkg` via `pkgbuild` + `productbuild` | Standard |

#### Windows
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | `netsh` or WMI adapter DNS setting | Yes (one-time) |
| System proxy (opt) | Registry `HKCU\...\Internet Settings\ProxyServer` | No (user-level) |
| CA trust (opt) | `certutil -addstore -f "Root" ca.crt` | Yes (UAC prompt) |
| Auto-start | Windows Service via `golang.org/x/sys/windows/svc` | Yes (installer) |
| Installer | MSI via WiX Toolset | Standard |

#### Linux
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | Modify `/etc/resolv.conf` or `systemd-resolved` | Yes (root) |
| Transparent redirect (opt) | `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443` | Yes (root) |
| CA trust (opt) | Copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates` | Yes (root) |
| Auto-start | systemd unit file | Yes (root) |
| Installer | `.deb` + `.rpm` via `nfpm` | Standard |

### 8. Communication Diagram

```mermaid
sequenceDiagram
    participant User
    participant Tray as Electron Tray
    participant Agent as Go Agent
    participant DNS as DNS Resolver
    participant DLP as DLP Pipeline
    participant Ext as Browser Extension
    participant DB as SQLite

    User->>Tray: Click tray icon → "Settings"
    Tray->>Agent: GET /api/policies
    Agent->>DB: SELECT * FROM category_policies
    DB-->>Agent: policies
    Agent-->>Tray: JSON response
    Tray-->>User: Render settings UI

    User->>Tray: Toggle "AI Chat" → Block
    Tray->>Agent: PUT /api/policies/ai_chat {action: "deny"}
    Agent->>DB: UPDATE category_policies SET action='deny'
    Agent->>DNS: Reload blocked domain set
    Agent-->>Tray: 200 OK

    Note over User: User tries to visit deepseek.com
    User->>DNS: DNS query: deepseek.com
    DNS->>Agent: Check policy
    Agent-->>DNS: NXDOMAIN (blocked)
    Agent->>DB: UPDATE aggregate_stats SET dns_blocks_total = dns_blocks_total + 1
    Note over DB: No domain name stored. Just counter++.
    DNS-->>User: NXDOMAIN

    Note over User: User pastes code into chat.openai.com
    User->>Ext: Paste event detected
    Ext->>Agent: POST /api/dlp/scan {content: "..."}
    Agent->>DLP: Step 1: Classify content → "source code"
    DLP->>DLP: Step 2: Aho-Corasick scan → candidates
    DLP->>DLP: Step 3: Regex validate candidates
    DLP->>DLP: Step 4: Score (hotwords + entropy + exclusions)
    DLP->>DLP: Step 5: Score 4 ≥ threshold 1 (critical) → BLOCK
    DLP-->>Agent: {blocked: true, pattern_name: "AWS Access Key", score: 4}
    Note over Agent: Content discarded from memory. Never written to disk.
    Agent-->>Ext: {blocked: true, pattern_name: "AWS Access Key"}
    Ext-->>User: Block paste, show ephemeral notification
    Agent->>DB: UPDATE aggregate_stats SET dlp_blocks_total = dlp_blocks_total + 1
    Note over DB: No content stored. No pattern details. Just counter++.
```

### 9. API Endpoints

| Method | Path | Description | Privacy Notes |
|--------|------|-------------|---------------|
| `GET` | `/api/status` | Agent health, uptime | No user data |
| `GET` | `/api/policies` | List category policies | Config only |
| `PUT` | `/api/policies/:category` | Update policy action | Config only |
| `GET` | `/api/stats` | Anonymous aggregate counters | Integers only, no domains/IPs |
| `POST` | `/api/stats/reset` | Reset counters to zero | — |
| `POST` | `/api/dlp/scan` | Scan content through layered DLP pipeline | Content processed in-memory, never persisted |
| `GET` | `/api/dlp/config` | Get DLP scoring thresholds | Config only |
| `PUT` | `/api/dlp/config` | Update DLP scoring thresholds | Config only |
| `GET` | `/api/rules` | List loaded rule files | Metadata only |
| `POST` | `/api/rules/update` | Trigger rule file update check | — |

**There is no `/api/alerts` endpoint. There is no `/api/logs` endpoint. This is by design.**
