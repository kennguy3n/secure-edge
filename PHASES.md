# ShieldNet Secure Edge — Implementation Phases

## Phase 1: DNS Blocking + Electron Tray (MVP)

**Covers:** Tiers 1, 3, 4 fully. Basic system tray presence. Zero-logging architecture.

### Deliverables
- [ ] Go agent binary with embedded DNS resolver (`miekg/dns`)
- [ ] SQLite database with `rulesets`, `category_policies`, `aggregate_stats` tables (no alert_events)
- [ ] Policy engine: load rule files, match domains, return NXDOMAIN or forward
- [ ] Anonymous counter system: increment `dns_blocks_total` on block, `dns_queries_total` on any query
- [ ] Local HTTP API (`/api/policies`, `/api/stats`, `/api/status`)
- [ ] Bundled rule files: `ai_chat_blocked.txt`, `phishing.txt`, `social.txt`, `news.txt`
- [ ] Electron tray app (hidden window, tray icon only)
- [ ] Tray context menu: Status, Open Settings, Quit
- [ ] Settings page: per-category policy toggles (Block / Allow)
- [ ] Status page: anonymous aggregate stats (total blocks, total queries, uptime)
- [ ] Platform DNS configuration scripts (macOS, Windows, Linux)
- [ ] Basic installer for one platform (Linux `.deb` or macOS `.pkg`)

### Architecture
```
Go Agent:      DNS resolver + Policy engine + SQLite (config+counters) + HTTP API
Electron:      Tray icon + Settings BrowserWindow (on-demand)
Rules:         Bundled .txt files loaded at startup
Logging:       NONE for user access. Operational errors only to stderr.
```

### What the Installer Does
```
1. Extract Go binary to install directory
2. Write default rule files to data directory
3. Create SQLite database with default policies and zeroed counters
4. Set OS DNS to 127.0.0.1 (backup original)
5. Register as system service / LaunchDaemon
6. Install Electron tray app
```

---

## Phase 2: Browser Extension + DLP Scanning (Tier 2 Browser)

**Covers:** Tier 2 for browser-based AI tool usage. Privacy-preserving DLP.

### Deliverables
- [ ] Chrome extension (Manifest V3) with content scripts for Tier 2 AI domains
- [ ] Firefox extension (WebExtensions) port
- [ ] DLP pattern scanner in the Go agent (`/api/dlp/scan` endpoint)
- [ ] `dlp_patterns.json` bundled rule file (API keys, emails, source code heuristics)
- [ ] Native Messaging host configuration for extension ↔ agent communication
- [ ] Extension intercepts: paste events, form submissions, fetch/XHR requests
- [ ] Ephemeral block notification: shows pattern name only, no matched content, auto-dismisses
- [ ] Anonymous DLP counters: `dlp_scans_total`, `dlp_blocks_total` (no content/domain stored)
- [ ] Category toggles extended to three-state: Allow / Allow + Inspect / Block

### Privacy Guarantees
- DLP scan content is received via HTTP POST, scanned in-memory, and response sent. The request body is garbage-collected. Never written to disk.
- Block notifications show "AWS Access Key pattern detected" — NOT the actual key.
- The extension stores no history of scanned pages or content.

### Architecture Addition
```
Browser Extension → Native Messaging → Go Agent → DLP Scanner (in-memory)
                                                 → Counter increment (no content stored)
                                                 → Extension (block/allow response)
```

---

## Phase 3: Rule Updates + Multi-Platform Installers

**Covers:** Server-side rule distribution. Production-ready packaging.

### Deliverables
- [ ] Rule updater: polls `manifest.json` from configurable URL (default: GitHub Releases)
- [ ] Manifest format: version, checksums (SHA256), file list
- [ ] Delta updates: only download changed rule files
- [ ] Electron auto-update via `electron-updater` (Squirrel on Windows, zip on macOS)
- [ ] macOS installer: `.pkg` via `pkgbuild` + `productbuild`
- [ ] Windows installer: MSI via WiX Toolset
- [ ] Linux installers: `.deb` + `.rpm` via `nfpm`
- [ ] CI/CD pipeline: GitHub Actions for cross-platform builds
- [ ] Code signing for macOS (Developer ID) and Windows (Authenticode)

### Rule Server (Minimal)
```
Static file host serving:
  GET /manifest.json       → version + checksums
  GET /rules/{filename}    → individual rule files
```

No processing, no auth, no user data. Can be a GitHub repo with tagged releases.
The rule server has NO knowledge of which devices downloaded which rules.

---

## Phase 4: Optional MITM Proxy (Tier 2 Full Coverage)

**Covers:** Tier 2 for non-browser traffic (CLI tools, IDE plugins, API calls).

### Deliverables
- [ ] Go MITM proxy (`elazarl/goproxy`) on `127.0.0.1:8443`
- [ ] Per-device Root CA generation (`crypto/x509`)
- [ ] Platform-specific CA trust installation (automated scripts)
- [ ] Platform-specific system proxy configuration
- [ ] Selective inspection: only Tier 2 domains decrypt TLS; all other traffic tunneled (CONNECT)
- [ ] DLP scanning of decrypted request bodies (in-memory only, never persisted)
- [ ] "Enable Advanced DLP" setup wizard in Electron UI
- [ ] Certificate pinning bypass list (known pinned apps)

### Privacy Notes
- The proxy decrypts TLS ONLY for Tier 2 domains. All other traffic passes through as opaque CONNECT tunnels.
- Decrypted content is scanned in-memory and immediately discarded.
- No access log. No connection log. No request/response capture.
- The proxy increments `dlp_scans_total` and `dlp_blocks_total` counters only.

### User Experience
```
Settings → Advanced → Enable Full DLP Protection
  → Generates local CA
  → Prompts for admin password
  → Installs CA to OS trust store
  → Configures system proxy
  → Shows status: "Full DLP Active"
```

This is **opt-in only**. Default installation uses DNS blocking + browser extension.

---

## Phase 5: Enterprise Features + Hardening

**Covers:** Features for managed deployments.

### Deliverables
- [ ] Configuration profiles: JSON-based policy profiles downloadable from server
- [ ] Tamper detection: alert if DNS settings or proxy are changed externally (ephemeral notification only)
- [ ] Agent health heartbeat to optional central server (sends ONLY: "agent alive, version X" — no access data)
- [ ] Export aggregate stats as JSON (counters only, no access data)
- [ ] Custom rule file support (admin adds company-specific domains)
- [ ] Allowlist/blocklist override UI
- [ ] Performance profiling and optimization pass
- [ ] Documentation: admin guide, user guide, rule contribution guide
- [ ] Privacy audit: third-party review of zero-logging guarantees
- [ ] Accessibility audit of Electron UI

### Enterprise Privacy Boundary
Even in enterprise mode, the agent NEVER sends access logs, domain lists, or user activity
to a central server. The heartbeat endpoint receives only: agent version, OS type, and
aggregate counters. An enterprise admin can see "Device X has blocked 142 requests total"
but cannot see WHAT was blocked.

---

## Difficulty Assessment

| Component | Difficulty | Notes |
|-----------|-----------|-------|
| DNS blocking agent | Easy | ~500 lines Go |
| Rule file format + updater | Easy | Direct reuse of ShieldNet format |
| SQLite config store (no logging) | Easy | Simpler than logged version — fewer tables, less I/O |
| Anonymous counter system | Easy | Atomic integer increments, periodic flush |
| Electron tray (minimal) | Easy | ~300 lines main process |
| Browser extension (Tier 2) | Medium | ~2000 lines TypeScript |
| Settings UI | Medium | Adapted from ShieldNet frontend (no Reports page needed) |
| Local MITM proxy | Medium | ~1000 lines Go (goproxy handles TLS) |
| Cross-platform installers | Medium | Three separate pipelines |
| DLP pattern tuning | Hard | Ongoing quality problem (false positives) |
| Preventing user bypass | Hard | Inherent limitation without MDM |
| Keeping AI tool list current | Hard | Community maintenance IS the product |
| Privacy audit | Hard | Needs thorough review of all code paths to ensure no accidental logging |
