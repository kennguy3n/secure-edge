# Admin Guide

This guide is for administrators who deploy ShieldNet Secure Edge across an
organization. End-user documentation lives in [user-guide.md](./user-guide.md).

## 1. Installation

Secure Edge ships as a single Go binary plus an Electron tray app. The Phase 4
release artifacts are produced by the `release.yml` GitHub Actions workflow and
attached to GitHub Releases. See [README.md](../README.md) for the per-platform
download/install commands.

| Platform | Install command |
| --- | --- |
| macOS (Apple Silicon) | `brew install --cask shieldnet-secure-edge` (planned) |
| macOS (Intel) | Download `secure-edge-darwin-amd64.tar.gz` and run `install.sh` |
| Linux (amd64) | `curl -fsSL https://shieldnet.io/install.sh | sh` |
| Linux (arm64) | Download `secure-edge-linux-arm64.tar.gz` and run `install.sh` |
| Windows | Run `secure-edge-setup.exe` (signed with the Authenticode cert; see Phase 6) |

All builds embed a build-time SHA-256 of `rules/manifest.json` so tamper
detection works even before the first rule update.

### 1.1 Verifying release artefacts before deploying

Every release ships with a `SHA256SUMS` manifest, a Sigstore keyless
signature over that manifest, per-artefact `.sig` / `.pem` files,
CycloneDX 1.5 SBOMs, and a SLSA build provenance attestation. Run the
verification recipe in [SECURITY.md](../SECURITY.md#verifying-a-release)
before pushing a build to managed endpoints — it confirms the artefact
was emitted by this repository's `Release` workflow on a `v*` tag and
has not been tampered with in transit. Platform-native code signing
(Apple Developer ID / Windows Authenticode / Linux GPG) is still
pending certificate provisioning (`PHASES.md`, "Code signing of release
artifacts"); the Sigstore chain is the authoritative trust path until
then.

## 2. Configuration (`config.yaml`)

The agent looks for `config.yaml` in the following locations, in order:

1. `$SECURE_EDGE_CONFIG` (env var, if set)
2. `$XDG_CONFIG_HOME/secure-edge/config.yaml`
3. `~/.config/secure-edge/config.yaml` (Linux/macOS) or
   `%APPDATA%\secure-edge\config.yaml` (Windows)
4. `/etc/secure-edge/config.yaml` (managed install)

Minimal example:

```yaml
upstream_dns:
  - 1.1.1.1
  - 9.9.9.9
listen_dns: 127.0.0.1:53053
listen_proxy: 127.0.0.1:8443
listen_api: 127.0.0.1:7878
rules_dir: ~/.local/share/secure-edge/rules
log_level: info
```

Full reference is in `agent/internal/config/config.go`.

## 3. Enterprise Profiles (managed mode)

Phase 5 added managed-mode profiles for enrolled fleets. A profile is a YAML
file with the same shape as `config.yaml` plus an `overrides` block. It is
loaded from `profile_path` or fetched from `profile_url` on agent start and on
every rule update.

```yaml
# profile.yaml
profile_id: acme-prod-2026q2
profile_version: 7
overrides:
  category_policies:
    "AI Chat (Unsanctioned)": deny
    "Code Hosting": allow_with_dlp
  thresholds:
    critical: 1
    high: 2
  managed: true   # disables local toggles in the tray UI
```

Set `profile_url: https://mdm.example.com/profiles/secure-edge.yaml` to fetch
the profile over HTTPS. Validation runs on every load — a malformed profile
falls back to the last good profile and logs a single line to the agent log
(no profile body is logged).

When `managed: true`, the Electron tray UI hides the category toggles and the
Settings page shows a read-only banner with the profile ID + version.

## 4. Rule Updates

Two mechanisms:

- **Automatic**: the agent polls `manifest.json` at the configured
  `update_url` on the `update_interval` cadence (default 24h). Each entry in
  the manifest carries a SHA-256; the agent only swaps in a new rule file if
  the SHA-256 matches.
- **Manual**: `POST /api/rules/update` triggers an immediate fetch. The
  response is `{"updated":true,"version":"..."}` on success.

Both paths use the same loader, so they share the same tamper checks
(see §6).

## 5. Admin Overrides (`rules/local/`)

For per-host customization, place files under `rules_dir/local/`:

```
rules/local/
├── allow_domains.txt        # extra Tier 1 domains (one per line)
├── block_domains.txt        # extra Tier 3 domains
└── dlp_patterns_local.json  # extra DLP patterns (same schema as dlp_patterns.json)
```

Local rules are loaded after the shipped rules and override on a key-by-key
basis. Local rules are not signed and not in the manifest — they're meant for
per-host one-offs, not for fleet distribution.

## 6. Tamper Detection

On start and on every rule load, the agent recomputes the SHA-256 of every
shipped rule file and compares against `manifest.json`. A mismatch:

1. Refuses to load the modified file (the agent keeps running with the
   previous good copy).
2. Increments `tamper_detections_total` in the aggregate stats.
3. Surfaces a red tray icon and a `GET /api/status` field
   (`"tamper_state": "detected"`).

The integrity check ignores `rules/local/` so per-host overrides do not trip
the alarm.

## 7. Heartbeat

When `heartbeat_url` is set in `config.yaml` or the enterprise profile, the
agent posts a JSON heartbeat on a fixed interval (default 5 min):

```json
{
  "profile_id": "acme-prod-2026q2",
  "profile_version": 7,
  "agent_version": "0.5.0",
  "manifest_version": "rules-2026-05-13",
  "stats": {
    "dns_queries_total": 50321,
    "dns_blocks_total": 142,
    "dlp_scans_total": 8901,
    "dlp_blocks_total": 7,
    "tamper_detections_total": 0
  }
}
```

The heartbeat carries only aggregate counters — no domain names, no URLs, no
user identifiers. The receiving endpoint should reply 200 OK; non-200 responses
are retried with exponential backoff. See `agent/internal/heartbeat/`.

## 8. Enforcement Boundary: Extension vs. Proxy

ShieldNet Secure Edge has two on-device inspection paths and it is important
to understand exactly what each one guarantees before relying on one in a
deployment.

| Layer                  | Role                                  | Bypassable by the page?                                          |
| ---------------------- | ------------------------------------- | ---------------------------------------------------------------- |
| Browser extension      | DLP **coaching** (UX, real-time toast) | Yes — the page sees `window.postMessage` traffic and is in the same JS world as the bridge. |
| Local MITM proxy       | DLP **enforcement** (TLS termination on Tier-2 hosts) | No — runs outside the browser process and gates the network. |
| Managed browser policy | Hard domain blocklist / allowlist     | No — enforced by the browser before any page JS runs.            |

### Why the extension is coaching, not enforcement

The companion extension installs a MAIN-world content script that patches the
page's own `window.fetch` and `XMLHttpRequest.prototype.send`. To talk to the
isolated-world content script (which owns the agent connection), it uses
`window.postMessage`. The page's own JavaScript sits in the same MAIN world and
can:

- See every `secure-edge-bridge` message the MAIN-world script posts.
- Reply with a forged `secure-edge-iso` `scan-resp` `{ result: { blocked: false }}`.
- Replace `window.fetch` or `XMLHttpRequest.prototype.send` *after* our patch
  installs, restoring the original unpatched function.

The `BRIDGE_SOURCE` / `ISO_SOURCE` channel tags are best-effort identification
markers, not security tokens (see the inline comment in
`extension/src/content/main-world-network.ts`). A hostile or compromised page
trivially defeats them. The extension is therefore the right tool for *honest
user error* (someone pasting an API key into ChatGPT) but not for adversarial
or compromised pages.

### When to enable the proxy

Enable the local MITM proxy whenever any of the following are true:

- The threat model includes pages or web apps that may be hostile to the
  extension (compromised AI portals, browser extensions that fight ours,
  enterprise SSO-wrapped AI tools that load arbitrary third-party JS).
- You need enforcement coverage for non-browser traffic — desktop AI apps,
  IDE plugins (e.g. Copilot, Cursor) hitting Tier-2 endpoints, CLI tools, or
  any other process that bypasses the browser entirely.
- You require auditable "the network refused to forward this body" semantics
  rather than "the browser was asked nicely not to".

Start the proxy with `POST /api/proxy/enable`; the agent generates a local CA,
prompts the user to install it, and routes only Tier-2 hostnames through the
TLS termination path. All other hosts get an opaque CONNECT tunnel — the proxy
never sees their plaintext. See `agent/internal/proxy/proxy.go` for the policy
hook and `scripts/macos/configure-proxy.sh` / the Windows equivalent for the
system-proxy handoff.

### When to deploy managed browser policies

Managed browser policies (Chrome Enterprise `URLBlocklist` and friends, Firefox
`policies.json`, Edge GPO) are enforced by the browser itself before any page
script runs. Combine them with the proxy for defence in depth:

- Use `URLBlocklist` to keep blocked AI domains unreachable even if the user
  somehow disables the agent.
- Use `ManagedConfigurationPerOrigin` to push a hard deny / read-only mode on
  internal AI tools.

The agent does **not** distribute managed browser policies — that is the
endpoint management system's job. Document the policy bundle you deploy
alongside Secure Edge so future operators understand which layer enforces what.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Tray icon is red | Tamper detected, or agent service is down | Check `GET /api/status`; reinstall the binary if SHA-256 mismatch persists. |
| DNS queries fail with NXDOMAIN for known-good domain | Domain is in an active blocklist | Add to `rules/local/allow_domains.txt`. |
| DLP false-positive blocks | Pattern fires on documentation/test value | File a `false_positive` issue on the GitHub repo; add a temporary exclusion in `rules/local/dlp_patterns_local.json`. |
| Profile not applied | `profile_url` returned non-200, or YAML invalid | Check the agent log for the single line emitted on profile load failure; the agent falls back to the last good profile. |
| High CPU | Likely DLP scanning very large clipboard pastes | The pipeline has a hard cap (`pipeline.maxScanBytes`) — confirm it's not been raised in a custom build. |

For deeper debugging, the agent supports `LOG_LEVEL=debug` to print per-step
pipeline timing (without logging scan content).
