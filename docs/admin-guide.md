# Admin Guide

This guide is for administrators who deploy ShieldNet Secure Edge across
an organisation. End-user documentation lives in
[user-guide.md](./user-guide.md).

## 1. Installation

Secure Edge ships as a single Go binary plus an Electron tray app.
Release artefacts are produced by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) and
attached to the GitHub Release for each `v*` tag.

| Layer | Artefact | Install path (default) |
| --- | --- | --- |
| Agent (macOS) | `.pkg` installer | `/usr/local/bin/secure-edge-agent` |
| Agent (Linux) | `.deb` / `.rpm` (built via `nfpm`) | `/usr/bin/secure-edge-agent` |
| Agent (Windows) | `.msi` (built via WiX) | `C:\Program Files\SecureEdge\bin\secure-edge-agent.exe` |
| Tray app | platform `electron-builder` bundles | platform default |
| Browser extension | Chrome `.zip`, Firefox `.xpi`, Safari `.zip` | per-browser store / sideload |

All builds embed a build-time SHA-256 of `rules/manifest.json` so tamper
detection works even before the first rule update.

### 1.1 Verifying release artefacts

Every release ships with a `SHA256SUMS` manifest, a Sigstore keyless
signature over that manifest, per-artefact `.sig` / `.pem` files,
CycloneDX 1.6 SBOMs, and a SLSA build provenance attestation. Run the
verification recipe in [SECURITY.md](../SECURITY.md#verifying-a-release)
before pushing a build to managed endpoints — it confirms the artefact
was emitted by this repository's `Release` workflow on a `v*` tag and
has not been tampered with in transit.

## 2. Configuration (`config.yaml`)

The agent loads its configuration from the path given to the `--config`
flag (default `config.yaml` in the working directory). The shipped
service definitions point at the canonical managed-install location:

| Platform | Location | Loaded by |
| --- | --- | --- |
| Linux | `/etc/secure-edge/config.yaml` | [`scripts/linux/secure-edge.service`](../scripts/linux/secure-edge.service) |
| macOS | `/etc/secure-edge/config.yaml` | [`scripts/macos/com.secureedge.agent.plist`](../scripts/macos/com.secureedge.agent.plist) |
| Windows | `%ProgramData%\SecureEdge\config.yaml` | [`scripts/windows/register-service.ps1`](../scripts/windows/register-service.ps1) |

Minimal example (YAML keys match the struct tags in
[`agent/internal/config/config.go`](../agent/internal/config/config.go)):

```yaml
upstream_dns: "1.1.1.1:53"
dns_listen: "127.0.0.1:53053"
proxy_listen: "127.0.0.1:8443"
api_listen: "127.0.0.1:8080"
rules_dir: "~/.local/share/secure-edge/rules"
```

Log verbosity is controlled by the `LOG_LEVEL` environment variable
(`debug` / `info` / `warn`), not a YAML key — see §9 Troubleshooting.

Full reference is in
[`agent/internal/config/config.go`](../agent/internal/config/config.go).

### 2.1 Reference presets

Three presets ship at the repository root; copy the one that matches
your posture and fill in the placeholder values:

| Preset | File | Posture |
| --- | --- | --- |
| Personal | `config.personal.example.yaml` | Fall-open, individual developer use. No per-install token; lenient HMAC; unsigned profiles accepted. Mirrors the packaged defaults. |
| Team | `config.team.example.yaml` | Per-install API token required; warn-toast on agent-unavailable; HMAC lenient; unsigned profiles accepted. |
| Managed | `config.managed.example.yaml` | Fail-closed end-state for MDM-deployed fleets. Every signed surface enforced. Requires `profile_path` or `profile_url` plus `profile_public_key`. |

`team` and `managed` are validated at startup by
`ValidateEnforcementRequirements` — they refuse to start without
`allowed_extension_ids`, `api_token_path`, and `api_token_required:
true`; `managed` additionally requires `bridge_mac_required: true`,
`profile_public_key`, and one of `profile_path` / `profile_url`.

### 2.2 Native Messaging bridge HMAC (`bridge_mac_required`)

The agent appends an HMAC-SHA256 MAC to every non-`hello` frame on the
Native Messaging bridge that connects the browser extension's service
worker to the locally installed agent binary. The MAC is keyed by the
per-install API token (the 32-byte hex value under `api_token_path`).
The agent mints a fresh 16-byte nonce per connection and surfaces it on
the (intentionally unsigned) `hello` reply.

```yaml
api_token_path: /var/lib/secure-edge/api-token
bridge_mac_required: false  # flip to true once every endpoint is on
                            # an extension build that produces MACs
```

When `bridge_mac_required: false` the agent logs a one-time stderr
warning per connection on a missing or invalid MAC but keeps serving.
When `true`, a missing or tampered MAC is rejected and the extension
falls back to the HTTP path (which has its own bearer-token guard via
`api_token_required`). The MAC check is auto-skipped when no
`api_token_path` is configured — there is nothing to verify against.

### 2.3 Risky file extensions (`risky_file_extensions`)

Secure Edge hard-blocks file uploads whose extension is on a
configurable risky list. The block is evaluated **on the page**,
inside the extension's `file-upload-interceptor`, **before** any
content is read or sent to the agent — the filename and contents
never leave the page for a risky-extension verdict.

The extension ships with a baked-in default list of 34 extensions
covering Windows / macOS / Linux executables, installers (`.msi`,
`.pkg`, `.deb`, `.rpm`), scripts (`.ps1`, `.vbs`, `.bat`, `.cmd`,
`.sh`, …), disk images, Java archives, and platform binaries. `.js`
and archive formats (`.zip`, `.7z`, `.rar`, …) are **intentionally
excluded** to avoid breaking developer workflows.

```yaml
# Three states:
#   1) omitted       -> extension uses the baked-in 34-entry default
#   2) empty list    -> opts out entirely; content scan still runs
#   3) populated     -> replaces the baked-in default verbatim
risky_file_extensions:
  - exe
  - scr
  - ps1
  - msi
```

The resolved list is exposed at `GET /api/config/risky-extensions`;
the extension caches it for 5 min in `chrome.storage.session`. A
risky-extension block fires **regardless of enforcement mode** — this
policy lever removes a class of file from the upload surface entirely.

## 3. Enterprise profiles

A profile is a JSON document that overrides category policies and DLP
thresholds for an enrolled fleet. It is loaded from `profile_path`,
fetched from `profile_url` on agent start, and reloadable via
`POST /api/profile/import` (either `{"url": …}` or `{"profile": {…}}`).

```yaml
profile_id: acme-prod-2026q2
profile_version: 7
overrides:
  category_policies:
    "AI Chat (Unsanctioned)": deny
    "Code Hosting": allow_with_dlp
  thresholds:
    critical: 1
    high: 2
  managed: true   # hides local toggles in the tray UI
```

Validation runs on every load. A malformed profile falls back to the
last good profile and logs a single line; no profile body is ever
written to disk. When `managed: true`, the Electron tray hides the
category toggles and the Settings page shows a read-only banner with
the profile ID + version.

### 3.1 Signing enterprise profiles

When `profile_public_key` is configured, the agent verifies an Ed25519
signature on every loaded profile across all three import surfaces
(`profile_path`, `profile_url`, `POST /api/profile/import`). When the
key is absent, the agent accepts unsigned profiles and emits a
warn-once line per process so half-rolled-out deployments are visible.

End-to-end signing:

```bash
# 1. Generate a keypair. crypto/ed25519's raw 64-byte private key
#    (seed || public) is what sign-enterprise-profile consumes.
cat > /tmp/genkey.go <<'EOF'
package main
import (
    "crypto/ed25519"; "crypto/rand"; "encoding/hex"; "fmt"; "os"
)
func main() {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { panic(err) }
    if err := os.WriteFile("ed25519-priv.hex",
        []byte(hex.EncodeToString(priv)), 0o600); err != nil {
        panic(err)
    }
    fmt.Println(hex.EncodeToString(pub))
}
EOF
go run /tmp/genkey.go > ed25519-pub.hex
chmod 600 ed25519-priv.hex

# 2. Sign the profile.
go run ./agent/cmd/sign-enterprise-profile \
    -in config/profile.json \
    -key ed25519-priv.hex

# 3. Configure every agent with the matching public key.
cat >> /etc/secure-edge/config.yaml <<EOF
profile_public_key: "$(cat ed25519-pub.hex)"
profile_path: "/etc/secure-edge/profile.json"
EOF
```

Re-sign on every profile update. The CLI is idempotent — the
`signature` field is excluded from the canonical bytes by construction,
so re-running it over an already-signed profile is deterministic.

Setting `profile_public_key` without `profile_path` or `profile_url`
fails startup in `managed` mode (the validator requires a source) and
prints a one-line orphan-key warning otherwise.

## 4. Rule updates

Two paths, both running through the same loader and tamper checks:

- **Automatic** — the agent polls `manifest.json` at `rule_update_url`
  on the `rule_update_interval` cadence (default **6 h**). Each entry
  in the manifest carries a SHA-256; a file is swapped in only if the
  SHA-256 matches.
- **Manual** — `POST /api/rules/update` triggers an immediate fetch
  and returns the `rules.Result` body (`updated`, `version`,
  `files_downloaded`, …).

## 5. Admin overrides (`rules/local/`)

For per-host customisation, drop files under `rules_dir/local/`:

```
rules/local/
├── allow_domains.txt        # extra Tier 1 domains (one per line)
├── block_domains.txt        # extra Tier 3 domains
└── dlp_patterns_local.json  # extra DLP patterns (same schema)
```

Local rules load after the shipped rules and override on a key-by-key
basis. They are not signed and not in the manifest — they are meant
for per-host one-offs, not fleet distribution. The integrity check in
§6 ignores `rules/local/`.

## 6. Tamper detection

On start and on every rule load, the agent recomputes the SHA-256 of
every shipped rule file and compares against `manifest.json`. A
mismatch:

1. Refuses to load the modified file (the agent keeps running with
   the last known good copy).
2. Increments `tamper_detections_total` in the aggregate stats.
3. Surfaces a red tray icon and the `"tamper_state": "detected"`
   field on `GET /api/status`.

## 7. Heartbeat

When `heartbeat_url` is set, the agent posts a JSON heartbeat on the
configured cadence (`heartbeat_interval`, default **1 h**):

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

The heartbeat carries only aggregate counters — no domain names, no
URLs, no user identifiers. The receiving endpoint should reply 200 OK;
non-200 responses retry with exponential backoff.

## 8. Enforcement boundary: extension vs. proxy

Secure Edge has two on-device inspection paths. Understand the
guarantees of each before relying on one in a deployment.

| Layer | Role | Bypassable by the page? |
| --- | --- | --- |
| Browser extension | DLP **coaching** (UX, real-time toast) | Yes — the page sees `window.postMessage` traffic and is in the same JS world as the bridge. |
| Local MITM proxy | DLP **enforcement** (TLS termination on Tier-2 hosts) | No — runs outside the browser process and gates the network. |
| Managed browser policy | Hard domain blocklist / allowlist | No — enforced by the browser before any page JS runs. |

### Why the extension is coaching

The companion extension installs a MAIN-world content script that
patches the page's own `window.fetch` and `XMLHttpRequest.prototype.send`
and talks to the isolated-world content script via
`window.postMessage`. The page's own JavaScript sits in the same
MAIN world and can see those messages, reply with a forged `scan-resp`,
or restore the unpatched originals. The extension is the right tool
for *honest user error* (someone pasting an API key into an AI tool)
but not for adversarial or compromised pages.

### When to enable the proxy

Enable the local MITM proxy when any of the following are true:

- The threat model includes pages or web apps that may be hostile to
  the extension (compromised AI portals, fighting extensions,
  enterprise SSO-wrapped AI tools that load arbitrary third-party JS).
- You need enforcement coverage for non-browser traffic — desktop AI
  apps, IDE plugins (Copilot, Cursor), CLI tools.
- You require "the network refused to forward this body" semantics
  rather than "the browser was asked nicely not to".

Start the proxy with `POST /api/proxy/enable`. The agent generates a
local CA, prompts the user to install it, and routes only Tier-2
hostnames through the TLS-termination path. All other hosts get an
opaque CONNECT tunnel — the proxy never sees their plaintext.

### Managed browser policies

Layer Chrome Enterprise `URLBlocklist` / Firefox `policies.json` / Edge
GPO on top of the proxy for defence in depth: the browser refuses to
load blocked AI domains even if the user disables the agent.
Distributing those policies is the endpoint-management system's job,
not Secure Edge's.

### 8.1 Image / screenshot DLP is not in scope

The DLP scanner operates on **text content only**. The Aho-Corasick
prefix scan, the regex pass, the entropy / hotword scoring, and the
classifier head all decode bytes as best-effort UTF-8 before any
pattern fires — a screenshot of an AWS access key is, to the scanner,
an unrelated string of mojibake.

Two surfaces are affected:

- **Clipboard screenshot paste**
  (`extension/src/content/paste-interceptor.ts`) — the interceptor
  suppresses the upload **gesture** by calling `preventDefault` /
  `stopPropagation` before any await, so the bytes never reach the
  page. The agent runs its UTF-8 decode + DLP scan on the file
  bytes; the resulting verdict is a coaching signal, not a
  content-aware verdict.
- **Drag-and-drop / `<input type=file>` of binary files**
  (`file-upload-interceptor.ts`) — same shape. The gesture is
  suppressed; the content scan is best-effort UTF-8.

What the scanner **does** cover for binary payloads:

- The risky-extension blocklist (§2.3) — filename-driven; the
  gesture is blocked before any content read.
- The MITM proxy — refuses the body at the network layer regardless
  of the content question.

What is **not supported** and is not on the roadmap: OCR over
screenshot pixels, image-classification heads, or PDF text extraction.

For managed deployments that need screenshot DLP coverage, the
recommended postures are (a) block the gesture outright on Tier-2 AI
tools via managed browser policy (`DefaultClipboardSetting:
BlockClipboard`), or (b) layer in a complementary endpoint DLP product
with OCR.

## 9. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Tray icon is red | Tamper detected, or agent service is down | Check `GET /api/status`; reinstall if a SHA-256 mismatch persists. |
| DNS queries fail with NXDOMAIN for a known-good domain | Domain is in an active blocklist | Add to `rules/local/allow_domains.txt`. |
| DLP false-positive blocks | Pattern fires on a documentation / test value | File a `false_positive` issue; add a temporary exclusion in `rules/local/dlp_patterns_local.json`. |
| Profile not applied | `profile_url` returned non-200, or YAML invalid | Check the agent log for the single line emitted on profile load failure. |
| High CPU | DLP scanning very large pastes | Confirm `pipeline.maxScanBytes` has not been raised in a custom build. |

For deeper debugging, set `LOG_LEVEL=debug` to print per-step pipeline
timing (without logging scan content).

## 10. Managed deployments (MDM)

This section is for operators wiring the agent + companion extension
into a Mobile Device Management platform after validating the
single-endpoint posture from §1–§9.

### 10.1 What to bundle

A deployment bundle is the minimum set of files an MDM-managed
endpoint needs to bring the agent up in **managed** mode with every
signed surface verified end-to-end. The bundle is generated per
organisation on the operator's signing host — it is **never**
published anywhere public.

| File | Where it lives on disk | Generated by | Signed? |
| --- | --- | --- | --- |
| `config.yaml` | macOS / Linux: `/etc/secure-edge/`<br>Windows: `%ProgramData%\SecureEdge\` | Hand-authored from §2 | No (operator-controlled) |
| `profile.json` | Path referenced by `profile_path` | `sign-enterprise-profile` (§3.1) | Yes — Ed25519 |
| `manifest.json` + `rules/` | Manifest fetched from `rule_update_url`; rule files unpacked into `rules_dir` | `sign-rule-manifest` (§4) | Yes — Ed25519 |
| `api_token` | macOS / Linux: `/var/lib/secure-edge/api_token`<br>Windows: `%ProgramData%\SecureEdge\api_token` | Generated per install on first run | n/a — secret |
| `secure-edge-agent` binary | platform-canonical bin dir | GitHub Releases (verified per §1.1) | Yes — cosign + SLSA L3 |
| Extension `.crx` / `.xpi` | Managed by browser policy | Web Store / signed `.crx` | Yes — Web Store key |

> **Privacy note.** Only the per-install `api_token` is a secret.
> Both Ed25519 public keys (`profile_public_key`,
> `rule_update_public_key`) are configuration values, not secrets —
> they verify signatures but cannot create them, so there is no harm
> in including them in an MDM payload that ships to thousands of
> endpoints. The matching private keys must never leave the
> operator's signing host.

The `config.yaml` fragment a managed endpoint receives:

```yaml
enforcement_mode: managed

profile_public_key: "<32-byte hex>"        # signed enterprise profile
rule_update_public_key: "<32-byte hex>"    # signed rule manifest

api_token_required: true                   # bearer-token guard
bridge_mac_required: true                  # Native Messaging HMAC

allowed_extension_ids:
  - "<your-chrome-extension-id>"           # pin to your managed extension build

profile_path: "/etc/secure-edge/profile.json"
rule_update_url: "https://rules.example.com/manifest.json"
rules_dir: "/etc/secure-edge/rules"
api_token_path: "/var/lib/secure-edge/api_token"
```

### 10.2 Chrome Enterprise managed policies

The extension is force-installed via Chrome Enterprise managed
policies; the same JSON works for Edge for Business and any
Chromium-derived browser that honours
`HKLM\Software\Policies\Google\Chrome` (Windows) or
`/Library/Managed Preferences/com.google.Chrome.plist` (macOS). For
Firefox use the equivalent `policies.json` syntax — the extension ID
and force-install semantics carry over.

```json
{
    "ExtensionInstallForcelist": [
        "<extension-id>;https://clients2.google.com/service/update2/crx"
    ],
    "ExtensionSettings": {
        "<extension-id>": {
            "installation_mode": "force_installed",
            "update_url": "https://clients2.google.com/service/update2/crx",
            "blocked_install_message": "Secure Edge is required by IT. Contact security@example.com if it is missing.",
            "runtime_blocked_hosts": [],
            "runtime_allowed_hosts": ["*://*/*"]
        }
    }
}
```

- `ExtensionInstallForcelist` pins the exact extension ID — replace
  `<extension-id>` with the value shown on `chrome://extensions` after a
  manual install on a test endpoint. This is the same string that
  belongs in `allowed_extension_ids` (§10.1).
- `runtime_allowed_hosts` defaults to every host because Secure Edge
  intercepts AI-tool surfaces by URL match. If your fleet only uses a
  known subset (e.g. just `chatgpt.com` and `claude.ai`), narrow this
  list to reduce the extension's exposure.
- The extension does not read `chrome.storage.managed`; the agent
  endpoint and enforcement mode are resolved over loopback at runtime
  from the agent itself (see §1 and §7). No additional managed-policy
  keys are needed.

### 10.3 Per-platform recipes

The three subsections below are shape-only walkthroughs — they show
the payload layout for each platform but do not include
operator-specific values (paths, group names, signing identities, the
HTTPS endpoint hosting your signed `manifest.json`). Substitute your
organisation's values when uploading the bundle.

Across all three platforms the deployment shape is the same:
`config.yaml`, the signed `profile.json`, and the per-install
`api_token` ship as MDM payload files. The signed `manifest.json` and
`rules/` directory are **not** staged on disk by the MDM — the agent
fetches the manifest from `rule_update_url` and unpacks the rule files
into `rules_dir` at runtime (§4).

#### 10.3.1 JAMF Pro (macOS)

JAMF deploys the bundle in three pieces: a **Configuration Profile**
for `config.yaml` and the two public keys, a **Files & Processes**
policy for the signed `profile.json` and the agent binary, and a
**Restricted Software** entry to prevent users from uninstalling the
agent.

1. **Configuration Profile** — *Computers → Configuration Profiles →
   New*. Add a **Custom Settings** payload with preference domain
   `com.shieldnet.secure-edge.config` and the plist below (one-to-one
   mapping of the `config.yaml` fields in §10.1):

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
      <dict>
        <key>enforcement_mode</key>
        <string>managed</string>
        <key>profile_public_key</key>
        <string>9b1ac8...</string>
        <key>rule_update_public_key</key>
        <string>5cf472...</string>
        <key>api_token_required</key>
        <true/>
        <key>bridge_mac_required</key>
        <true/>
        <key>allowed_extension_ids</key>
        <array>
          <string>your-chrome-extension-id</string>
        </array>
        <key>profile_path</key>
        <string>/etc/secure-edge/profile.json</string>
        <key>rule_update_url</key>
        <string>https://rules.example.com/manifest.json</string>
        <key>rules_dir</key>
        <string>/etc/secure-edge/rules</string>
        <key>api_token_path</key>
        <string>/var/lib/secure-edge/api_token</string>
      </dict>
    </plist>
    ```

    The agent on macOS reads `config.yaml` from `/etc/secure-edge/`
    (the path the shipped LaunchDaemon at
    [`scripts/macos/com.secureedge.agent.plist`](../scripts/macos/com.secureedge.agent.plist)
    points at). A postinstall script in step 2 translates the plist
    into the YAML the agent expects (or, equivalently, you can ship a
    static `config.yaml` as a payload file).

2. **Files & Processes policy** — *Computers → Policies → New*. Upload
   the signed `profile.json` as a package payload. Target distribution
   point: `/etc/secure-edge/`. Trigger: **Recurring Check-in** (default
   30 min) and **At Login** for the first roll-out window.

3. **Restricted Software** — *Computers → Restricted Software*. Match
   on the agent binary path; action = **Restrict and Kill**. Pair with
   a JAMF Self Service entry so a user can request reinstall if the
   binary is removed in error.

#### 10.3.2 Microsoft Intune (Windows)

Intune deploys the bundle as a **Win32 app** plus an **ADMX-backed
device configuration policy**. The Win32 app installs the agent
binary, writes `config.yaml`, and drops the signed `profile.json` into
`%ProgramData%\SecureEdge\`. The ADMX policy pins the browser-side
`ExtensionInstallForcelist`.

1. **Package the agent as a Win32 app.** Use the
   `IntuneWinAppUtil.exe` tool against a folder containing:

    ```
    secure-edge-windows-amd64.exe
    install.ps1
    register-service.ps1   # shipped at scripts/windows/register-service.ps1
    profile.json
    config.yaml
    ```

    `install.ps1` is a thin wrapper that:

    ```powershell
    # Halt on first error so a partial install never silently
    # leaves the endpoint in a half-configured state.
    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $true

    $installDir = "$env:ProgramFiles\SecureEdge\bin"
    $dataDir = "$env:ProgramData\SecureEdge"

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    Copy-Item secure-edge-windows-amd64.exe "$installDir\secure-edge-agent.exe"
    Copy-Item config.yaml "$dataDir\"
    Copy-Item profile.json "$dataDir\"

    # Register the SecureEdge Windows service via the shipped script.
    # The script's defaults match the install layout above
    # (C:\Program Files\SecureEdge\bin\secure-edge-agent.exe +
    # C:\ProgramData\SecureEdge\config.yaml). The agent's first run
    # under the service mints the api_token, writes it to
    # %ProgramData%\SecureEdge\api_token, and starts fetching the
    # signed manifest from rule_update_url. See §1 and §4.
    & "$PSScriptRoot\register-service.ps1" install
    ```

    Detection rule: file exists at
    `%ProgramFiles%\SecureEdge\bin\secure-edge-agent.exe`. (The
    `api_token` is minted by the agent on first run, so an
    install-time detection rule must not depend on it — otherwise
    Intune races the first-run and may retry the install.)

2. **Device configuration policy — ADMX.** Use the Chrome ADMX
   templates already installed in your Intune tenant. Configure:

    - `ExtensionInstallForcelist`: append
      `<extension-id>;https://clients2.google.com/service/update2/crx`.
    - `ExtensionSettings`: paste the JSON from §10.2 inline.

3. **Assignment scope.** Assign both the Win32 app and the ADMX policy
   to the same Entra ID group. Stage the rollout: assign to a 5 % pilot
   group with the lenient `bridge_mac_required: false` posture, watch
   the agent log for `bridge MAC verification failed` warnings for one
   week, then flip the policy to `bridge_mac_required: true` and
   expand the assignment.

#### 10.3.3 VMware Workspace ONE (cross-platform)

Workspace ONE uses one **Product** per platform target. The
cross-platform appeal is that the same `profile.json` plus public-key
set ships to macOS, Windows, and Linux endpoints with only the
file-system layout changing.

1. **Files / Actions** payload — *Resources → Profiles & Baselines →
   Files / Actions*. Upload `profile.json` as a single archive.
   Per-platform extraction path:

    | Platform | Extract to |
    | --- | --- |
    | macOS | `/etc/secure-edge/` |
    | Windows | `%ProgramData%\SecureEdge\` |
    | Linux | `/etc/secure-edge/` |

2. **Custom Settings** payload — per platform, ship the `config.yaml`
   from §10.1. Workspace ONE renders the YAML inline; no
   plist-to-YAML translation step is required.

3. **Sensors and compliance** — define a sensor that watches for the
   agent's heartbeat (§7) and a compliance policy that flags any
   endpoint where the heartbeat endpoint has not received a 200 OK in
   the last 24 h. This catches an agent that has been killed without
   the tray icon turning red.

> **Workspace ONE signature gotcha.** Workspace ONE re-archives
> uploaded payloads before deploying them. The on-disk filename has to
> match what `config.yaml` references via `profile_path` — Workspace
> ONE will rename files inside an archive in some configurations.
> Verify with a single test endpoint before rolling out: the agent log
> emits one line on profile load failure with the absolute path it
> tried.

### 10.4 Defence-in-depth checklist

| Layer | Where it lives | Verified by |
| --- | --- | --- |
| Browser extension policy | MDM-managed `ExtensionInstallForcelist` | Browser admin console — extension cannot be removed by the user |
| Per-install bearer token | `api_token_path` on disk; `api_token_required: true` | `GET /api/status` returns 401 without `Authorization: Bearer …` |
| Native-Messaging HMAC bridge | `bridge_mac_required: true` (reuses `api_token` as HMAC key) | Agent stderr emits `bridge MAC verification failed` when an older extension talks to a strict-mode agent (§2.2) |
| Signed rule manifest | `rule_update_public_key` configured; `manifest.json` produced by `sign-rule-manifest` | Agent log line on rule update; refuses to load an unverified manifest (§4) |
| Signed enterprise profile | `profile_public_key` configured; `profile.json` produced by `sign-enterprise-profile` | Agent log line on profile load; refuses to load an unsigned profile when the key is configured (§3.1) |
| Risky-extension blocklist | Optional `risky_file_extensions` override; baked-in 34-entry default otherwise | Extension surfaces the policy toast on `<input type=file>`, drag-drop, and clipboard paste (§2.3) |

Each row is independently verifiable from the agent log or a single
API probe. A row failing in isolation does not break the others (every
defence is layered), but a persistent failure should be treated as a
deployment regression and the previous bundle rolled back.
