# Secure Edge User Guide

This guide is for end-users of Secure Edge.

## 1. The tray icon

A small shield icon sits in your system tray.

- **Green shield** — agent running, all rules loaded, no integrity issues.
- **Red shield** — agent is offline or a tamper alert is active. Open the tray
  menu and click **Status** to see the cause (e.g. service stopped, rule file
  modified).

Clicking the tray icon opens a small menu:

- **Status** — quick view of agent health and aggregate counters.
- **Settings** — managed-mode banner if your org enrolled this host, otherwise
  category toggles (Allow / Inspect / Block) for each policy tier.
- **Quit** — stops the agent.

The agent is designed to be invisible during normal use. You only see the tray
icon and, occasionally, a block notification.

## 2. Block notifications

When you paste or upload content that matches a DLP rule, you'll see a small
ephemeral notification in the corner of your screen:

> 🛡 **Blocked**: your message contained an API token (pattern: *GitHub PAT*).

A few things to know:

- The notification fades after a few seconds. There is **no record** of which
  content was blocked beyond a single counter (`dlp_blocks_total`).
- The text you tried to send is **never** stored, logged, or transmitted.
- The block happens at the browser extension or proxy layer — the destination
  service never receives the content.

If you believe the block was wrong, you can **report a false positive** (see
§4).

## 3. What data the agent does / does not collect

Secure Edge stores only policy settings and five anonymous counters
(`dns_queries_total`, `dns_blocks_total`, `dlp_scans_total`,
`dlp_blocks_total`, `tamper_detections_total`). It never stores
domains, URLs, or anything you type. For the technical guarantee, see
the [README](../README.md#privacy-invariant).

## 4. Reporting a false positive

If a block looks wrong:

1. **Note the pattern name** shown in the tray notification (e.g.
   *Stripe Secret Key*).
2. Open a bug report on the
   [GitHub repo](https://github.com/kennguy3n/secure-edge/issues/new?template=bug_report.md)
   titled `[false positive] <pattern name>`.
3. Include the pattern name and a **redacted snippet** of the content
   that triggered the block. Do **not** paste the actual secret-looking
   string — replace the secret-shaped part with `<redacted>` or generic
   placeholders.
4. Maintainers will triage and either tighten the pattern, add an
   exclusion, or close the issue with an explanation.

We track FP / FN rates against a 50-sample smoke corpus in
[`agent/internal/dlp/accuracy_smoke_test.go`](../agent/internal/dlp/accuracy_smoke_test.go).
The budget is **FP < 10 %** and **FN < 5 %**; a pattern that takes us out
of budget will not merge.

## 5. Browser extension behaviour

If the browser extension is installed:

- It hooks the paste and form-submit events for the Tier-2 domains in the
  active ruleset.
- Tier-1 domains are passed through with no inspection.
- Tier-3/Tier-4 domains never resolve (DNS NXDOMAIN), so the extension never
  sees them.

The extension speaks to the agent over Native Messaging (stdin/stdout)
or the HTTP fallback on `127.0.0.1:8080`. It does not call out to any
external service. Source code lives in
[`extension/`](../extension/) — TypeScript with content scripts, background
worker, and unit tests.

## 6. Disabling the agent

Use the tray menu's **Quit** entry to stop the agent. Re-launch it via the
desktop shortcut, the macOS Login Items list, or systemd. If your org
enrolled this host in managed mode, the agent will re-launch automatically
within ~30 seconds.
