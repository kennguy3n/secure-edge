// In-page ephemeral toast renderer for DLP-blocked actions.
//
// All Tier-2 content scripts share this helper so the user sees a
// consistent "Secure Edge blocked …" message regardless of which
// interceptor (paste / form / fetch / XHR) tripped the pipeline.
//
// The toast displays the matched pattern *name* only — never the
// matched content — and disappears after NOTIFICATION_TTL_MS.

export type BlockedKind = "paste" | "submission" | "request" | "drop" | "clipboard" | "upload";

const NOTIFICATION_TTL_MS = 5000;
const TOAST_ID = "secure-edge-blocked-toast";

/** Reason a policy-level toast surfaces. "agent-unavailable" is the
 *  managed-mode block when the agent doesn't return a verdict;
 *  "oversize" is the managed-mode block for payloads above the
 *  inline-scan limit. Both also surface in team mode as warnings. */
export type PolicyReason = "agent-unavailable" | "oversize";

/** Render an ephemeral toast announcing a DLP block. No-op in
 *  non-DOM environments (e.g. node test runner). */
export function showBlockedToast(patternName: string, kind: BlockedKind = "paste"): void {
    renderToast({
        text: `Secure Edge blocked this ${kind} (${sanitise(patternName)}).`,
        palette: blockPalette,
    });
}

/** Surface a managed-mode policy block. Used when the agent is
 *  unreachable (no verdict) or the content exceeds MAX_SCAN_BYTES,
 *  and the operator has opted into "managed" enforcement. The
 *  message intentionally distinguishes the policy reason from a
 *  pattern match so the user can tell "Secure Edge would have
 *  scanned but couldn't" apart from "Secure Edge matched a pattern". */
export function showPolicyBlockedToast(reason: PolicyReason, kind: BlockedKind = "paste"): void {
    renderToast({
        text: policyMessage("block", reason, kind),
        palette: blockPalette,
    });
}

/** Surface a team-mode warning. The action still goes through (the
 *  caller falls open) but the user knows the scan was skipped so
 *  they can choose to retry once the agent is reachable. The
 *  warning palette is intentionally yellow rather than red — a
 *  block toast and a warn toast must never look identical or users
 *  will learn to ignore both. */
export function showPolicyWarnToast(reason: PolicyReason, kind: BlockedKind = "paste"): void {
    renderToast({
        text: policyMessage("warn", reason, kind),
        palette: warnPalette,
    });
}

interface Palette {
    background: string;
    color: string;
    border: string;
}

const blockPalette: Palette = {
    background: "#fef2f2",
    color: "#7f1d1d",
    border: "#fecaca",
};

const warnPalette: Palette = {
    background: "#fffbeb",
    color: "#78350f",
    border: "#fde68a",
};

function renderToast(opts: { text: string; palette: Palette }): void {
    if (typeof document === "undefined" || !document.body) return;

    document.getElementById(TOAST_ID)?.remove();

    const toast = document.createElement("div");
    toast.id = TOAST_ID;
    toast.setAttribute("role", "status");
    toast.style.cssText = [
        "position:fixed",
        "right:16px",
        "bottom:16px",
        "z-index:2147483647",
        `background:${opts.palette.background}`,
        `color:${opts.palette.color}`,
        `border:1px solid ${opts.palette.border}`,
        "border-radius:6px",
        "padding:10px 14px",
        "font:13px/1.4 system-ui,sans-serif",
        "box-shadow:0 4px 16px rgba(0,0,0,.15)",
        "max-width:320px",
    ].join(";");
    toast.textContent = opts.text;

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), NOTIFICATION_TTL_MS);
}

function policyMessage(level: "block" | "warn", reason: PolicyReason, kind: BlockedKind): string {
    const prefix = level === "block" ? "Secure Edge blocked" : "Secure Edge could not scan";
    switch (reason) {
        case "agent-unavailable":
            return level === "block"
                ? `${prefix} this ${kind} \u2014 agent unavailable, blocked by policy.`
                : `${prefix} this ${kind} \u2014 agent unavailable, scan skipped.`;
        case "oversize":
            return level === "block"
                ? `${prefix} this ${kind} \u2014 content too large for inline scan, blocked by policy.`
                : `${prefix} this ${kind} \u2014 content too large for inline scan, skipped.`;
    }
}

/** Strip non-printable / non-ASCII characters from a pattern name so
 *  a tampered rule file cannot inject HTML or break out of the toast.
 *  Caps the length to keep the toast a single line. */
export function sanitise(s: string): string {
    return s.replace(/[^\x20-\x7e]/g, "").slice(0, 80);
}

// Exported for tests; not part of the production entrypoint surface.
export const __test__ = { policyMessage };
