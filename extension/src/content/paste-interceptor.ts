// Paste interceptor content script.
//
// Listens for `paste` events on Tier 2 AI tool pages, extracts the
// pasted text, and sends it to the local Secure Edge agent
// (POST /api/dlp/scan). If the agent blocks, the paste is prevented
// and an ephemeral in-page notification shows the matched pattern name
// (never the matched content) and auto-dismisses after 5 seconds.
//
// Failure modes (agent unreachable, slow response, non-2xx) fall open:
// the paste proceeds so an outage of the agent does not break the
// user's workflow. The agent UI surfaces an offline indicator.

import { AGENT_BASE, ScanResult } from "../shared.js";

const SCAN_TIMEOUT_MS = 1500;
const NOTIFICATION_TTL_MS = 5000;
const MAX_PASTE_BYTES = 1 * 1024 * 1024; // 1 MiB — silently allow huge pastes.

document.addEventListener("paste", onPaste, { capture: true });

async function onPaste(ev: ClipboardEvent): Promise<void> {
    const data = ev.clipboardData;
    if (!data) return;
    const text = data.getData("text/plain");
    if (!text || text.length === 0) return;
    if (text.length > MAX_PASTE_BYTES) return;

    // Stop the paste while we ask the agent. We re-emit the paste
    // manually if the agent allows it (see resumePaste below).
    ev.preventDefault();
    ev.stopPropagation();

    const target = ev.target as EventTarget | null;
    const result = await scan(text);

    if (result === null) {
        // Agent unreachable → fall open: complete the paste.
        await resumePaste(target, text);
        return;
    }
    if (!result.blocked) {
        await resumePaste(target, text);
        return;
    }
    showNotification(result.pattern_name);
}

async function scan(content: string): Promise<ScanResult | null> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), SCAN_TIMEOUT_MS);
    try {
        const r = await fetch(`${AGENT_BASE}/api/dlp/scan`, {
            method: "POST",
            mode: "cors",
            credentials: "omit",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content }),
            signal: ctl.signal,
        });
        if (!r.ok) return null;
        return (await r.json()) as ScanResult;
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

async function resumePaste(target: EventTarget | null, text: string): Promise<void> {
    // Insert the text into the focused element. Two cases:
    //   1. <input> / <textarea> — set selectionStart/End and use
    //      document.execCommand('insertText') so the page sees the
    //      same event-stream it would have seen from a normal paste.
    //   2. contenteditable / rich editor — same insertText API.
    const el = (target instanceof HTMLElement ? target : document.activeElement) as HTMLElement | null;
    if (!el) return;
    el.focus();
    if (document.queryCommandSupported && document.queryCommandSupported("insertText")) {
        document.execCommand("insertText", false, text);
        return;
    }
    // Fallback for inputs/textareas without execCommand support.
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        const start = el.selectionStart ?? el.value.length;
        const end = el.selectionEnd ?? el.value.length;
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + text.length;
        el.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

function showNotification(patternName: string): void {
    const id = "secure-edge-blocked-toast";
    document.getElementById(id)?.remove();

    const toast = document.createElement("div");
    toast.id = id;
    toast.setAttribute("role", "status");
    toast.style.cssText = [
        "position:fixed",
        "right:16px",
        "bottom:16px",
        "z-index:2147483647",
        "background:#fef2f2",
        "color:#7f1d1d",
        "border:1px solid #fecaca",
        "border-radius:6px",
        "padding:10px 14px",
        "font:13px/1.4 system-ui,sans-serif",
        "box-shadow:0 4px 16px rgba(0,0,0,.15)",
        "max-width:320px",
    ].join(";");
    toast.textContent = `Secure Edge blocked this paste (${sanitise(patternName)}).`;

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), NOTIFICATION_TTL_MS);
}

// Strip anything that isn't a printable ASCII char so a malicious
// pattern_name (e.g. coming from a tampered rule file) can't inject
// HTML or break out of the toast.
function sanitise(s: string): string {
    return s.replace(/[^\x20-\x7e]/g, "").slice(0, 80);
}

// Export for tests; not used by the content-script entry path.
export const __test__ = { sanitise, scan, onPaste };
