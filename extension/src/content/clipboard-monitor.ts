// Clipboard monitor content script (Phase 6 Task 14).
//
// Off by default. When the user opts in via the extension options
// page (Task 13), we ask the browser for the current clipboard text
// whenever a Tier-2 AI tool tab gains focus and pre-scan it. If the
// clipboard already contains a blocked secret we surface the toast
// before the user has a chance to paste it.
//
// Privacy invariant: the clipboard text never leaves the local
// machine (the scan goes to 127.0.0.1) and is never persisted.
// Clipboard access requires the navigator.clipboard.readText() Web
// API; failures are silent fall-open like every other interceptor.

import { scanContent, MAX_SCAN_BYTES } from "./scan-client.js";
import { showBlockedToast } from "./toast.js";

/** Storage key for the opt-in flag set by the options page. */
const STORAGE_KEY = "secureEdge:clipboardMonitor";

/** Minimum delay between consecutive clipboard reads. Prevents the
 *  monitor from hammering the clipboard API on a noisy focus loop. */
const SCAN_INTERVAL_MS = 1500;

/** Tracks the digest of the last scanned clipboard text so we don't
 *  re-scan the same secret on every focus event. Stored as a length
 *  + first/last char fingerprint — not the original text. */
let lastFingerprint = "";
let lastScanAt = 0;

if (typeof document !== "undefined") {
    document.addEventListener(
        "focus",
        () => void maybeScanClipboard(),
        { capture: true },
    );
    if (typeof window !== "undefined") {
        window.addEventListener("focus", () => void maybeScanClipboard());
    }
}

export async function maybeScanClipboard(): Promise<void> {
    const enabled = await readEnabledFlag();
    if (!enabled) return;

    const now = Date.now();
    if (now - lastScanAt < SCAN_INTERVAL_MS) return;
    lastScanAt = now;

    let text = "";
    try {
        const nav = (globalThis as { navigator?: Navigator }).navigator;
        if (!nav || !nav.clipboard || !nav.clipboard.readText) return;
        text = await nav.clipboard.readText();
    } catch {
        // User declined permission, or the document doesn't have
        // focus. Silent fall-open is the safe default.
        return;
    }
    if (!text || text.length === 0 || text.length > MAX_SCAN_BYTES) return;

    const fp = fingerprint(text);
    if (fp === lastFingerprint) return;
    lastFingerprint = fp;

    const result = await scanContent(text);
    if (!result || !result.blocked) return;
    showBlockedToast(result.pattern_name, "clipboard");
}

/**
 * fingerprint produces a deterministic short string that lets us
 * cheaply detect "same clipboard content as last time" without
 * storing the original text. It is intentionally not a secure hash —
 * we don't need crypto guarantees, just a stable identifier.
 */
function fingerprint(s: string): string {
    if (s.length === 0) return "0";
    const first = s.charCodeAt(0).toString(16);
    const last = s.charCodeAt(s.length - 1).toString(16);
    return `${s.length}:${first}:${last}`;
}

async function readEnabledFlag(): Promise<boolean> {
    try {
        const c = typeof chrome !== "undefined" ? chrome : undefined;
        if (!c || !c.storage || !c.storage.local) return false;
        const got = await c.storage.local.get(STORAGE_KEY);
        return Boolean(got[STORAGE_KEY]);
    } catch {
        return false;
    }
}

export const __test__ = { maybeScanClipboard, fingerprint, STORAGE_KEY, readEnabledFlag };
