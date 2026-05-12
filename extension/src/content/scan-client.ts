// Shared DLP-scan helper for every content-script interceptor.
//
// Each interceptor (paste, form, fetch/XHR) calls scanContent(text)
// and treats `null` as "fall open" (allow the action). The transport
// preference is:
//
//   1. chrome.runtime.sendMessage to the background service worker,
//      which tries Native Messaging first and falls back to HTTP.
//      This avoids CORS on Tier-2 AI pages entirely — the worker
//      runs in the extension origin, not the page origin.
//   2. Direct fetch() to http://127.0.0.1:8080/api/dlp/scan from the
//      content script. Works when the background worker is asleep
//      and the page's origin is in the agent's CORS allowlist.
//
// Either path returning a non-null ScanResult is authoritative.

import { AGENT_BASE, ScanReply, ScanRequest, ScanResult } from "../shared.js";

/** Single-scan timeout. The Tier-2 AI pages are interactive — if
 *  the agent doesn't answer within this budget we fall open so we
 *  don't freeze the user's typing / submission. */
const SCAN_TIMEOUT_MS = 1500;

/** Maximum content size sent to the agent. Anything larger is
 *  silently allowed — not a realistic prompt and an obvious
 *  memory-exhaustion vector for the agent. */
export const MAX_SCAN_BYTES = 1 * 1024 * 1024; // 1 MiB

/** Scan `content` through the local agent's DLP pipeline.
 *  Returns null on any transport failure (fall-open). */
export async function scanContent(content: string): Promise<ScanResult | null> {
    if (content.length === 0 || content.length > MAX_SCAN_BYTES) return null;

    // Path 1: route through the background service worker so Native
    // Messaging is tried before HTTP. The worker owns the long-lived
    // port; content scripts can't open connectNative() themselves.
    const viaWorker = await scanViaWorker(content);
    if (viaWorker !== undefined) return viaWorker;

    // Path 2: direct loopback fetch. Same shape as the worker's HTTP
    // fallback, but inlined so a sleeping worker doesn't lose us a scan.
    return scanViaHTTP(content);
}

async function scanViaWorker(content: string): Promise<ScanResult | null | undefined> {
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.sendMessage !== "function") return undefined;
    try {
        const req: ScanRequest = { kind: "scan", content };
        const reply = (await runtime.sendMessage(req)) as ScanReply | undefined;
        if (reply && reply.kind === "scan-result") return reply.result;
    } catch {
        // service worker not listening, no receiving end, etc. —
        // fall through to HTTP.
    }
    return undefined;
}

async function scanViaHTTP(content: string): Promise<ScanResult | null> {
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

// Export for tests; not part of the production entrypoint surface.
export const __test__ = { scanViaWorker, scanViaHTTP, SCAN_TIMEOUT_MS };
