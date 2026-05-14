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

import {
    AGENT_BASE,
    ENFORCEMENT_MODE_STORAGE_KEY,
    EnforcementMode,
    EnforcementModeReply,
    EnforcementModeRequest,
    ScanReply,
    ScanRequest,
    ScanResult,
} from "../shared.js";

/** Single-scan timeout. The Tier-2 AI pages are interactive — if
 *  the agent doesn't answer within this budget we fall open so we
 *  don't freeze the user's typing / submission. */
const SCAN_TIMEOUT_MS = 1500;

/** Maximum content size sent to the agent. Anything larger is
 *  silently allowed in personal/team modes — not a realistic prompt
 *  and an obvious memory-exhaustion vector for the agent. In
 *  "managed" mode an oversized payload is blocked outright (see
 *  policyForOversize below). */
export const MAX_SCAN_BYTES = 1 * 1024 * 1024; // 1 MiB

/** In-process cache of the active enforcement mode. The source of
 *  truth lives in the background service worker (which polls the
 *  agent on a TTL); this cache is just a synchronous read for the
 *  hot path of content-script interception. Default is "personal"
 *  so a content script that never finished bootstrapping behaves
 *  identically to the pre-C2 release. */
let cachedEnforcementMode: EnforcementMode = "personal";

/** True once the script has at least attempted to populate the
 *  cache from the service worker (or chrome.storage.session). Used
 *  so the first hot-path call kicks off a bootstrap without waiting
 *  for an external refresh trigger. */
let enforcementModeBootstrapped = false;

/** Returns the enforcement mode the page-side policy helpers will
 *  use right now. Synchronous so size guards in click/paste/submit
 *  handlers don't have to await. */
export function getCachedEnforcementMode(): EnforcementMode {
    return cachedEnforcementMode;
}

/** Refresh the cached enforcement mode from the background service
 *  worker (which holds the canonical value fetched from the agent).
 *  Falls back to chrome.storage.session, then leaves the previous
 *  value intact on any failure so a transient service-worker
 *  eviction doesn't flip every page back to "personal" mid-session.
 *  Returns the value now in the cache. */
export async function refreshEnforcementMode(): Promise<EnforcementMode> {
    enforcementModeBootstrapped = true;
    const viaWorker = await readEnforcementModeFromWorker();
    if (viaWorker !== null) {
        cachedEnforcementMode = viaWorker;
        return cachedEnforcementMode;
    }
    const viaStorage = await readEnforcementModeFromStorage();
    if (viaStorage !== null) {
        cachedEnforcementMode = viaStorage;
    }
    return cachedEnforcementMode;
}

/** Boot the enforcement-mode cache exactly once per content-script
 *  lifetime. Safe to call from a module top-level — failures stay
 *  silent and the default "personal" remains active. */
export function ensureEnforcementModeBootstrapped(): void {
    if (enforcementModeBootstrapped) return;
    enforcementModeBootstrapped = true;
    void refreshEnforcementMode();
}

/** Fall-policy directive returned by policyForUnavailable /
 *  policyForOversize. Each interceptor maps this to the UI signal
 *  appropriate for its event source (paste/drop/submit/network). */
export type FallPolicy = "allow" | "warn" | "block";

/** Policy directive when the agent returns no verdict (timeout,
 *  401, network error, etc.). personal=allow, team=warn, managed=
 *  block. Driven by the cached mode so callers never block
 *  themselves on the bootstrap fetch. */
export function policyForUnavailable(mode: EnforcementMode = cachedEnforcementMode): FallPolicy {
    switch (mode) {
        case "managed":
            return "block";
        case "team":
            return "warn";
        default:
            return "allow";
    }
}

/** Policy directive when the content exceeds MAX_SCAN_BYTES and the
 *  agent never gets a chance to look at it. The plan keeps
 *  personal/team in their current silent-allow stance and only
 *  flips managed to block — an enterprise that opts into managed
 *  mode explicitly wants oversized payloads stopped at the edge
 *  rather than slipping past the inline-scan limit. */
export function policyForOversize(mode: EnforcementMode = cachedEnforcementMode): FallPolicy {
    return mode === "managed" ? "block" : "allow";
}

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

/** Ask the background service worker for the cached enforcement
 *  mode. Returns null on any failure so the caller falls through to
 *  the storage path. */
async function readEnforcementModeFromWorker(): Promise<EnforcementMode | null> {
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.sendMessage !== "function") return null;
    try {
        const req: EnforcementModeRequest = { kind: "enforcement-mode" };
        const reply = (await runtime.sendMessage(req)) as EnforcementModeReply | undefined;
        if (reply && reply.kind === "enforcement-mode-result") return reply.mode;
    } catch {
        // service worker asleep, no receiving end, etc.
    }
    return null;
}

/** Storage-fallback path. The service worker mirrors every refresh
 *  into chrome.storage.session; on a worker eviction the storage
 *  read still surfaces the mode the operator last configured. */
async function readEnforcementModeFromStorage(): Promise<EnforcementMode | null> {
    try {
        const c = typeof chrome !== "undefined" ? chrome : undefined;
        const session = c?.storage?.session;
        if (!session) return null;
        const got = await session.get(ENFORCEMENT_MODE_STORAGE_KEY);
        const m = got[ENFORCEMENT_MODE_STORAGE_KEY];
        if (m === "personal" || m === "team" || m === "managed") return m;
    } catch {
        /* storage unavailable. */
    }
    return null;
}

// Export for tests; not part of the production entrypoint surface.
export const __test__ = {
    scanViaWorker,
    scanViaHTTP,
    SCAN_TIMEOUT_MS,
    /** Force the cached mode to a known value. Tests must call
     *  reset() in afterEach to avoid bleeding state across cases. */
    setCachedEnforcementMode(mode: EnforcementMode): void {
        cachedEnforcementMode = mode;
        enforcementModeBootstrapped = true;
    },
    resetEnforcementMode(): void {
        cachedEnforcementMode = "personal";
        enforcementModeBootstrapped = false;
    },
    readEnforcementModeFromWorker,
    readEnforcementModeFromStorage,
};
