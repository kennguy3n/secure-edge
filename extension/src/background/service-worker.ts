// Background service worker for the Secure Edge companion extension.
//
// Responsibilities (MV3):
//   1. Reply to popup "ping" requests with the agent /api/status payload.
//   2. Reply to content-script "scan" requests by trying Native Messaging
//      first, falling back to HTTP. This is the only place in the
//      extension that owns the chrome.runtime.connectNative port — content
//      scripts cannot open native connections themselves.
//   3. Surface a clear connection error when the local agent is down.

import {
    AGENT_BASE,
    ENFORCEMENT_MODE_STORAGE_KEY,
    EnforcementMode,
    EnforcementModeReply,
    EnforcementModeRequest,
    EnforcementModeResponse,
    PopupRequest,
    PopupReply,
    RISKY_EXTENSIONS_STORAGE_KEY,
    RiskyExtensionsReply,
    RiskyExtensionsRequest,
    RiskyExtensionsResponse,
    ScanRequest,
    ScanReply,
    ScanResult,
    StatusResponse,
} from "../shared.js";
import {
    helloViaNativeMessaging,
    scanViaNativeMessaging,
    setBridgeEnforcementMode,
} from "./native-messaging.js";
import { startDynamicHostUpdater } from "./dynamic-hosts.js";

// chrome.storage.session key under which the per-install API
// capability token is cached (work item A2). The token is fetched
// from the agent over Native Messaging at service-worker boot and
// every time the cached value is missing; refreshing it on each
// service-worker spin-up is cheap and avoids needing a separate
// invalidation path.
const API_TOKEN_KEY = "secureEdgeAPIToken";

/** TTL for the cached enforcement mode. The mode is operator-set in
 *  config.yaml + an agent restart, so a fresh fetch every five
 *  minutes is plenty to pick up a posture change without spamming
 *  the local agent on every page navigation. The cache is
 *  process-local; a service-worker eviction drops it and the next
 *  request triggers a fresh fetch. */
const ENFORCEMENT_MODE_TTL_MS = 5 * 60 * 1000;

/** TTL for the cached risky-file-extension blocklist (Phase 7 / B2).
 *  Same cadence as the enforcement-mode cache: an operator change
 *  takes effect on the next refresh (or on a service-worker
 *  cold-start). The cache is process-local. */
const RISKY_EXTENSIONS_TTL_MS = 5 * 60 * 1000;

/** In-memory cache for the active enforcement mode. Default is the
 *  privacy-first fall-open posture so the extension preserves its
 *  pre-C2 behaviour when the agent has never been reached. */
let cachedEnforcementMode: EnforcementMode = "personal";
let cachedEnforcementModeAt = 0;

/** True when no caller has refreshed the cache yet in this worker
 *  lifetime. Used so the first runtime.onMessage path triggers a
 *  fetch regardless of the TTL clock — a fresh worker cold-start
 *  shouldn't wait for the timer to expire before talking to the
 *  agent. */
let enforcementModeEverFetched = false;

/** In-memory cache for the risky-extension blocklist override. The
 *  "default" mode (the agent omitted the `extensions` field) is the
 *  cold-start default so a content script that races the bootstrap
 *  still falls safe — it uses its baked-in list, which is the
 *  always-block stance. */
let cachedRiskyExtensionsMode: "default" | "configured" = "default";
let cachedRiskyExtensions: ReadonlyArray<string> = [];
let cachedRiskyExtensionsAt = 0;
let riskyExtensionsEverFetched = false;

// Boot the dynamic Tier-2 host updater. Polls /api/rules/status and
// registers content scripts for any custom hosts the agent's rule
// file adds at runtime — no extension reload needed (Phase 6 Task 12).
try {
    startDynamicHostUpdater();
} catch {
    // chrome.scripting may be unavailable in the test harness; the
    // catch keeps service-worker boot quiet in that environment.
}

// Best-effort token bootstrap on service-worker start. A null reply
// (host unavailable, agent pre-A2, or empty token configured) leaves
// the storage entry untouched so the HTTP fallback drops the
// Authorization header and the request reaches a pre-A2 agent
// unchanged.
void bootstrapAPIToken();

async function bootstrapAPIToken(): Promise<void> {
    try {
        const token = await helloViaNativeMessaging();
        if (token) {
            await sessionStorageSet(API_TOKEN_KEY, token);
        }
    } catch {
        // Native Messaging is best-effort here. The HTTP fallback
        // path will still work, just without an Authorization
        // header. A post-A2 agent with api_token_required=true
        // returns 401 in that case, which scanViaHTTP treats as a
        // fall-open / null result.
    }
}

async function getCachedAPIToken(): Promise<string | null> {
    const v = await sessionStorageGet(API_TOKEN_KEY);
    return typeof v === "string" && v.length > 0 ? v : null;
}

// sessionStorageGet / sessionStorageSet wrap chrome.storage.session
// so the service-worker boot path tolerates older Chrome builds
// that don't expose the session area (it was added in M102). When
// the API is missing we treat the cache as permanently empty —
// every fetch will then re-fetch via Native Messaging, which is
// still correct, just less efficient.
async function sessionStorageGet(key: string): Promise<unknown> {
    const storage = (chrome as { storage?: { session?: chrome.storage.StorageArea } }).storage;
    const area = storage?.session;
    if (!area) return undefined;
    return new Promise((resolve) => {
        try {
            area.get(key, (items) => resolve(items?.[key]));
        } catch {
            resolve(undefined);
        }
    });
}

async function sessionStorageSet(key: string, value: string): Promise<void> {
    const storage = (chrome as { storage?: { session?: chrome.storage.StorageArea } }).storage;
    const area = storage?.session;
    if (!area) return;
    await new Promise<void>((resolve) => {
        try {
            area.set({ [key]: value }, () => resolve());
        } catch {
            resolve();
        }
    });
}

type IncomingMessage =
    | PopupRequest
    | ScanRequest
    | EnforcementModeRequest
    | RiskyExtensionsRequest;
type OutgoingReply = PopupReply | ScanReply | EnforcementModeReply | RiskyExtensionsReply;

chrome.runtime.onMessage.addListener(
    (msg: IncomingMessage, _sender, sendResponse: (reply: OutgoingReply) => void) => {
        if (msg && msg.kind === "ping") {
            void pingAgent().then(sendResponse);
            return true; // keep the channel open for the async reply
        }
        if (msg && msg.kind === "scan") {
            void handleScan(msg.content).then((result) =>
                sendResponse({ kind: "scan-result", result }),
            );
            return true;
        }
        if (msg && msg.kind === "enforcement-mode") {
            void getEnforcementMode().then((mode) =>
                sendResponse({ kind: "enforcement-mode-result", mode }),
            );
            return true;
        }
        if (msg && msg.kind === "risky-extensions") {
            void getRiskyExtensions().then(({ mode, extensions }) =>
                sendResponse({
                    kind: "risky-extensions-result",
                    mode,
                    extensions,
                }),
            );
            return true;
        }
        sendResponse({ kind: "error", message: `unknown message: ${JSON.stringify(msg)}` });
        return false;
    },
);

async function pingAgent(): Promise<PopupReply> {
    try {
        const r = await fetch(`${AGENT_BASE}/api/status`, {
            method: "GET",
            mode: "cors",
            credentials: "omit",
            headers: await authHeaders(),
        });
        if (!r.ok) {
            return { kind: "error", message: `agent returned HTTP ${r.status}` };
        }
        const body = (await r.json()) as StatusResponse;
        return {
            kind: "ok",
            version: body.version ?? "unknown",
            uptime_seconds: body.uptime_seconds ?? 0,
        };
    } catch (err) {
        return {
            kind: "error",
            message: err instanceof Error ? err.message : "agent unreachable",
        };
    }
}

/** Try Native Messaging first, fall back to loopback HTTP. Returns
 *  null on any failure so the content script can fall open. */
export async function handleScan(content: string): Promise<ScanResult | null> {
    const native = await scanViaNativeMessaging(content);
    if (native !== null) return native;
    return scanViaHTTP(content);
}

async function scanViaHTTP(content: string): Promise<ScanResult | null> {
    try {
        const r = await fetch(`${AGENT_BASE}/api/dlp/scan`, {
            method: "POST",
            mode: "cors",
            credentials: "omit",
            headers: {
                "Content-Type": "application/json",
                ...(await authHeaders()),
            },
            body: JSON.stringify({ content }),
        });
        if (r.status === 401) {
            // Agent rotated its token or we never received one. A
            // single re-bootstrap on 401 is cheap and avoids a
            // permanently broken HTTP path after the service worker
            // sleeps and reawakens against an updated agent.
            await bootstrapAPIToken();
            return null;
        }
        if (!r.ok) return null;
        return (await r.json()) as ScanResult;
    } catch {
        return null;
    }
}

// authHeaders returns the optional Authorization header carrying the
// per-install API capability token (work item A2). Returns {} when
// no token is cached so the HTTP fallback against a pre-A2 agent is
// byte-identical to its current request shape.
async function authHeaders(): Promise<Record<string, string>> {
    const token = await getCachedAPIToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Return the current enforcement mode, refreshing from the agent
 *  when the cache is empty or older than ENFORCEMENT_MODE_TTL_MS.
 *  Any fetch failure leaves the cached value intact so a flaky agent
 *  doesn't flip every page back to "personal" mid-session.
 *  Exported for tests. */
export async function getEnforcementMode(): Promise<EnforcementMode> {
    const now = Date.now();
    if (enforcementModeEverFetched && now - cachedEnforcementModeAt < ENFORCEMENT_MODE_TTL_MS) {
        return cachedEnforcementMode;
    }
    const fresh = await fetchEnforcementMode();
    if (fresh !== null) {
        cachedEnforcementMode = fresh;
        cachedEnforcementModeAt = now;
        enforcementModeEverFetched = true;
        // Mirror the new value into the Native Messaging module so
        // the bridge's MAC-failure fall-closed gate (G4) reads the
        // same enforcement state as runtime.onMessage handlers.
        setBridgeEnforcementMode(fresh);
        await persistEnforcementMode(fresh);
    }
    return cachedEnforcementMode;
}

/** GET /api/config/enforcement-mode and return the parsed mode.
 *  Returns null on any transport / parse error so the caller can
 *  decide whether to keep the previous value or fall back to the
 *  default. The endpoint is intentionally CORS-allowed for the
 *  extension origin; control-plane authentication does not gate
 *  read-only config endpoints. */
async function fetchEnforcementMode(): Promise<EnforcementMode | null> {
    try {
        const r = await fetch(`${AGENT_BASE}/api/config/enforcement-mode`, {
            method: "GET",
            mode: "cors",
            credentials: "omit",
        });
        if (!r.ok) return null;
        const body = (await r.json()) as EnforcementModeResponse;
        const m = body.mode;
        if (m === "personal" || m === "team" || m === "managed") return m;
        return null;
    } catch {
        return null;
    }
}

/** Mirror the current mode into chrome.storage.session so a
 *  content-script fast path (or a future popup surface) can read it
 *  without a runtime.sendMessage round trip. Storage failures are
 *  silently swallowed; runtime.sendMessage stays the source of
 *  truth. */
async function persistEnforcementMode(mode: EnforcementMode): Promise<void> {
    try {
        const c = typeof chrome !== "undefined" ? chrome : undefined;
        const session = c?.storage?.session;
        if (!session) return;
        await session.set({ [ENFORCEMENT_MODE_STORAGE_KEY]: mode });
    } catch {
        /* storage unavailable; mode stays in-process only. */
    }
}

/** Phase 7 / B2 risky-file-extension cache accessor. Returns the
 *  current cache, refreshing from the agent when the cache is empty
 *  or older than RISKY_EXTENSIONS_TTL_MS. Any fetch failure leaves
 *  the cached value intact so a flaky agent doesn't flip every
 *  page back to the baked-in default mid-session.
 *
 *  The return shape mirrors the wire contract:
 *    mode: "default"     — agent omitted `extensions`; the
 *                          content script should use its baked-in
 *                          list. `extensions` is an empty array on
 *                          this variant.
 *    mode: "configured"  — agent supplied a list (possibly empty
 *                          for opt-out); use it verbatim.
 *
 *  Exported for tests. */
export async function getRiskyExtensions(): Promise<{
    mode: "default" | "configured";
    extensions: ReadonlyArray<string>;
}> {
    const now = Date.now();
    if (
        riskyExtensionsEverFetched &&
        now - cachedRiskyExtensionsAt < RISKY_EXTENSIONS_TTL_MS
    ) {
        return { mode: cachedRiskyExtensionsMode, extensions: cachedRiskyExtensions };
    }
    const fresh = await fetchRiskyExtensions();
    if (fresh !== null) {
        cachedRiskyExtensionsMode = fresh.mode;
        cachedRiskyExtensions = fresh.extensions;
        cachedRiskyExtensionsAt = now;
        riskyExtensionsEverFetched = true;
        await persistRiskyExtensions(fresh);
    }
    return { mode: cachedRiskyExtensionsMode, extensions: cachedRiskyExtensions };
}

/** GET /api/config/risky-extensions and return the parsed reply.
 *  Returns null on any transport / parse error so the caller can
 *  keep the previous cached value. */
async function fetchRiskyExtensions(): Promise<
    { mode: "default" | "configured"; extensions: ReadonlyArray<string> } | null
> {
    try {
        const r = await fetch(`${AGENT_BASE}/api/config/risky-extensions`, {
            method: "GET",
            mode: "cors",
            credentials: "omit",
        });
        if (!r.ok) return null;
        const body = (await r.json()) as RiskyExtensionsResponse;
        // The wire contract: `extensions` absent → "default";
        // present (including the empty array opt-out wire shape)
        // → "configured". The agent already normalises entries to
        // dot-less lowercase form; we accept whatever it sent.
        if (!body || !Object.prototype.hasOwnProperty.call(body, "extensions")) {
            return { mode: "default", extensions: [] };
        }
        const exts = Array.isArray(body.extensions)
            ? body.extensions.filter((e): e is string => typeof e === "string")
            : [];
        return { mode: "configured", extensions: exts };
    } catch {
        return null;
    }
}

/** Mirror the current risky-extension cache into
 *  chrome.storage.session so a content-script fast path can read
 *  it without a runtime.sendMessage round trip after a
 *  service-worker eviction. Storage failures are silently
 *  swallowed; runtime.sendMessage stays the source of truth.
 *
 *  Storage shape:
 *    "default"  — baked-in list (mode === "default").
 *    [..]       — configured list (mode === "configured");
 *                 may be empty for the opt-out wire shape. */
async function persistRiskyExtensions(value: {
    mode: "default" | "configured";
    extensions: ReadonlyArray<string>;
}): Promise<void> {
    try {
        const c = typeof chrome !== "undefined" ? chrome : undefined;
        const session = c?.storage?.session;
        if (!session) return;
        const stored: unknown =
            value.mode === "default" ? "default" : Array.from(value.extensions);
        await session.set({ [RISKY_EXTENSIONS_STORAGE_KEY]: stored });
    } catch {
        /* storage unavailable; cache stays in-process only. */
    }
}

/** Exported test handle so unit tests can reset the cache between
 *  cases. Not part of the production surface. */
export const __test__ = {
    resetEnforcementMode(): void {
        cachedEnforcementMode = "personal";
        cachedEnforcementModeAt = 0;
        enforcementModeEverFetched = false;
        // Keep the bridge's locally-cached mode in sync with the
        // service-worker cache so tests that reset one don't leave
        // the other holding a stale managed-mode flag.
        setBridgeEnforcementMode("personal");
    },
    setEnforcementMode(mode: EnforcementMode, at: number): void {
        cachedEnforcementMode = mode;
        cachedEnforcementModeAt = at;
        enforcementModeEverFetched = true;
        setBridgeEnforcementMode(mode);
    },
    /** Reset the B2 cache (Phase 7) to its post-import state.
     *  Must be called from afterEach in any test that exercises
     *  getRiskyExtensions / fetchRiskyExtensions, otherwise the
     *  cached value bleeds across cases. */
    resetRiskyExtensions(): void {
        cachedRiskyExtensionsMode = "default";
        cachedRiskyExtensions = [];
        cachedRiskyExtensionsAt = 0;
        riskyExtensionsEverFetched = false;
    },
    setRiskyExtensions(
        mode: "default" | "configured",
        extensions: ReadonlyArray<string>,
        at: number,
    ): void {
        cachedRiskyExtensionsMode = mode;
        cachedRiskyExtensions = extensions;
        cachedRiskyExtensionsAt = at;
        riskyExtensionsEverFetched = true;
    },
    ENFORCEMENT_MODE_TTL_MS,
    RISKY_EXTENSIONS_TTL_MS,
};
