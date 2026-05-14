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
    PopupRequest,
    PopupReply,
    ScanRequest,
    ScanReply,
    ScanResult,
    StatusResponse,
} from "../shared.js";
import { helloViaNativeMessaging, scanViaNativeMessaging } from "./native-messaging.js";
import { startDynamicHostUpdater } from "./dynamic-hosts.js";

// chrome.storage.session key under which the per-install API
// capability token is cached (work item A2). The token is fetched
// from the agent over Native Messaging at service-worker boot and
// every time the cached value is missing; refreshing it on each
// service-worker spin-up is cheap and avoids needing a separate
// invalidation path.
const API_TOKEN_KEY = "secureEdgeAPIToken";

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

type IncomingMessage = PopupRequest | ScanRequest;
type OutgoingReply = PopupReply | ScanReply;

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
