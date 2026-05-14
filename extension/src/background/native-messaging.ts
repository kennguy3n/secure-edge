// Native Messaging client for the Secure Edge agent.
//
// Chrome lets MV3 extensions talk to a "native messaging host" via a
// long-lived chrome.runtime.Port. The host is a separately-installed
// program registered in the user's NativeMessagingHosts directory.
// We use it from the service worker to avoid CORS entirely — the
// HTTP fallback always has to deal with whatever Tier-2 AI page's
// CORS posture happens to be.
//
// All public functions return null on any error (no native host
// installed, port disconnect, response timeout) so callers can
// trivially fall through to the HTTP path.

import { NATIVE_HOST, ScanResult } from "../shared.js";

/** Per-request timeout. Same budget as the HTTP fallback so a slow
 *  native host is no worse than a slow loopback. */
const REQUEST_TIMEOUT_MS = 1500;

interface PendingRequest {
    resolve: (r: ScanResult | null) => void;
    timer: ReturnType<typeof setTimeout>;
}

interface NativeMessage {
    id?: number;
    result?: ScanResult;
    // api_token is populated on a successful "hello" reply (work
    // item A2). Empty / undefined means "agent did not provide a
    // token" and the extension falls back to its pre-A2 HTTP
    // posture (no Authorization header).
    api_token?: string;
    error?: string;
}

interface PendingHello {
    resolve: (token: string | null) => void;
    timer: ReturnType<typeof setTimeout>;
}

let port: chrome.runtime.Port | null = null;
let nextId = 1;
const pending = new Map<number, PendingRequest>();
const pendingHello = new Map<number, PendingHello>();
let portUnsupported = false;

function ensurePort(): chrome.runtime.Port | null {
    if (port) return port;
    if (portUnsupported) return null;
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.connectNative !== "function") {
        portUnsupported = true;
        return null;
    }
    try {
        port = runtime.connectNative(NATIVE_HOST);
    } catch {
        portUnsupported = true;
        return null;
    }
    port.onMessage.addListener((raw: unknown) => {
        const msg = raw as NativeMessage;
        if (typeof msg.id !== "number") return;
        // Hello replies are routed first because their id space is
        // shared with scans — a hello reply with a matching id
        // would otherwise be silently discarded by the scan path.
        const helloReq = pendingHello.get(msg.id);
        if (helloReq) {
            pendingHello.delete(msg.id);
            clearTimeout(helloReq.timer);
            if (msg.error) {
                helloReq.resolve(null);
                return;
            }
            // An empty string from the agent means "no token
            // configured" — surface that as null so callers can
            // distinguish "feature off" from "have a token".
            const token = typeof msg.api_token === "string" && msg.api_token.length > 0
                ? msg.api_token
                : null;
            helloReq.resolve(token);
            return;
        }
        const req = pending.get(msg.id);
        if (!req) return;
        pending.delete(msg.id);
        clearTimeout(req.timer);
        if (msg.error) {
            req.resolve(null);
            return;
        }
        req.resolve(msg.result ?? null);
    });
    port.onDisconnect.addListener(() => {
        port = null;
        for (const r of pending.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pending.clear();
        for (const r of pendingHello.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pendingHello.clear();
    });
    return port;
}

/** Send `content` to the Native Messaging host for a DLP scan.
 *  Returns null when the host is unavailable, disconnects mid-request,
 *  or exceeds REQUEST_TIMEOUT_MS. Never throws. */
export function scanViaNativeMessaging(content: string): Promise<ScanResult | null> {
    const p = ensurePort();
    if (!p) return Promise.resolve(null);
    const id = nextId++;
    return new Promise<ScanResult | null>((resolve) => {
        const timer = setTimeout(() => {
            if (pending.delete(id)) resolve(null);
        }, REQUEST_TIMEOUT_MS);
        pending.set(id, { resolve, timer });
        try {
            p.postMessage({ id, kind: "scan", content });
        } catch {
            pending.delete(id);
            clearTimeout(timer);
            resolve(null);
        }
    });
}

/** Send a "hello" handshake to the Native Messaging host and
 *  resolve with the per-install API capability token the agent
 *  hands back (work item A2). Returns null when the host is
 *  unavailable, replies with an error, replies with an empty token,
 *  or exceeds REQUEST_TIMEOUT_MS. Never throws. The token returned
 *  here is then attached as "Authorization: Bearer <token>" on the
 *  service worker's HTTP fallback path. */
export function helloViaNativeMessaging(): Promise<string | null> {
    const p = ensurePort();
    if (!p) return Promise.resolve(null);
    const id = nextId++;
    return new Promise<string | null>((resolve) => {
        const timer = setTimeout(() => {
            if (pendingHello.delete(id)) resolve(null);
        }, REQUEST_TIMEOUT_MS);
        pendingHello.set(id, { resolve, timer });
        try {
            p.postMessage({ id, kind: "hello" });
        } catch {
            pendingHello.delete(id);
            clearTimeout(timer);
            resolve(null);
        }
    });
}

/** Test-only helpers. Reset the singleton state between cases. */
export const __test__ = {
    reset(): void {
        port = null;
        nextId = 1;
        portUnsupported = false;
        for (const r of pending.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pending.clear();
        for (const r of pendingHello.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pendingHello.clear();
    },
    pendingSize: (): number => pending.size,
    pendingHelloSize: (): number => pendingHello.size,
};
