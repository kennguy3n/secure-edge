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

import { NATIVE_HOST, ScanResult, EnforcementMode } from "../shared.js";
import {
    computeRequestMAC,
    computeResponseMAC,
    constantTimeEqHex,
    decodeNonceHex,
    importBridgeKey,
} from "./bridge-mac.js";

// G4: locally-cached enforcement mode used to decide whether a MAC
// verification failure should fall open (personal / team) or fail
// closed (managed). The cache is updated by the service worker via
// setBridgeEnforcementMode() every time the agent's enforcement-mode
// endpoint is refreshed, mirroring the cachedEnforcementMode in
// service-worker.ts. Until the first refresh the cache is
// "personal" — the privacy-first fall-open default, identical to
// the service worker's cold-start posture so the two stay in sync.
let cachedEnforcementMode: EnforcementMode = "personal";

/** setBridgeEnforcementMode updates the locally-cached enforcement
 *  mode that verifyResponseMACAndResolve consults when a reply MAC
 *  fails to verify. The service worker calls this in lockstep with
 *  its own cache update so a managed install never sees a window
 *  where the bridge has out-of-date enforcement state.
 *
 *  We do not read chrome.storage.session here because the service
 *  worker is the single writer; consulting storage from this module
 *  would race the writer and create a stale-read failure mode in
 *  exactly the path the gate is meant to harden. */
export function setBridgeEnforcementMode(mode: EnforcementMode): void {
    cachedEnforcementMode = mode;
}

/** Per-request timeout. Same budget as the HTTP fallback so a slow
 *  native host is no worse than a slow loopback. */
const REQUEST_TIMEOUT_MS = 1500;

interface PendingRequest {
    resolve: (r: ScanResult | null) => void;
    timer: ReturnType<typeof setTimeout>;
    /** Captured `kind` so the reply-side MAC verification can recompute
     *  the response HMAC input field-for-field. */
    kind: string;
}

interface NativeMessage {
    id?: number;
    result?: ScanResult;
    // api_token is populated on a successful "hello" reply (work
    // item A2). Empty / undefined means "agent did not provide a
    // token" and the extension falls back to its pre-A2 HTTP
    // posture (no Authorization header).
    api_token?: string;
    // bridge_nonce is populated on the hello reply when the agent
    // has an api_token configured (work item C1). The extension
    // caches it and includes it in the HMAC input on every
    // subsequent non-hello frame.
    bridge_nonce?: string;
    // mac is the lowercase-hex HMAC-SHA256 of the documented input
    // tuple. Empty on the hello reply by design (TOFU bootstrap).
    mac?: string;
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

// C1 per-connection MAC state. nonce + signing key are seeded by the
// hello reply and cleared on port disconnect.
let bridgeKey: CryptoKey | null = null;
let bridgeNonce: Uint8Array | null = null;
// Pre-imported key is async to construct; we cache the pending
// import so concurrent scans don't race to importKey() five times.
let bridgeKeyPromise: Promise<CryptoKey | null> | null = null;
let bridgeWarnedOnce = false;

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
            // C1: cache the per-connection nonce + signing key if
            // the agent surfaced one. The hello reply itself is
            // intentionally unsigned (TOFU bootstrap: the very
            // frame that hands us the secret can't be MAC'd
            // against it).
            if (token !== null && typeof msg.bridge_nonce === "string") {
                const decoded = decodeNonceHex(msg.bridge_nonce);
                if (decoded !== null) {
                    bridgeNonce = decoded;
                    bridgeKeyPromise = importBridgeKey(token).then(
                        (k) => {
                            bridgeKey = k;
                            return k;
                        },
                        (err) => {
                            // Web Crypto refused the key (extension
                            // context lacks crypto.subtle? key
                            // material malformed?). Fall through
                            // to no-MAC posture; the agent's
                            // lenient default will still serve.
                            console.warn("secure-edge: failed to import bridge key", err);
                            bridgeKey = null;
                            bridgeKeyPromise = null;
                            bridgeNonce = null;
                            return null;
                        },
                    );
                }
            }
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
        // C1: if we have a signing key and the agent surfaced a
        // MAC, verify it before delivering the result. On
        // verification failure we still resolve with the result
        // (extension-side lenient posture) but log a warning so
        // the operator notices.
        const result = msg.result ?? null;
        verifyResponseMACAndResolve(req, msg, result);
    });
    port.onDisconnect.addListener(() => {
        port = null;
        bridgeKey = null;
        bridgeNonce = null;
        bridgeKeyPromise = null;
        bridgeWarnedOnce = false;
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

/** Best-effort verification of the agent's response MAC.
 *
 *  Posture matrix (G4):
 *
 *                          | personal / team       | managed
 *    ------------------------+-----------------------+------------------
 *    MAC infra absent      | resolve(result)       | resolve(result)
 *    MAC field missing     | warn → resolve(result)| warn → resolve(null)
 *    MAC field mismatched  | warn → resolve(result)| warn → resolve(null)
 *    computeResponseMAC    |                       |
 *      threw / rejected    | warn → resolve(result)| warn → resolve(null)
 *
 *  "MAC infra absent" (no bridgeKey or no bridgeNonce) is the
 *  legitimate "the agent's bridge_mac_required is false" case and
 *  cannot be distinguished from a forged hello reply that omitted
 *  the nonce — we still fall open there because the alternative
 *  would brick every managed install whose agent has yet to roll
 *  out C1. The agent enforces its own bridge_mac_required gate on
 *  request frames so the C1 trust root is the agent, not the
 *  extension.
 *
 *  Every other failure mode (the agent surfaced a MAC, but we
 *  couldn't verify it) is treated as a positive integrity violation
 *  in managed mode: the result is discarded (resolve(null)), which
 *  the caller already routes through the strict
 *  policyForUnavailable(managed) path that blocks the upload. The
 *  one-time per-connection warning still fires so the operator's
 *  tray notification surfaces the bridge degradation.  */
function verifyResponseMACAndResolve(
    req: PendingRequest,
    msg: NativeMessage,
    result: ScanResult | null,
): void {
    if (!bridgeKey || !bridgeNonce) {
        // No MAC infrastructure cached (pre-C1 agent or hello
        // didn't surface a nonce). Skip verification — there's
        // nothing to verify against. Documented above as the one
        // case we cannot distinguish from a malicious omission;
        // the agent's request-side bridge_mac_required gate is
        // the authoritative defence.
        req.resolve(result);
        return;
    }
    const macHex = typeof msg.mac === "string" ? msg.mac : "";
    if (!macHex) {
        warnOncePerConnection("agent reply missing MAC");
        req.resolve(resultForMACFailure(result));
        return;
    }
    let blockedByte: 0x00 | 0x01 | 0xff = 0xff;
    if (result !== null) {
        blockedByte = result.blocked ? 0x01 : 0x00;
    }
    // computeResponseMAC is async; we kick it off and resolve the
    // pending request from the .then(). Errors are caught + logged
    // and we still resolve with the managed-aware fallback shape so
    // a thrown SubtleCrypto call (e.g. a degraded service worker
    // host) does not leak a falsely-trusted result.
    computeResponseMAC(
        bridgeKey,
        bridgeNonce,
        typeof msg.id === "number" ? msg.id : 0,
        req.kind,
        blockedByte,
        typeof msg.api_token === "string" ? msg.api_token : "",
        typeof msg.error === "string" ? msg.error : "",
    ).then(
        (expected) => {
            if (!constantTimeEqHex(expected, macHex)) {
                warnOncePerConnection("agent reply MAC mismatch");
                req.resolve(resultForMACFailure(result));
                return;
            }
            req.resolve(result);
        },
        (err) => {
            console.warn("secure-edge: failed to compute response MAC", err);
            req.resolve(resultForMACFailure(result));
        },
    );
}

/** resultForMACFailure picks the value to resolve a pending request
 *  with when the reply MAC could not be verified. In managed mode we
 *  return null so the caller's policyForUnavailable("managed") path
 *  takes over and blocks the upload; in any other mode we preserve
 *  the legacy lenient posture (resolve with the result so a missing
 *  / mismatched MAC is observable in the console but not enforced).
 *
 *  The function is intentionally null-safe on the input: a
 *  short-circuit failure can still arrive with result=null (the
 *  agent surfaced an error without a result body) and we forward
 *  that through unchanged. */
function resultForMACFailure(result: ScanResult | null): ScanResult | null {
    if (cachedEnforcementMode === "managed") return null;
    return result;
}

function warnOncePerConnection(reason: string): void {
    if (bridgeWarnedOnce) return;
    bridgeWarnedOnce = true;
    console.warn(
        `secure-edge: ${reason} on Native Messaging bridge ` +
        "(extension-side lenient mode); upgrade either side once " +
        "both produce MACs.",
    );
}

/** Send `content` to the Native Messaging host for a DLP scan.
 *  Returns null when the host is unavailable, disconnects mid-request,
 *  or exceeds REQUEST_TIMEOUT_MS. Never throws. */
export function scanViaNativeMessaging(content: string): Promise<ScanResult | null> {
    const p = ensurePort();
    if (!p) return Promise.resolve(null);
    const id = nextId++;
    const kind = "scan";
    return new Promise<ScanResult | null>((resolve) => {
        const timer = setTimeout(() => {
            if (pending.delete(id)) resolve(null);
        }, REQUEST_TIMEOUT_MS);
        pending.set(id, { resolve, timer, kind });
        // postMessage must happen synchronously enough that the
        // agent sees frames in monotonic-id order, but the MAC
        // compute is async. We resolve the promise with null on
        // any compute-side error so callers always fall through
        // to HTTP rather than hanging on a never-resolved scan.
        sendScanWithMAC(p, id, kind, content).catch((err) => {
            pending.delete(id);
            clearTimeout(timer);
            console.warn("secure-edge: scan send failed", err);
            resolve(null);
        });
    });
}

async function sendScanWithMAC(
    p: chrome.runtime.Port,
    id: number,
    kind: string,
    content: string,
): Promise<void> {
    // If a hello bridge-key import is in flight, wait for it so the
    // first scan after hello picks up the MAC infrastructure rather
    // than racing the hello reply.
    if (bridgeKeyPromise && !bridgeKey) {
        await bridgeKeyPromise;
    }
    const frame: Record<string, unknown> = { id, kind, content };
    if (bridgeKey && bridgeNonce) {
        try {
            frame.mac = await computeRequestMAC(bridgeKey, bridgeNonce, id, kind, content);
        } catch (err) {
            console.warn("secure-edge: failed to compute request MAC", err);
            // Fall through and send without a MAC — the agent's
            // lenient default still serves; strict mode will
            // reject.
        }
    }
    p.postMessage(frame);
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
            // Hello is deliberately NOT MAC'd: the very reply we
            // are about to read is what hands us the secret + nonce
            // (TOFU bootstrap). Matches the agent's hello-path
            // handling in agent/internal/api/nativemsg.go.
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
        bridgeKey = null;
        bridgeNonce = null;
        bridgeKeyPromise = null;
        bridgeWarnedOnce = false;
        // Reset the G4 cache to the cold-start default so a managed-
        // mode test that runs before a personal-mode one does not
        // leave the bridge in fail-closed.
        cachedEnforcementMode = "personal";
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
    bridgeKeyReady: (): boolean => bridgeKey !== null && bridgeNonce !== null,
};
