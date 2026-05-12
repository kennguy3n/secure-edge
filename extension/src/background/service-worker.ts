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
import { scanViaNativeMessaging } from "./native-messaging.js";

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
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content }),
        });
        if (!r.ok) return null;
        return (await r.json()) as ScanResult;
    } catch {
        return null;
    }
}
