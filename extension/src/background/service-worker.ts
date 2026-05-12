// Background service worker for the Secure Edge companion extension.
//
// Responsibilities (MV3):
//   1. Reply to popup "ping" requests with the agent /api/status payload.
//   2. Surface a clear connection error when the local agent is down.
//
// All other work (paste interception, fetch-to-agent) happens inside
// the content script so the user content never leaves the page until
// the agent's DLP pipeline has cleared it.

import { AGENT_BASE, PopupRequest, PopupReply, StatusResponse } from "../shared.js";

chrome.runtime.onMessage.addListener(
    (msg: PopupRequest, _sender, sendResponse: (reply: PopupReply) => void) => {
        if (msg && msg.kind === "ping") {
            void pingAgent().then(sendResponse);
            return true; // keep the channel open for the async reply
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
