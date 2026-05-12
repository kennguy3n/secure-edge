// Isolated-world relay for the MAIN-world fetch / XHR bridge.
//
// The actual fetch / XMLHttpRequest patches live in
// main-world-network.ts and run in the page's own JavaScript context
// (so SPAs' native `fetch` and `XMLHttpRequest.prototype.send` are
// intercepted; see that file for the why). MAIN-world scripts cannot
// use `chrome.runtime`, so this isolated-world relay:
//
//   * Listens for `scan-req` messages the bridge posts to `window`.
//   * Runs the body through the existing `scanContent` helper, which
//     talks to the background service worker (Native Messaging first,
//     loopback HTTP fallback) and ultimately to the local agent.
//   * Posts a `scan-resp` back to `window` with the verdict.
//   * Renders the ephemeral block toast on the page when the agent
//     returns `blocked: true` — the bridge throws / aborts the request
//     but doesn't touch the DOM itself.
//
// Fall-open semantics match the rest of the extension: any scan-side
// error returns `result: null`, which the bridge treats as "allow".

import type { ScanResult } from "../shared.js";
import { scanContent } from "./scan-client.js";
import { showBlockedToast } from "./toast.js";

const BRIDGE_SOURCE = "secure-edge-bridge";
const ISO_SOURCE = "secure-edge-iso";

interface ScanRequestMessage {
    source: typeof BRIDGE_SOURCE;
    kind: "scan-req";
    id: string;
    content: string;
}

interface ScanResponseMessage {
    source: typeof ISO_SOURCE;
    kind: "scan-resp";
    id: string;
    result: ScanResult | null;
}

function isScanRequest(data: unknown): data is ScanRequestMessage {
    if (!data || typeof data !== "object") return false;
    const d = data as { source?: unknown; kind?: unknown; id?: unknown; content?: unknown };
    return d.source === BRIDGE_SOURCE
        && d.kind === "scan-req"
        && typeof d.id === "string"
        && typeof d.content === "string";
}

type ToastFn = (patternName: string) => void;
type ReplyFn = (msg: ScanResponseMessage) => void;

/** Handle a single bridge message. Exported for unit tests so we can
 *  exercise the relay without standing up a real `window`. */
export async function handleBridgeMessage(
    data: unknown,
    reply: ReplyFn,
    scan: (content: string) => Promise<ScanResult | null> = scanContent,
    toast: ToastFn = (p) => showBlockedToast(p, "request"),
): Promise<void> {
    if (!isScanRequest(data)) return;
    const { id, content } = data;
    let result: ScanResult | null;
    try {
        result = await scan(content);
    } catch {
        result = null;
    }
    if (result && result.blocked) {
        toast(result.pattern_name);
    }
    reply({ source: ISO_SOURCE, kind: "scan-resp", id, result });
}

if (typeof window !== "undefined") {
    window.addEventListener("message", (ev: MessageEvent) => {
        if (ev.source && ev.source !== window) return;
        void handleBridgeMessage(ev.data, (msg) => window.postMessage(msg, "*"));
    });
}

export const __test__ = { handleBridgeMessage, isScanRequest, BRIDGE_SOURCE, ISO_SOURCE };
