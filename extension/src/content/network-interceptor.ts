// Network-request interceptor content script.
//
// Monkey-patches window.fetch and XMLHttpRequest.prototype.send so
// every outbound request body on a Tier-2 AI tool page is run through
// the local agent's DLP pipeline before it leaves the browser. The
// goals are:
//
//   * Cover request bodies the paste / form interceptors miss —
//     e.g. modern SPA chat UIs that POST JSON straight from a React
//     handler, without ever firing a `submit` event.
//   * Stay invisible when the agent has nothing to say — the
//     patched fetch / send is otherwise a transparent pass-through.
//   * Fall open on any agent failure so an offline daemon can never
//     wedge a Tier-2 page.
//
// Only bodies above MIN_SCAN_BYTES are inspected to keep heartbeats /
// telemetry pings out of the hot path; tiny bodies cannot realistically
// carry a credential we'd want to block on anyway.

import { scanContent } from "./scan-client.js";
import { showBlockedToast } from "./toast.js";

/** Bodies below this size are skipped — not enough material to
 *  carry a DLP-worthy secret. Mirrors the agent's hotword / regex
 *  budget so we don't waste a scan on UI ping payloads. */
export const MIN_SCAN_BYTES = 50;

/** ToastFn alias keeps the test signature small. */
type ToastFn = (patternName: string) => void;

/** Patch fetch on `target`. Idempotent: if the property is already a
 *  wrapped patch we skip. The returned `unpatch` is exported for tests. */
export function patchFetch(target: { fetch: typeof fetch }, toast: ToastFn = (p) => showBlockedToast(p, "request")) {
    const original = target.fetch;
    if ((original as { __secureEdgePatched?: boolean }).__secureEdgePatched) {
        return () => { /* already patched */ };
    }
    const wrapped: typeof fetch = async (...args) => {
        const body = extractFetchBody(args);
        if (body.length >= MIN_SCAN_BYTES) {
            const result = await scanContent(body);
            if (result && result.blocked) {
                toast(result.pattern_name);
                throw new Error("Secure Edge: blocked by DLP");
            }
        }
        return original.apply(target, args);
    };
    (wrapped as { __secureEdgePatched?: boolean }).__secureEdgePatched = true;
    target.fetch = wrapped;
    return () => {
        target.fetch = original;
    };
}

/** Patch XMLHttpRequest.prototype.send on the given constructor. */
export function patchXHR(
    XHR: { prototype: XMLHttpRequest },
    toast: ToastFn = (p) => showBlockedToast(p, "request"),
) {
    const proto = XHR.prototype as unknown as {
        send: (body?: unknown) => void;
        __secureEdgePatched?: boolean;
    };
    if (proto.__secureEdgePatched) return () => { /* already patched */ };
    const original = proto.send;
    proto.send = function patchedSend(this: XMLHttpRequest, body?: unknown) {
        const text = bodyToText(body);
        if (text.length < MIN_SCAN_BYTES) {
            return original.call(this, body as Document | XMLHttpRequestBodyInit | null | undefined);
        }
        // XHR send() is sync from the caller's perspective; we abort
        // the request on block but cannot suspend it pending an async
        // scan. We start the scan and abort on block via xhr.abort().
        void scanContent(text).then((result) => {
            if (result && result.blocked) {
                try {
                    this.abort();
                } catch { /* ignore */ }
                toast(result.pattern_name);
            }
        });
        return original.call(this, body as Document | XMLHttpRequestBodyInit | null | undefined);
    };
    proto.__secureEdgePatched = true;
    return () => {
        proto.send = original;
        proto.__secureEdgePatched = false;
    };
}

/** Pull a string body out of fetch()'s argument tuple. Returns "" when
 *  the body is not extractable (FormData / Blob / ReadableStream). */
export function extractFetchBody(args: Parameters<typeof fetch>): string {
    const init = args[1];
    if (!init || init.body === undefined || init.body === null) return "";
    const body = init.body;
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    return "";
}

/** Convert an XHR body argument into a scannable string. */
export function bodyToText(body: unknown): string {
    if (body === undefined || body === null) return "";
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    return "";
}

// Install the patches when running inside a real browser. Tests import
// the patch functions directly with mock globals.
if (typeof window !== "undefined") {
    patchFetch(window);
    if (typeof XMLHttpRequest !== "undefined") {
        patchXHR(XMLHttpRequest as unknown as { prototype: XMLHttpRequest });
    }
}

export const __test__ = { patchFetch, patchXHR, extractFetchBody, bodyToText };
