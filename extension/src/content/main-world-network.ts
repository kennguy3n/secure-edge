// MAIN-world fetch / XHR bridge.
//
// Chrome MV3 content scripts run in an isolated world by default, so
// patches to `window.fetch` or `XMLHttpRequest.prototype.send` from an
// isolated-world script are invisible to the page's own JavaScript:
// the page keeps using its own un-patched copies and our DLP scan
// never fires. This module therefore runs as a separate content_scripts
// entry with `"world": "MAIN"` and patches the page's real globals.
//
// MAIN-world scripts cannot use `chrome.runtime`, so the bridge talks
// to the isolated-world `network-interceptor.ts` via `window.postMessage`.
// The isolated-world script owns the runtime port to the background
// service worker (which in turn talks to the local agent via Native
// Messaging or HTTP loopback).
//
// XHR send is *deferred* until the scan resolves: calling the original
// `send(body)` before knowing the verdict puts bytes on the wire that
// `xhr.abort()` cannot recall. The page-visible side-effects of
// readystatechange still fire normally because the actual network write
// happens once the scan returns "allowed".
//
// This file is intentionally free of runtime imports so it can be
// loaded as a classic script into the page's world; only `import type`
// declarations are used, which TS erases at compile time.

import type { ScanResult } from "../shared.js";

/** Bodies below this size are skipped — not enough material to carry
 *  a DLP-worthy secret. Mirrors the isolated-world threshold. */
export const MIN_SCAN_BYTES = 50;

/** Hard cap on body bytes pulled into the scanner. Mirrors the
 *  isolated-world `MAX_SCAN_BYTES` in `scan-client.ts`. Duplicated
 *  here (rather than imported) because this module runs in the
 *  page's MAIN world and cannot pull from the extension bundle.
 *  Keep the two literals in sync.
 *
 *  Bodies above this cap are still scanned, just truncated — the
 *  policy layer treats `text.length >= MAX_SCAN_BYTES` as "oversize"
 *  and routes through `policyForOversize()` rather than
 *  `policyForUnavailable()`. Doing the truncation here (instead of
 *  letting the agent enforce its own cap and refuse to scan) keeps
 *  the round-trip cheap and avoids streaming megabyte payloads
 *  through the bridge for every fetch. */
export const MAX_SCAN_BYTES = 1 * 1024 * 1024;

/** Maximum time to wait for the isolated-world script to reply with a
 *  scan verdict before falling open and allowing the request. */
export const SCAN_TIMEOUT_MS = 1500;

/** Channel tags. The page itself can observe `window.postMessage` so
 *  these tags are best-effort identification, not security tokens. */
export const BRIDGE_SOURCE = "secure-edge-bridge";
export const ISO_SOURCE = "secure-edge-iso";

export type ScanRequestMessage = {
    source: typeof BRIDGE_SOURCE;
    kind: "scan-req";
    id: string;
    content: string;
};

export type ScanResponseMessage = {
    source: typeof ISO_SOURCE;
    kind: "scan-resp";
    id: string;
    result: ScanResult | null;
};

function isScanResponse(data: unknown): data is ScanResponseMessage {
    if (!data || typeof data !== "object") return false;
    const d = data as { source?: unknown; kind?: unknown; id?: unknown };
    return d.source === ISO_SOURCE && d.kind === "scan-resp" && typeof d.id === "string";
}

function genId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 11)}`;
}

/** A minimal window-like surface used by patchFetch / patchXHR. Exposing
 *  it lets the unit tests inject a fake transport without faking the
 *  global `window`. */
export interface BridgeWindow {
    postMessage(message: unknown, targetOrigin: string): void;
    addEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
    removeEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
}

/** Ask the isolated-world content script to scan `content`. Resolves
 *  to null on timeout / no-listener so the caller can fall open. */
export function requestScan(
    win: BridgeWindow,
    content: string,
    timeoutMs: number = SCAN_TIMEOUT_MS,
): Promise<ScanResult | null> {
    return new Promise((resolve) => {
        const id = genId();
        let settled = false;
        const finish = (result: ScanResult | null) => {
            if (settled) return;
            settled = true;
            win.removeEventListener("message", onMessage);
            clearTimeout(timer);
            resolve(result);
        };
        const onMessage = (ev: MessageEvent) => {
            if (!isScanResponse(ev.data) || ev.data.id !== id) return;
            finish(ev.data.result);
        };
        const timer = setTimeout(() => finish(null), timeoutMs);
        win.addEventListener("message", onMessage);
        const req: ScanRequestMessage = { source: BRIDGE_SOURCE, kind: "scan-req", id, content };
        win.postMessage(req, "*");
    });
}

/** Patch fetch on `target`. Idempotent: re-patching is a no-op so the
 *  bridge can be loaded twice without stacking wrappers. */
export function patchFetch(
    target: { fetch: typeof fetch },
    win: BridgeWindow = window as unknown as BridgeWindow,
): () => void {
    const original = target.fetch;
    if ((original as { __secureEdgePatched?: boolean }).__secureEdgePatched) {
        return () => { /* already patched */ };
    }
    const wrapped: typeof fetch = async (...args) => {
        const body = await extractFetchBodyAsync(args);
        if (body.length >= MIN_SCAN_BYTES) {
            const result = await requestScan(win, body);
            if (result && result.blocked) {
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

/** Patch XMLHttpRequest.prototype.send so the original send is invoked
 *  only after the DLP scan resolves, closing the send-before-scan race. */
export function patchXHR(
    XHR: { prototype: XMLHttpRequest },
    win: BridgeWindow = window as unknown as BridgeWindow,
): () => void {
    const proto = XHR.prototype as unknown as {
        send: (body?: unknown) => void;
        __secureEdgePatched?: boolean;
    };
    if (proto.__secureEdgePatched) return () => { /* already patched */ };
    const original = proto.send;
    proto.send = function patchedSend(this: XMLHttpRequest, body?: unknown) {
        // Defer the network write until both body extraction and the
        // scan resolve. XHR is asynchronous from the page's
        // perspective; readystatechange still fires once the deferred
        // original.send completes.
        //
        // The body extractor is async because Blob/File/ArrayBuffer
        // text reads are async (Blob.text() returns a Promise). The
        // sub-threshold short-circuit therefore moves inside the
        // promise chain — small bodies still take a single
        // microtask hop, which preserves the page's send()-is-async
        // contract for readystatechange ordering.
        const xhr = this;
        const safeSend = () => {
            try {
                original.call(xhr, body as Document | XMLHttpRequestBodyInit | null | undefined);
            } catch {
                // xhr was aborted by the caller between patched send()
                // returning and the scan resolving. Nothing to do.
            }
        };
        bodyToTextAsync(body).then((text) => {
            if (text.length < MIN_SCAN_BYTES) {
                safeSend();
                return;
            }
            return requestScan(win, text).then((result) => {
                if (result && result.blocked) {
                    try { xhr.abort(); } catch { /* ignore */ }
                    return;
                }
                safeSend();
            });
        }, safeSend);
    };
    proto.__secureEdgePatched = true;
    return () => {
        proto.send = original;
        proto.__secureEdgePatched = false;
    };
}

/** Pull a string body out of fetch()'s argument tuple. Returns "" when
 *  the body is not extractable. Sync-only path: handles string and
 *  URLSearchParams. For Blob / File / ArrayBuffer / ArrayBufferView /
 *  ReadableStream / FormData-with-files use
 *  `extractFetchBodyAsync`. Retained for the unit tests that pin
 *  the synchronous fast path. */
export function extractFetchBody(args: Parameters<typeof fetch>): string {
    const init = args[1];
    if (!init || init.body === undefined || init.body === null) return "";
    return bodyValueToText(init.body);
}

/** Async variant of {@link extractFetchBody}. Supports the full
 *  set of fetch body types — Blob / File / ArrayBuffer /
 *  ArrayBufferView / ReadableStream / FormData-with-files — by
 *  awaiting the appropriate read API. Wired into the fetch hook so a
 *  file upload via `fetch(url, { body: file })` is scannable. */
export async function extractFetchBodyAsync(
    args: Parameters<typeof fetch>,
): Promise<string> {
    const init = args[1];
    if (!init || init.body === undefined || init.body === null) return "";
    return bodyValueToTextAsync(init.body);
}

/** Convert an XHR body argument into a scannable string
 *  synchronously. Same coverage as {@link extractFetchBody}.
 *  Retained for the unit tests that pin the synchronous fast path;
 *  the XHR hook itself now uses {@link bodyToTextAsync}. */
export function bodyToText(body: unknown): string {
    if (body === undefined || body === null) return "";
    return bodyValueToText(body);
}

/** Async variant of {@link bodyToText}. Wired into the XHR hook so
 *  `xhr.send(file)` / `xhr.send(formDataWithFile)` is scannable. */
export async function bodyToTextAsync(body: unknown): Promise<string> {
    if (body === undefined || body === null) return "";
    return bodyValueToTextAsync(body);
}

/** Synchronous body → text converter. Only covers types that can be
 *  read without I/O. Used by the legacy sync helpers; the live
 *  fetch / XHR hooks now go through {@link bodyValueToTextAsync}.
 *
 *  Supported:
 *    - string         → returned as-is
 *    - URLSearchParams → form-encoded
 *    - FormData       → text fields only, encoded as `k=v&k=v`
 *
 *  Returns "" for everything else (Blob / File / ArrayBuffer /
 *  ArrayBufferView / ReadableStream). */
function bodyValueToText(body: unknown): string {
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    if (typeof FormData !== "undefined" && body instanceof FormData) {
        const parts: string[] = [];
        body.forEach((value, key) => {
            if (typeof value === "string") {
                parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
            }
        });
        return parts.join("&");
    }
    return "";
}

/** Async body → text converter shared by the fetch and XHR hooks.
 *
 *  Adds the file-upload-interception (B1) coverage on top of the
 *  sync path:
 *
 *    - Blob / File            → `slice(0, MAX_SCAN_BYTES).text()`
 *    - ArrayBuffer            → UTF-8 decode of the first
 *                               `MAX_SCAN_BYTES` bytes
 *    - ArrayBufferView        → UTF-8 decode of the first
 *                               `MAX_SCAN_BYTES` bytes
 *    - ReadableStream         → drained via a `tee()`-style read up to
 *                               `MAX_SCAN_BYTES` bytes; the original
 *                               stream cannot be safely consumed here
 *                               so this branch returns "" (see note
 *                               below).
 *    - FormData (with files)  → text fields encoded as `k=v&k=v`;
 *                               each File / Blob entry contributes
 *                               `<key>=<utf8 contents>` (URL-encoded)
 *                               using the same `MAX_SCAN_BYTES`
 *                               slice. Encoding all file entries onto
 *                               a single line lets the scanner pattern
 *                               match across the file content the same
 *                               way it matches text body content.
 *
 *  All reads are capped at `MAX_SCAN_BYTES` per body component to
 *  bound memory + scan latency. The cap covers the cumulative read,
 *  not per-file inside a FormData — once cumulative bytes hit the
 *  cap the remaining entries are skipped and the policy layer routes
 *  the request through `policyForOversize()` (the agent treats
 *  truncated text as oversize). This keeps a 5 GB-file upload from
 *  buffering 5 GB into the page.
 *
 *  ReadableStream caveat: a single ReadableStream cannot be teed
 *  reliably after Request / Response has already locked it, and
 *  swapping `init.body` would break user code that wires response
 *  bytes through. Returning "" here is conservative — the policy
 *  layer then routes through `policyForUnavailable()` rather than
 *  showing a spurious block. ReadableStream uploads are extremely
 *  rare in the AI-tool UIs covered by this extension; covering them
 *  is tracked separately. */
async function bodyValueToTextAsync(body: unknown): Promise<string> {
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    if (typeof Blob !== "undefined" && body instanceof Blob) {
        return readBlobText(body, MAX_SCAN_BYTES);
    }
    if (typeof ArrayBuffer !== "undefined" && body instanceof ArrayBuffer) {
        return decodeBufferText(body, MAX_SCAN_BYTES);
    }
    if (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView(body)) {
        const view = body as ArrayBufferView;
        return decodeBufferText(view.buffer, MAX_SCAN_BYTES, view.byteOffset, view.byteLength);
    }
    if (typeof FormData !== "undefined" && body instanceof FormData) {
        return readFormDataText(body, MAX_SCAN_BYTES);
    }
    // ReadableStream falls through to "" — see the JSDoc note above.
    return "";
}

/** Read up to `cap` bytes of `blob` as UTF-8 text. */
async function readBlobText(blob: Blob, cap: number): Promise<string> {
    const sliced = blob.size > cap ? blob.slice(0, cap) : blob;
    try {
        return await sliced.text();
    } catch {
        // Reading a Blob backed by a revoked URL or a torn-down file
        // descriptor can throw. Treat it the same as "unsupported" —
        // the policy layer will route through policyForUnavailable
        // and the request goes through subject to the configured
        // enforcement mode.
        return "";
    }
}

/** UTF-8 decode up to `cap` bytes of an ArrayBuffer. Optional offset
 *  and byteLength are used for ArrayBufferView reads so a typed array
 *  pointing at the middle of a larger buffer is decoded correctly. */
function decodeBufferText(
    buffer: ArrayBufferLike,
    cap: number,
    offset = 0,
    byteLength?: number,
): string {
    const total = byteLength ?? buffer.byteLength - offset;
    const len = Math.min(total, cap);
    if (len <= 0) return "";
    try {
        // `fatal: false` so a stream that's not valid UTF-8 (e.g. a
        // PNG header) still produces a best-effort string the
        // scanner can match patterns against, rather than throwing
        // and falling open silently.
        const decoder = new TextDecoder("utf-8", { fatal: false });
        const view = new Uint8Array(buffer, offset, len);
        return decoder.decode(view);
    } catch {
        return "";
    }
}

/** Walk a FormData object encoding each text field and the contents
 *  of each File / Blob entry into a single `k=v&k=v` string.
 *
 *  The raw-read budget per entry is `cap - used`: we never read more
 *  bytes from a Blob than the remaining budget. Entries past the cap
 *  contribute their key but not their contents — the cap is hit, the
 *  scanner sees enough material to fire patterns, and the policy
 *  layer treats the truncated result as oversize.
 *
 *  Caveat: `encodeURIComponent` inflates special characters by up to
 *  3x (e.g. one byte ` ` -> three bytes `%20`), so the joined output
 *  string can exceed `MAX_SCAN_BYTES` even though every raw read
 *  respected the per-entry remaining budget. This is caught downstream
 *  by `network-interceptor.ts`'s isolated-world oversize check
 *  (`content.length > MAX_SCAN_BYTES` -> `policyForOversize`), so it
 *  cannot bypass the policy. For ASCII payloads (the common DLP
 *  target — API keys, tokens, credit cards) `encodeURIComponent` is
 *  effectively a no-op and the cap holds tightly.
 */
async function readFormDataText(fd: FormData, cap: number): Promise<string> {
    const parts: string[] = [];
    let used = 0;
    const entries: [string, FormDataEntryValue][] = [];
    fd.forEach((value, key) => {
        entries.push([key, value]);
    });
    for (const [key, value] of entries) {
        if (used >= cap) break;
        const remaining = cap - used;
        if (typeof value === "string") {
            const encoded = `${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
            parts.push(encoded);
            used += encoded.length;
            continue;
        }
        // value is a File or Blob.
        if (typeof Blob === "undefined" || !(value instanceof Blob)) continue;
        const fileText = await readBlobText(value, remaining);
        const encoded = `${encodeURIComponent(key)}=${encodeURIComponent(fileText)}`;
        parts.push(encoded);
        used += encoded.length;
    }
    return parts.join("&");
}

// Install the patches when running inside a real browser. Tests import
// the patch functions directly with mock globals.
if (typeof window !== "undefined") {
    patchFetch(window as unknown as { fetch: typeof fetch });
    if (typeof XMLHttpRequest !== "undefined") {
        patchXHR(XMLHttpRequest as unknown as { prototype: XMLHttpRequest });
    }
}

export const __test__ = {
    patchFetch,
    patchXHR,
    extractFetchBody,
    extractFetchBodyAsync,
    bodyToText,
    bodyToTextAsync,
    requestScan,
    MIN_SCAN_BYTES,
    MAX_SCAN_BYTES,
    SCAN_TIMEOUT_MS,
    BRIDGE_SOURCE,
    ISO_SOURCE,
};
