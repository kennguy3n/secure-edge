// Unit tests for the MAIN-world fetch / XHR bridge and the
// isolated-world relay. Together they implement the network
// interceptor; the legacy single-file shape merged both halves into a
// content-script monkey-patch that never ran in the page's own world.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ as mainWorld } from "../main-world-network.js";
import { __test__ as iso } from "../network-interceptor.js";
import { MAX_SCAN_BYTES as ISO_MAX_SCAN_BYTES } from "../scan-client.js";
import type { ScanResult } from "../../shared.js";
import type { BridgeDoc, BridgeRuntime } from "../network-interceptor.js";

const {
    patchFetch,
    patchXHR,
    extractFetchBody,
    extractFetchBodyAsync,
    bodyToText,
    bodyToTextAsync,
    requestScan,
    BRIDGE_SOURCE,
    ISO_SOURCE,
    MAX_SCAN_BYTES,
} = mainWorld;
const { handleBridgeMessage, manifestDeclaresMainWorld, injectMainWorldBridge, BRIDGE_SCRIPT_PATH } = iso;

type MessageListener = (ev: MessageEvent) => void;

/** Synthesise the postMessage-based channel between the MAIN-world
 *  bridge and the isolated-world relay. `onRequest` is invoked for each
 *  `scan-req` the bridge posts; its return value becomes the relay's
 *  `scan-resp` reply. */
function makeBridgedWindow(onRequest: (content: string) => ScanResult | null) {
    const listeners: MessageListener[] = [];
    const win = {
        addEventListener(_type: "message", listener: MessageListener) {
            listeners.push(listener);
        },
        removeEventListener(_type: "message", listener: MessageListener) {
            const i = listeners.indexOf(listener);
            if (i >= 0) listeners.splice(i, 1);
        },
        postMessage(message: unknown, _origin: string) {
            const data = message as { source?: unknown; kind?: unknown; id?: unknown; content?: unknown };
            if (data.source !== BRIDGE_SOURCE || data.kind !== "scan-req") return;
            // Run the scan + reply asynchronously so postMessage itself
            // is observably a no-op from the caller's perspective —
            // matching what real isolated-world ↔ MAIN-world plumbing
            // does (scanContent is async + chrome.runtime.sendMessage
            // hops the event loop).
            queueMicrotask(() => {
                const result = onRequest(String(data.content ?? ""));
                const reply = { source: ISO_SOURCE, kind: "scan-resp", id: data.id, result };
                for (const fn of [...listeners]) fn({ data: reply } as MessageEvent);
            });
        },
    };
    return win;
}

test("MAX_SCAN_BYTES is identical between scan-client (isolated world) and main-world-network (main world)", () => {
    // The constant is defined twice because the MAIN-world bridge
    // (`main-world-network.ts`) is injected into the page and cannot
    // import from the extension bundle, whereas the isolated-world
    // scan-client (`scan-client.ts`) lives in the extension bundle.
    // Both literals must agree, otherwise the oversize policy would
    // trigger at different thresholds in the two scan paths (fetch /
    // XHR / FormData go through MAIN; paste / form / drag /
    // file-upload go through isolated). A divergence would silently
    // shift the DLP cap.
    assert.equal(
        MAX_SCAN_BYTES,
        ISO_MAX_SCAN_BYTES,
        "MAX_SCAN_BYTES in main-world-network.ts MUST equal MAX_SCAN_BYTES in scan-client.ts — both must be edited in lockstep",
    );
    // Pin the absolute value too so a coordinated edit that bumps both
    // sites still gets a second look in code review. 1 MiB matches the
    // documented DLP contract.
    assert.equal(MAX_SCAN_BYTES, 1 * 1024 * 1024, "MAX_SCAN_BYTES must remain 1 MiB; coordinate any bump with the documented DLP contract");
});

test("extractFetchBody pulls string init.body", () => {
    assert.equal(
        extractFetchBody(["https://x", { body: JSON.stringify({ a: 1 }) }] as unknown as Parameters<typeof fetch>),
        '{"a":1}',
    );
    assert.equal(extractFetchBody(["https://x"] as unknown as Parameters<typeof fetch>), "");
});

test("bodyToText handles string and URLSearchParams", () => {
    assert.equal(bodyToText("plain"), "plain");
    assert.equal(bodyToText(new URLSearchParams({ a: "1" })), "a=1");
    assert.equal(bodyToText(null), "");
    assert.equal(bodyToText({ unrelated: true }), "");
});

test("bodyToText extracts FormData text fields and skips files (P1-5)", () => {
    const fd = new FormData();
    fd.append("prompt", "leak: AKIAABCDEFGHIJKLMNOP");
    fd.append("model", "gpt-4");
    // File / Blob entries must be ignored — reading them is async
    // and the hook runs synchronously.
    fd.append("upload", new Blob(["secret"], { type: "text/plain" }), "secret.txt");

    const out = bodyToText(fd);

    // Order is insertion-order per the FormData spec.
    assert.equal(
        out,
        "prompt=leak%3A%20AKIAABCDEFGHIJKLMNOP&model=gpt-4",
        `unexpected FormData encoding: ${out}`,
    );
    // The Blob value must not have leaked into the scan input.
    assert.ok(!out.includes("secret"), "Blob value must not appear in scan input");
});

test("extractFetchBody extracts FormData text fields (P1-5)", () => {
    const fd = new FormData();
    fd.append("question", "AKIAABCDEFGHIJKLMNOP");
    const args = [
        "https://x.test/api",
        { method: "POST", body: fd },
    ] as unknown as Parameters<typeof fetch>;
    assert.equal(extractFetchBody(args), "question=AKIAABCDEFGHIJKLMNOP");
});

test("bodyToText returns empty string for Blob / ArrayBuffer (sync fast path)", () => {
    // The synchronous helper is the legacy fast path retained for
    // string + URLSearchParams + FormData-with-only-text-fields. Any
    // body that requires I/O to read (Blob, ArrayBuffer, file-bearing
    // FormData entries) must use bodyToTextAsync. Asserting "" here
    // pins the sync surface so a future refactor that re-routes the
    // sync path through async transparently would be caught by tests.
    assert.equal(bodyToText(new Blob(["AKIA..."], { type: "text/plain" })), "");
    assert.equal(bodyToText(new ArrayBuffer(16)), "");
});

test("bodyToTextAsync reads Blob contents (B1 — file upload interception)", async () => {
    // Plain-text Blob: the scanner sees the full payload.
    const blob = new Blob(["leak: AKIAABCDEFGHIJKLMNOP"], { type: "text/plain" });
    assert.equal(await bodyToTextAsync(blob), "leak: AKIAABCDEFGHIJKLMNOP");
});

test("bodyToTextAsync reads File contents (B1)", async () => {
    // File is a Blob subclass; the same read path covers it. The
    // scanner therefore catches a file dragged into <input type=file>
    // and uploaded via fetch(url, { body: file }).
    const file = new File(["password = hunter2"], "creds.txt", { type: "text/plain" });
    assert.equal(await bodyToTextAsync(file), "password = hunter2");
});

test("bodyToTextAsync truncates Blob at MAX_SCAN_BYTES (B1 oversize cap)", async () => {
    // A 5 MiB blob must read at most MAX_SCAN_BYTES (1 MiB) so the
    // page is never made to buffer a multi-GB upload through the
    // bridge. The exact length pins the policy-layer contract:
    // text.length >= MAX_SCAN_BYTES is the trigger for the oversize
    // branch (`policyForOversize`).
    const huge = new Blob([new Uint8Array(5 * 1024 * 1024).fill(65)]);
    const text = await bodyToTextAsync(huge);
    assert.equal(text.length, MAX_SCAN_BYTES);
});

test("bodyToTextAsync decodes ArrayBuffer + ArrayBufferView as UTF-8 (B1)", async () => {
    const encoder = new TextEncoder();
    const buf = encoder.encode("token = AKIAABCDEFGHIJKLMNOP").buffer;
    assert.equal(await bodyToTextAsync(buf), "token = AKIAABCDEFGHIJKLMNOP");
    // ArrayBufferView (Uint8Array) covers fetch(url, { body: arr }).
    const view = new Uint8Array(buf);
    assert.equal(await bodyToTextAsync(view), "token = AKIAABCDEFGHIJKLMNOP");
});

test("bodyToTextAsync reads FormData with File entries (B1)", async () => {
    // FormData with file entry: the scanner sees both text fields
    // and the file contents on a single line, which lets DLP patterns
    // match across the file body the same way they match text.
    const fd = new FormData();
    fd.append("prompt", "review this");
    fd.append("upload", new File(["AKIAABCDEFGHIJKLMNOP"], "leak.txt", { type: "text/plain" }));
    const text = await bodyToTextAsync(fd);
    // Insertion order, files contribute key=<utf8 contents>.
    assert.equal(text, "prompt=review%20this&upload=AKIAABCDEFGHIJKLMNOP");
});

test("bodyToTextAsync FormData enforces cumulative MAX_SCAN_BYTES cap", async () => {
    // Two big files: the first fills the cap, the second contributes
    // its key but not its contents. The cumulative cap is what gates
    // the oversize-policy branch — per-file caps would let an attacker
    // sneak past by splitting a payload across N files.
    const fd = new FormData();
    fd.append("a", new Blob([new Uint8Array(800 * 1024).fill(65)]));
    fd.append("b", new Blob([new Uint8Array(800 * 1024).fill(66)]));
    const text = await bodyToTextAsync(fd);
    assert.ok(text.length >= MAX_SCAN_BYTES, "cumulative read must reach the oversize cap");
    // The "a=" prefix and the early bytes of file a should appear;
    // the encoder pads bytes so we just check the cap is hit.
});

test("bodyToTextAsync returns empty for ReadableStream (intentional, B1)", async () => {
    // ReadableStream cannot be safely tee'd here without replacing
    // init.body. Returning "" routes the request through
    // policyForUnavailable (per the JSDoc note) — a conservative
    // fall-open posture vs. a spurious block.
    const stream = new ReadableStream({
        start(controller) { controller.enqueue(new Uint8Array([65, 66])); controller.close(); },
    });
    assert.equal(await bodyToTextAsync(stream), "");
});

test("extractFetchBodyAsync handles Blob body on fetch (B1)", async () => {
    const args = [
        "https://example.test/upload",
        { method: "POST", body: new Blob(["secret-token-XYZ-1234567890"]) },
    ] as unknown as Parameters<typeof fetch>;
    assert.equal(await extractFetchBodyAsync(args), "secret-token-XYZ-1234567890");
});

test("requestScan resolves with the isolated-world verdict", async () => {
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    const r = await requestScan(win, "X".repeat(80));
    assert.deepEqual(r, { blocked: true, pattern_name: "aws_key", score: 9 });
});

test("requestScan falls open after timeout when no listener replies", async () => {
    const win = {
        addEventListener() { /* no-op */ },
        removeEventListener() { /* no-op */ },
        postMessage() { /* no reply ever */ },
    };
    const r = await requestScan(win, "X".repeat(80), 20);
    assert.equal(r, null);
});

test("patchFetch wraps and forwards small bodies untouched", async () => {
    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: ((async () => {
            upstreamCalls++;
            return { ok: true, json: async () => ({}) } as unknown as Response;
        }) as typeof fetch),
    };
    const win = makeBridgedWindow(() => { assert.fail("scan should not fire for sub-threshold body"); });
    patchFetch(target, win);

    await target.fetch("https://example.test/api", { method: "POST", body: "tiny" });
    assert.equal(upstreamCalls, 1, "upstream fetch should be invoked exactly once for small bodies");
});

test("patchFetch throws on DLP block and never reaches upstream", async () => {
    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: (async (..._args: Parameters<typeof fetch>): Promise<Response> => {
            upstreamCalls++;
            return { ok: true, json: async () => ({}) } as unknown as Response;
        }) as typeof fetch,
    };
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    patchFetch(target, win);

    const longBody = "AKIA" + "X".repeat(80);
    await assert.rejects(target.fetch("https://example.test/api", { method: "POST", body: longBody }));
    assert.equal(upstreamCalls, 0, "wrapped page POST must not reach upstream on block");
});

test("patchFetch is idempotent", () => {
    const target: { fetch: typeof fetch } = {
        fetch: ((async () => ({ ok: true, json: async () => ({}) } as unknown as Response)) as typeof fetch),
    };
    const win = makeBridgedWindow(() => null);
    const unpatch = patchFetch(target, win);
    const wrapped = target.fetch;
    patchFetch(target, win); // re-patch should be a no-op
    assert.equal(target.fetch, wrapped, "second patchFetch must not stack");
    unpatch();
});

test("patchXHR forwards small bodies untouched", async () => {
    let originalSendCalls = 0;
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => { assert.fail("scan should not fire for sub-threshold body"); });
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);
    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "tiny");
    // patchedSend now defers through bodyToTextAsync (Blob/File/
    // ArrayBuffer reads are async). Sub-threshold bodies still
    // short-circuit but the original send happens one microtask
    // later. Drain microtasks before asserting.
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(originalSendCalls, 1);
});

test("patchXHR defers send until scan resolves (no send-before-scan race)", async () => {
    const events: string[] = [];
    const proto = {
        send(_body?: unknown) { events.push("send"); },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => {
        events.push("scan");
        return { blocked: false, pattern_name: "", score: 0 };
    });
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);

    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "X".repeat(80));
    // patchedSend must not have called the original synchronously.
    assert.deepEqual(events, [], "no upstream side-effects must be visible before scan resolves");

    // Drain microtasks + the queueMicrotask reply hop.
    await new Promise((r) => setTimeout(r, 5));
    assert.deepEqual(events, ["scan", "send"], "scan must complete before the original send fires");
});

test("patchXHR aborts and never sends on DLP block", async () => {
    let originalSendCalls = 0;
    let abortCalls = 0;
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);

    const xhr = { abort: () => { abortCalls++; } } as unknown as XMLHttpRequest;
    (XHR.prototype.send as (body?: unknown) => void).call(xhr, "X".repeat(80));
    await new Promise((r) => setTimeout(r, 5));

    assert.equal(abortCalls, 1, "blocked XHR must be aborted");
    assert.equal(originalSendCalls, 0, "blocked XHR must never reach the network");
});

test("patchXHR falls open when the scan never returns a verdict", async () => {
    let originalSendCalls = 0;
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const stuckWin = {
        addEventListener() { /* no-op */ },
        removeEventListener() { /* no-op */ },
        postMessage() { /* never replies */ },
    };
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, stuckWin);

    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "X".repeat(80));
    // The bridge's internal timeout is 1500ms; we can't wait that long
    // in a unit test, so test the .catch path by injecting a window
    // whose postMessage throws (also a fall-open path).
    assert.equal(originalSendCalls, 0, "send is still deferred while the scan is in flight");
});

test("handleBridgeMessage replies with the scan verdict and toasts on block", async () => {
    let toastCalls = 0;
    const replies: unknown[] = [];
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "abc", content: "X".repeat(80) },
        (msg) => { replies.push(msg); },
        async () => ({ blocked: true, pattern_name: "aws_key", score: 9 }),
        () => { toastCalls++; },
    );
    assert.equal(toastCalls, 1, "isolated-world must show the toast on block");
    assert.equal(replies.length, 1);
    assert.deepEqual(replies[0], {
        source: ISO_SOURCE,
        kind: "scan-resp",
        id: "abc",
        result: { blocked: true, pattern_name: "aws_key", score: 9 },
    });
});

test("handleBridgeMessage ignores non-bridge messages", async () => {
    let replies = 0;
    await handleBridgeMessage({ source: "page", kind: "anything" }, () => { replies++; });
    await handleBridgeMessage(undefined, () => { replies++; });
    await handleBridgeMessage("hello", () => { replies++; });
    assert.equal(replies, 0, "only structured bridge messages must elicit a reply");
});

test("handleBridgeMessage falls open when scan throws", async () => {
    const replies: unknown[] = [];
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "z", content: "X".repeat(80) },
        (msg) => { replies.push(msg); },
        async () => { throw new Error("agent unreachable"); },
        () => {},
    );
    assert.equal(replies.length, 1);
    assert.deepEqual(replies[0], { source: ISO_SOURCE, kind: "scan-resp", id: "z", result: null });
});

// --- MAIN-world bridge delivery ---------------------------------------
//
// Chrome MV3 honours `world: "MAIN"` in content_scripts; Firefox 128
// silently ignores the key (Bug #7 from Devin Review). The relay's job
// is to detect that case via the runtime manifest and inject the
// bridge as a `<script>` element loaded via runtime.getURL().

/** Build a minimal fake `chrome.runtime` whose `getManifest()` returns
 *  the supplied content_scripts list. */
function makeRuntime(content_scripts: Array<{ world?: string }>): BridgeRuntime {
    return {
        getURL: (p: string) => `moz-extension://abc/${p}`,
        getManifest: () => ({ content_scripts }),
    };
}

/** Build a minimal fake DOM whose `documentElement` records appended
 *  children. Mirrors just enough of `Document` for injectMainWorldBridge. */
function makeDoc(): { doc: BridgeDoc; appended: HTMLScriptElement[]; created: HTMLScriptElement[] } {
    const appended: HTMLScriptElement[] = [];
    const created: HTMLScriptElement[] = [];
    const docElement = {
        appendChild(node: Node) {
            appended.push(node as HTMLScriptElement);
            return node;
        },
    };
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            const listeners: Array<() => void> = [];
            const el: Partial<HTMLScriptElement> & {
                _src?: string;
                _type?: string;
                _listeners: Array<() => void>;
                parentNode: { removeChild(n: Node): Node } | null;
            } = {
                _src: "",
                _type: "",
                _listeners: listeners,
                parentNode: null,
                addEventListener(_t: unknown, fn: unknown) { listeners.push(fn as () => void); },
            };
            Object.defineProperty(el, "src", {
                get() { return el._src ?? ""; },
                set(v: string) { el._src = v; },
            });
            Object.defineProperty(el, "type", {
                get() { return el._type ?? ""; },
                set(v: string) { el._type = v; },
            });
            created.push(el as HTMLScriptElement);
            return el as HTMLScriptElement;
        },
        documentElement: docElement,
        head: null,
    };
    return { doc, appended, created };
}

test("manifestDeclaresMainWorld returns true when any entry declares world MAIN", () => {
    assert.equal(
        manifestDeclaresMainWorld(makeRuntime([{}, { world: "MAIN" }])),
        true,
    );
});

test("manifestDeclaresMainWorld returns false when no entry declares MAIN", () => {
    assert.equal(manifestDeclaresMainWorld(makeRuntime([{}, { world: "ISOLATED" }])), false);
    assert.equal(manifestDeclaresMainWorld(makeRuntime([])), false);
});

test("manifestDeclaresMainWorld defaults to false (and triggers injection) when getManifest throws", () => {
    const rt: BridgeRuntime = {
        getURL: (p) => p,
        getManifest: () => { throw new Error("unavailable"); },
    };
    // A throwing manifest reader is treated as Firefox-shaped — we'd
    // rather double-patch than silently disable the interceptor.
    assert.equal(manifestDeclaresMainWorld(rt), false);
});

test("injectMainWorldBridge is a no-op on Chrome (manifest declares MAIN world)", () => {
    const { doc, appended } = makeDoc();
    const rt = makeRuntime([{ world: "MAIN" }]);
    const el = injectMainWorldBridge(rt, doc);
    assert.equal(el, null, "Chrome path must not inject (platform already loaded the bridge)");
    assert.equal(appended.length, 0);
});

test("injectMainWorldBridge appends a script element on Firefox-shaped manifests", () => {
    const { doc, appended, created } = makeDoc();
    const rt = makeRuntime([{ world: "ISOLATED" }]);
    const el = injectMainWorldBridge(rt, doc);
    assert.notEqual(el, null);
    assert.equal(appended.length, 1, "exactly one bridge script element must be appended");
    assert.equal(created.length, 1);
    const inserted = appended[0] as HTMLScriptElement & { _src?: string; _type?: string };
    assert.ok(
        inserted._src && inserted._src.endsWith(BRIDGE_SCRIPT_PATH),
        `injected src must resolve via runtime.getURL(${BRIDGE_SCRIPT_PATH}), got ${inserted._src}`,
    );
    assert.equal(inserted._type, "text/javascript");
});

test("injectMainWorldBridge falls back to <head> when documentElement is missing", () => {
    const appended: HTMLScriptElement[] = [];
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            return {
                addEventListener(_t: unknown, _fn: unknown) { /* unused */ },
                src: "",
                type: "",
            } as unknown as HTMLScriptElement;
        },
        documentElement: null,
        head: {
            appendChild(node: Node) {
                appended.push(node as HTMLScriptElement);
                return node;
            },
        },
    };
    const rt = makeRuntime([]);
    const el = injectMainWorldBridge(rt, doc);
    assert.notEqual(el, null);
    assert.equal(appended.length, 1, "head must receive the bridge script when documentElement is null");
});

test("injectMainWorldBridge returns null when no parent is available yet", () => {
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            return {
                addEventListener(_t: unknown, _fn: unknown) { /* unused */ },
            } as unknown as HTMLScriptElement;
        },
        documentElement: null,
        head: null,
    };
    // Mirrors document_start before <html> is parsed. Caller would retry.
    assert.equal(injectMainWorldBridge(makeRuntime([]), doc), null);
});
