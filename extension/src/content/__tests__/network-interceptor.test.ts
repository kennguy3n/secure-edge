// Unit tests for the fetch / XHR network interceptor.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ } from "../network-interceptor.js";

const { patchFetch, patchXHR, extractFetchBody, bodyToText } = __test__;

function mockFetchResponse(response: { ok: boolean; body?: unknown; err?: unknown }) {
    return (async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
        if (response.err) throw response.err;
        return {
            ok: response.ok,
            json: async () => response.body,
        } as unknown as Response;
    }) as typeof fetch;
}

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

test("patchFetch wraps and forwards small bodies untouched", async () => {
    // Two layered mocks: the patched fetch will run our DLP-scan call
    // (which goes through the same target.fetch we install). The
    // original fetch is the upstream call we are wrapping.
    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: ((async () => {
            upstreamCalls++;
            return { ok: true, json: async () => ({ blocked: false, pattern_name: "", score: 0 }) } as unknown as Response;
        }) as typeof fetch),
    };
    patchFetch(target, () => assert.fail("toast should not fire"));

    // Body shorter than MIN_SCAN_BYTES; skip the scan, just forward.
    await target.fetch("https://example.test/api", { method: "POST", body: "tiny" });
    assert.equal(upstreamCalls, 1, "upstream fetch should be invoked exactly once for small bodies");
});

test("patchFetch throws on DLP block and surfaces toast", async () => {
    // The DLP scan flows through scan-client.scanContent, which uses
    // globalThis.fetch to call /api/dlp/scan. We mock that to return
    // blocked=true. The wrapped page POST should never reach upstream.
    globalThis.fetch = mockFetchResponse({
        ok: true,
        body: { blocked: true, pattern_name: "aws_key", score: 9 },
    });

    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: (async (..._args: Parameters<typeof fetch>): Promise<Response> => {
            upstreamCalls++;
            return { ok: true, json: async () => ({}) } as unknown as Response;
        }) as typeof fetch,
    };

    let toastCalls = 0;
    patchFetch(target, () => {
        toastCalls++;
    });

    const longBody = "AKIA" + "X".repeat(80);
    await assert.rejects(target.fetch("https://example.test/api", { method: "POST", body: longBody }));
    assert.equal(toastCalls, 1, "toast should fire on block");
    assert.equal(upstreamCalls, 0, "wrapped page POST must not reach upstream on block");
});

test("patchFetch is idempotent", async () => {
    const target: { fetch: typeof fetch } = {
        fetch: mockFetchResponse({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } }),
    };
    const unpatch1 = patchFetch(target);
    const wrapped = target.fetch;
    patchFetch(target); // re-patch should be a no-op
    assert.equal(target.fetch, wrapped, "second patchFetch must not stack");
    unpatch1();
});

test("patchXHR forwards small bodies untouched", () => {
    let originalSendCalls = 0;
    const proto = {
        send(_body?: unknown) {
            originalSendCalls++;
        },
    } as unknown as XMLHttpRequest;
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR);
    (XHR.prototype.send as (body?: unknown) => void).call({}, "tiny");
    assert.equal(originalSendCalls, 1);
});
