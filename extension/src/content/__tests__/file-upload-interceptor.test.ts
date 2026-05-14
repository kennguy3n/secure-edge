// File-upload interceptor unit tests (Phase 7 / B1).
//
// Exercises the change-event path (`<input type=file>`) and the
// drop-event path (`dataTransfer.files`). Mocks globalThis.fetch so
// the scan-client takes the HTTP path (no chrome.runtime in the
// node test process) and stubs `document` so toast.ts no-ops without
// throwing.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { __test__ } from "../file-upload-interceptor.js";
import { __test__ as scanClientTest } from "../scan-client.js";

const { onChange, onDrop, readFilesText } = __test__;

type MockResponse = { ok: boolean; body?: unknown; err?: unknown };

function mockFetch(response: MockResponse): { calls: Array<{ url: string; body: string }> } {
    const calls: Array<{ url: string; body: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        calls.push({ url: String(input), body: String(init?.body ?? "") });
        if (response.err) throw response.err;
        return { ok: response.ok, json: async () => response.body } as unknown as Response;
    }) as typeof fetch;
    return { calls };
}

function stubDocument(): { appendCount: { n: number } } {
    const appendCount = { n: 0 };
    (globalThis as { document?: unknown }).document = {
        getElementById: () => null,
        // Toast renders an element and schedules `setTimeout(() =>
        // toast.remove(), …)` — give the fake element a remove()
        // method so the deferred cleanup doesn't throw an
        // uncaughtException after the test ends.
        createElement: () => ({
            id: "",
            setAttribute: () => {},
            style: { cssText: "" },
            textContent: "",
            remove: () => {},
        }),
        body: {
            appendChild: () => { appendCount.n++; },
        },
    } as unknown as Document;
    return { appendCount };
}

interface MockInput {
    tagName: "INPUT";
    type: string;
    files: FileList | null;
    value: string;
    valueAssignments: number;
    dispatched: string[];
    dispatchEvent: (ev: Event) => boolean;
}

function makeFileInput(files: File[]): MockInput {
    const fileList = {
        length: files.length,
        item: (i: number) => files[i] ?? null,
        [Symbol.iterator]: function* () { for (const f of files) yield f; },
    } as unknown as FileList;
    for (let i = 0; i < files.length; i++) {
        (fileList as unknown as Record<number, File>)[i] = files[i];
    }
    const input: MockInput = {
        tagName: "INPUT",
        type: "file",
        files: fileList,
        value: "fake-c-path",
        valueAssignments: 0,
        dispatched: [],
        dispatchEvent(ev: Event): boolean {
            input.dispatched.push(ev.type);
            return true;
        },
    };
    // Track writes to .value so the clear-on-block assertion works.
    Object.defineProperty(input, "value", {
        get(): string { return this._value ?? "fake-c-path"; },
        set(v: string) {
            this._value = v;
            this.valueAssignments++;
        },
    });
    return input;
}

function makeChangeEvent(input: MockInput): Event {
    return { type: "change", target: input } as unknown as Event;
}

function makeDropEvent(files: File[]): {
    ev: DragEvent;
    preventCalls: { n: number };
    stopCalls: { n: number };
} {
    const preventCalls = { n: 0 };
    const stopCalls = { n: 0 };
    const fileList = {
        length: files.length,
        item: (i: number) => files[i] ?? null,
        [Symbol.iterator]: function* () { for (const f of files) yield f; },
    } as unknown as FileList;
    for (let i = 0; i < files.length; i++) {
        (fileList as unknown as Record<number, File>)[i] = files[i];
    }
    const ev = {
        dataTransfer: { files: fileList } as unknown as DataTransfer,
        preventDefault: () => { preventCalls.n++; },
        stopPropagation: () => { stopCalls.n++; },
    } as unknown as DragEvent;
    return { ev, preventCalls, stopCalls };
}

beforeEach(() => {
    scanClientTest.resetEnforcementMode();
    stubDocument();
});

afterEach(() => {
    scanClientTest.resetEnforcementMode();
    delete (globalThis as { document?: unknown }).document;
    delete (globalThis as { fetch?: unknown }).fetch;
});

test("readFilesText reads cumulative text up to cap", async () => {
    const f1 = new File(["AKIA1234567890ABCDEF"], "a.txt");
    const f2 = new File(["second"], "b.txt");
    const { text, truncated } = await readFilesText(
        { length: 2, 0: f1, 1: f2 } as unknown as FileList,
        1024,
    );
    // Files are joined by '\n' so the scanner sees boundaries.
    assert.equal(text, "AKIA1234567890ABCDEF\nsecond");
    assert.equal(truncated, false);
});

test("readFilesText truncates at cap and reports it", async () => {
    const huge = new File([new Uint8Array(2048).fill(65)], "big.bin");
    const { text, truncated } = await readFilesText(
        { length: 1, 0: huge } as unknown as FileList,
        1024,
    );
    assert.equal(text.length, 1024);
    assert.equal(truncated, true);
});

test("onChange ignores non-file inputs", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const ev = {
        type: "change",
        target: { tagName: "INPUT", type: "text" },
    } as unknown as Event;
    await onChange(ev);
    assert.equal(calls.length, 0, "no scan should fire for non-file inputs");
});

test("onChange ignores file input with no selection", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const input = makeFileInput([]);
    await onChange(makeChangeEvent(input));
    assert.equal(calls.length, 0, "no scan should fire for empty FileList");
});

test("onChange clears input.value and dispatches change on DLP block", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 9 } });
    const file = new File(["leak: AKIAABCDEFGHIJKLMNOP" + "X".repeat(50)], "creds.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input));
    assert.equal(input.valueAssignments, 1, "input.value should be cleared once");
    assert.equal(input.value, "");
    assert.deepEqual(input.dispatched, ["change"], "a synthetic change event must be dispatched");
});

test("onChange allows file through on DLP blocked=false", async () => {
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["harmless content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input));
    assert.equal(input.valueAssignments, 0, "input.value must not be cleared on allow");
});

test("onChange in managed mode blocks on agent-unavailable", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("managed");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input));
    assert.equal(input.valueAssignments, 1, "managed + unavailable must clear the selection");
});

test("onChange in team mode falls open on agent-unavailable (warn-only)", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("team");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input));
    assert.equal(input.valueAssignments, 0, "team + unavailable must NOT clear the selection (warn-only)");
});

test("onChange in personal mode falls open on agent-unavailable", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("personal");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input));
    assert.equal(input.valueAssignments, 0, "personal + unavailable must NOT clear the selection");
});

test("onDrop preventDefault + stopPropagation on file drop with DLP block", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 9 } });
    const file = new File(["leak: AKIAABCDEFGHIJKLMNOP" + "X".repeat(50)], "creds.txt");
    const { ev, preventCalls, stopCalls } = makeDropEvent([file]);
    await onDrop(ev);
    assert.equal(preventCalls.n, 1, "preventDefault must fire on block");
    assert.equal(stopCalls.n, 1, "stopPropagation must fire on block");
});

test("onDrop is a no-op when dataTransfer has no files (text drop)", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const { ev, preventCalls } = makeDropEvent([]);
    await onDrop(ev);
    assert.equal(calls.length, 0, "no scan should fire for text-only drops (drag-interceptor handles those)");
    assert.equal(preventCalls.n, 0, "file-upload-interceptor must not block text drops");
});

test("onDrop falls open on allowed file content", async () => {
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["harmless content " + "X".repeat(50)], "ok.txt");
    const { ev, preventCalls, stopCalls } = makeDropEvent([file]);
    await onDrop(ev);
    assert.equal(preventCalls.n, 0, "preventDefault must not fire on allow");
    assert.equal(stopCalls.n, 0, "stopPropagation must not fire on allow");
});

test("onChange skips zero-byte files (nothing to scan)", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const empty = new File([""], "empty.txt");
    const input = makeFileInput([empty]);
    await onChange(makeChangeEvent(input));
    assert.equal(calls.length, 0, "empty file body means no scan request");
    assert.equal(input.valueAssignments, 0);
});
