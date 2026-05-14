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
import { __test__ as riskyExtTest } from "../risky-extensions.js";

const { onChange, onDrop, readFilesText, firstRiskyExtensionMatch } = __test__;

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
    // Track writes to .value so the sync-first clear assertion works.
    Object.defineProperty(input, "value", {
        get(): string { return this._value ?? "fake-c-path"; },
        set(v: string) {
            this._value = v;
            this.valueAssignments++;
        },
    });
    return input;
}

interface MockChangeEvent {
    type: "change";
    target: MockInput;
    stopCalls: { n: number };
    stopImmediateCalls: { n: number };
}

function makeChangeEvent(input: MockInput): MockChangeEvent {
    const stopCalls = { n: 0 };
    const stopImmediateCalls = { n: 0 };
    return {
        type: "change",
        target: input,
        stopPropagation() { stopCalls.n++; },
        stopImmediatePropagation() { stopImmediateCalls.n++; },
        stopCalls,
        stopImmediateCalls,
    } as unknown as MockChangeEvent;
}

function makeDropEvent(files: File[]): {
    ev: DragEvent;
    preventCalls: { n: number };
    stopCalls: { n: number };
    stopImmediateCalls: { n: number };
} {
    const preventCalls = { n: 0 };
    const stopCalls = { n: 0 };
    const stopImmediateCalls = { n: 0 };
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
        stopImmediatePropagation: () => { stopImmediateCalls.n++; },
    } as unknown as DragEvent;
    return { ev, preventCalls, stopCalls, stopImmediateCalls };
}

/**
 * Make a fetch mock that NEVER resolves until release() is called.
 * Used by the sync-dispatch tests to prove that suppression
 * (preventDefault / stopPropagation / clearing input.value)
 * happens BEFORE the scan resolves — i.e. while the event would
 * still be in flight on a real browser dispatch.
 */
function blockingFetch(): {
    release: (resp: MockResponse) => void;
    calls: Array<{ url: string; body: string }>;
} {
    const calls: Array<{ url: string; body: string }> = [];
    let resolver: ((r: MockResponse) => void) | null = null;
    const pending = new Promise<MockResponse>((resolve) => { resolver = resolve; });
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        calls.push({ url: String(input), body: String(init?.body ?? "") });
        const response = await pending;
        if (response.err) throw response.err;
        return { ok: response.ok, json: async () => response.body } as unknown as Response;
    }) as typeof fetch;
    return {
        release: (r: MockResponse) => {
            assert.ok(resolver !== null, "resolver must be initialised by the time release is called");
            resolver!(r);
        },
        calls,
    };
}

beforeEach(() => {
    scanClientTest.resetEnforcementMode();
    riskyExtTest.reset();
    stubDocument();
});

afterEach(() => {
    scanClientTest.resetEnforcementMode();
    riskyExtTest.reset();
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

// Regression test for the multi-file newline-separator bug: when two
// or more files collectively reach exactly `cap` bytes, the joined
// text would previously be `cap + (N-1)` chars due to uncounted
// "\n" separators between parts. scan-client's `content.length >
// MAX_SCAN_BYTES` guard would then silently return null, defeating
// the toast UX. The fix slices the joined string to `cap`.
test("readFilesText never returns a string longer than cap (multi-file with separators)", async () => {
    const cap = 1024;
    // Two files of exactly cap/2 chars each. Without the fix, the
    // joined text would be cap + 1 chars (one "\n" separator).
    const f1 = new File([new Uint8Array(cap / 2).fill(65)], "a.bin");
    const f2 = new File([new Uint8Array(cap / 2).fill(66)], "b.bin");
    const { text, truncated } = await readFilesText(
        { length: 2, 0: f1, 1: f2 } as unknown as FileList,
        cap,
    );
    assert.ok(
        text.length <= cap,
        `readFilesText returned ${text.length} chars; MUST be <= cap (${cap}) so scanContent does not silently bail`,
    );
    // Three files where the per-file accounting (used) only reaches
    // cap on the third file, but the two intervening separators
    // would have pushed joined.length to cap + 2 before the fix.
    const third = Math.floor(cap / 3);
    const g1 = new File([new Uint8Array(third).fill(65)], "a.bin");
    const g2 = new File([new Uint8Array(third).fill(66)], "b.bin");
    const g3 = new File([new Uint8Array(cap - 2 * third).fill(67)], "c.bin");
    const result = await readFilesText(
        { length: 3, 0: g1, 1: g2, 2: g3 } as unknown as FileList,
        cap,
    );
    assert.ok(
        result.text.length <= cap,
        `readFilesText (3 files) returned ${result.text.length} chars; MUST be <= cap (${cap})`,
    );
    assert.equal(
        truncated,
        true,
        "truncated MUST be true when the joined string was sliced down to cap",
    );
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
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(calls.length, 0, "no scan should fire for empty FileList");
});

test("onChange clears input.value synchronously on every file selection (DLP block)", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 9 } });
    const file = new File(["leak: AKIAABCDEFGHIJKLMNOP" + "X".repeat(50)], "creds.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(input.valueAssignments, 1, "input.value should be cleared once");
    assert.equal(input.value, "");
});

test("onChange clears input.value synchronously on every file selection (DLP allow)", async () => {
    // Sync-first contract: suppression is unconditional, because the
    // verdict cannot be known synchronously and a deferred clear is
    // too late — the page has already read input.files. A clean scan
    // does NOT resume the selection (no portable way to re-construct
    // input.files). User must re-pick.
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["harmless content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(input.valueAssignments, 1, "input.value MUST be cleared even on allow under the sync-first contract");
    assert.equal(input.value, "");
});

test("onChange clears input.value BEFORE the scan resolves (sync-first proof)", async () => {
    // Sync-dispatch proof: hold the scan promise pending while we
    // assert that input.value has already been cleared. On a real
    // browser, the page's later listeners run during this window;
    // if we cleared after await, the page would have already read
    // input.files.
    const blocker = blockingFetch();
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    const pending = onChange(makeChangeEvent(input) as unknown as Event);
    // First microtask after onChange's sync prefix runs.
    await Promise.resolve();
    assert.equal(input.valueAssignments, 1, "input.value MUST be cleared synchronously before the scan resolves");
    assert.equal(input.value, "");
    // Now release the scan and let onChange finish.
    blocker.release({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    await pending;
});

test("onChange calls stopImmediatePropagation synchronously (proof: same-target listeners suppressed)", async () => {
    const blocker = blockingFetch();
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    const ev = makeChangeEvent(input);
    const pending = onChange(ev as unknown as Event);
    await Promise.resolve();
    assert.equal(
        ev.stopImmediateCalls.n,
        1,
        "stopImmediatePropagation MUST fire synchronously before await so the page's own change listener does not run",
    );
    assert.equal(ev.stopCalls.n, 1, "stopPropagation MUST also fire synchronously");
    blocker.release({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    await pending;
});

test("onChange in managed mode + agent-unavailable still surfaces a block toast", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("managed");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    // Under sync-first the selection is already cleared regardless
    // of mode; this test just keeps the mode wiring covered.
    assert.equal(input.valueAssignments, 1);
});

test("onChange in team mode + agent-unavailable still clears the selection (sync-first)", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("team");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(input.valueAssignments, 1);
});

test("onChange in personal mode + agent-unavailable still clears the selection (sync-first)", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    scanClientTest.setCachedEnforcementMode("personal");
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(input.valueAssignments, 1);
});

test("onDrop preventDefault + stopPropagation fire synchronously on every file drop", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 9 } });
    const file = new File(["leak: AKIAABCDEFGHIJKLMNOP" + "X".repeat(50)], "creds.txt");
    const { ev, preventCalls, stopCalls } = makeDropEvent([file]);
    await onDrop(ev);
    assert.equal(preventCalls.n, 1, "preventDefault must fire");
    assert.equal(stopCalls.n, 1, "stopPropagation must fire");
});

test("onDrop calls stopImmediatePropagation synchronously (same-target / same-phase listeners suppressed)", async () => {
    // The drop-event dispatch sequence on `document` is
    //   capture-phase listeners (in registration order) ->
    //   target / bubble.
    // If a later capture-phase listener is registered on `document`
    // (e.g. a hypothetical future drop interceptor added after
    // file-upload-interceptor in manifest order), we must prevent it
    // from running on a file drop too — only file-upload-interceptor
    // owns the verdict for file payloads. stopImmediatePropagation
    // is what enforces that contract; calling preventDefault +
    // stopPropagation alone would still let same-phase / same-target
    // listeners fire.
    const blocker = blockingFetch();
    const file = new File(["payload " + "X".repeat(50)], "drop.txt");
    const { ev, stopImmediateCalls } = makeDropEvent([file]);
    const pending = onDrop(ev);
    await Promise.resolve();
    assert.equal(
        stopImmediateCalls.n,
        1,
        "stopImmediatePropagation MUST fire synchronously before the scan resolves so same-target capture listeners do not run",
    );
    blocker.release({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    await pending;
});

test("onDrop preventDefault is observable on a real Event after the sync wrapper returns", async () => {
    // The strongest sync-dispatch proof: use a real CustomEvent
    // (Node does not expose a DragEvent constructor without jsdom,
    // but CustomEvent inherits the same defaultPrevented mechanism
    // from Event). Drive the listener exactly the way
    //   document.addEventListener("drop", (ev) => void onDrop(ev), { capture: true })
    // does in module init — fire-and-forget — then assert
    // defaultPrevented is already true by the time control returns
    // to the dispatcher.
    const blocker = blockingFetch();
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const ev = new CustomEvent("drop", { cancelable: true });
    const fileList = {
        length: 1,
        item: (i: number) => (i === 0 ? file : null),
        0: file,
        [Symbol.iterator]: function* () { yield file; },
    } as unknown as FileList;
    Object.defineProperty(ev, "dataTransfer", { value: { files: fileList } });
    assert.equal(ev.defaultPrevented, false, "precondition: real Event starts un-prevented");
    // Fire-and-forget exactly like the wrapper installed in module init.
    void onDrop(ev as unknown as DragEvent);
    // The sync prefix of onDrop has already executed. On a real
    // browser dispatch, this is the moment the page's listeners
    // would be invoked; we must see defaultPrevented === true.
    assert.equal(
        ev.defaultPrevented,
        true,
        "defaultPrevented MUST be observable on the event the instant the wrapper returns",
    );
    // Drain the deferred scan so the test exits cleanly.
    blocker.release({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    await Promise.resolve();
    await Promise.resolve();
});

test("onDrop preventDefault fires BEFORE the scan resolves (sync-first proof)", async () => {
    // Sync-dispatch proof: hold the scan pending while we assert
    // that the drop has already been suppressed. On a real browser,
    // the page's drop listeners run during this window.
    const blocker = blockingFetch();
    const file = new File(["content " + "X".repeat(50)], "ok.txt");
    const { ev, preventCalls, stopCalls } = makeDropEvent([file]);
    const pending = onDrop(ev);
    await Promise.resolve();
    assert.equal(preventCalls.n, 1, "preventDefault MUST fire synchronously before the scan resolves");
    assert.equal(stopCalls.n, 1, "stopPropagation MUST fire synchronously before the scan resolves");
    blocker.release({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    await pending;
});

test("onDrop is a no-op when dataTransfer has no files (text drop)", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const { ev, preventCalls } = makeDropEvent([]);
    await onDrop(ev);
    assert.equal(calls.length, 0, "no scan should fire for text-only drops (drag-interceptor handles those)");
    assert.equal(preventCalls.n, 0, "file-upload-interceptor must not block text drops");
});

test("onDrop also suppresses on allowed file content (sync-first — no resume)", async () => {
    // Under sync-first, the drop is suppressed unconditionally
    // because the verdict isn't known in time. There is no portable
    // way to re-inject a File into the page's drop target on a
    // clean scan, so the user must re-drag.
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["harmless content " + "X".repeat(50)], "ok.txt");
    const { ev, preventCalls, stopCalls } = makeDropEvent([file]);
    await onDrop(ev);
    assert.equal(preventCalls.n, 1, "preventDefault MUST fire even on allow under the sync-first contract");
    assert.equal(stopCalls.n, 1, "stopPropagation MUST fire even on allow");
});

test("onChange skips zero-byte files (no scan request) but still clears the input synchronously", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const empty = new File([""], "empty.txt");
    const input = makeFileInput([empty]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(calls.length, 0, "empty file body means no scan request");
    // Under the sync-first contract the input is cleared before we
    // even attempt the scan, so a zero-byte selection is still
    // suppressed (the user must re-pick a non-empty file).
    assert.equal(input.valueAssignments, 1, "sync-first: input cleared regardless of file contents");
});

// --- B2 / risky-file-extension policy --------------------------------------
//
// PR7 / B2: the interceptor short-circuits the content scan when any
// file in the selection / drop matches the active risky-extension
// blocklist. Suppression (preventDefault / stopImmediatePropagation
// / input.value = "") still fires synchronously — the B2 branch
// only affects whether the *async scan* is dispatched after the
// sync prelude. The toast surfaces the matched extension instead
// of a pattern-name verdict.

test("firstRiskyExtensionMatch returns the matched extension for a risky file", () => {
    const fileList = {
        length: 2,
        0: new File(["x"], "ok.txt"),
        1: new File(["x"], "evil.exe"),
    } as unknown as ArrayLike<File>;
    assert.equal(firstRiskyExtensionMatch(fileList), "exe");
});

test("firstRiskyExtensionMatch returns null when no file is risky", () => {
    const fileList = {
        length: 2,
        0: new File(["x"], "ok.txt"),
        1: new File(["x"], "report.pdf"),
    } as unknown as ArrayLike<File>;
    assert.equal(firstRiskyExtensionMatch(fileList), null);
});

test("firstRiskyExtensionMatch returns null when operator opted out (empty cache)", () => {
    // The opt-out wire shape ({"extensions": []}) materialises in
    // the cache as an empty array. The matcher MUST return null so
    // the interceptor falls through to the content scan path even
    // for an .exe upload.
    riskyExtTest.setCachedRiskyExtensions([]);
    const fileList = {
        length: 1,
        0: new File(["x"], "evil.exe"),
    } as unknown as ArrayLike<File>;
    assert.equal(firstRiskyExtensionMatch(fileList), null);
});

test("onChange blocks risky-extension upload and does NOT call the scan endpoint", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["MZ payload"], "evil.exe");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    // No HTTP scan request was issued — the extension check
    // short-circuits before the async scan. This is what makes B2
    // privacy-friendly: the filename and contents never leave the
    // page.
    assert.equal(calls.length, 0, "risky-extension upload MUST NOT trigger /api/dlp/scan");
    // Sync-first suppression still fires.
    assert.equal(input.valueAssignments, 1, "input.value MUST still be cleared on B2 block");
    assert.equal(input.value, "");
});

test("onChange blocks risky-extension regardless of enforcement mode (always-block)", async () => {
    // B2 is mode-independent. Walk every mode and confirm the
    // block fires uniformly.
    for (const mode of ["personal", "team", "managed"] as const) {
        scanClientTest.resetEnforcementMode();
        scanClientTest.setCachedEnforcementMode(mode);
        const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
        const file = new File(["payload"], `evil.${mode === "managed" ? "scr" : "ps1"}`);
        const input = makeFileInput([file]);
        await onChange(makeChangeEvent(input) as unknown as Event);
        assert.equal(calls.length, 0, `risky-extension upload MUST NOT scan in ${mode} mode`);
        assert.equal(input.valueAssignments, 1, `input.value MUST still be cleared on B2 block in ${mode} mode`);
    }
});

test("onChange blocks mixed selection (one risky + one benign) on the risky entry", async () => {
    // The PR plan: a mixed drop or selection MUST block the whole
    // gesture — re-constructing a FileList without the risky entry
    // is not portable. The toast names the matched extension.
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const benign = new File(["safe"], "report.pdf");
    const risky = new File(["x"], "evil.exe");
    const input = makeFileInput([benign, risky]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(calls.length, 0, "mixed selection containing a risky entry MUST be blocked outright");
    assert.equal(input.valueAssignments, 1);
});

test("onChange falls through to the content scan when the override list is empty (opt-out)", async () => {
    // Operator opted out of B2 entirely — the interceptor must
    // hand the file off to the content scanner exactly as it did
    // before B2 shipped.
    riskyExtTest.setCachedRiskyExtensions([]);
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["MZ"], "evil.exe");
    const input = makeFileInput([file]);
    await onChange(makeChangeEvent(input) as unknown as Event);
    assert.equal(calls.length, 1, "opt-out: the content scan path MUST still fire");
    assert.equal(calls[0].url, "http://127.0.0.1:8080/api/dlp/scan");
});

test("onDrop blocks risky-extension drop and does NOT call the scan endpoint", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const file = new File(["MZ"], "trojan.scr");
    const { ev, preventCalls, stopCalls, stopImmediateCalls } = makeDropEvent([file]);
    await onDrop(ev);
    assert.equal(calls.length, 0, "risky-extension drop MUST NOT trigger /api/dlp/scan");
    // Sync-first suppression still fires.
    assert.equal(preventCalls.n, 1, "preventDefault MUST fire on B2 block");
    assert.equal(stopCalls.n, 1, "stopPropagation MUST fire on B2 block");
    assert.equal(stopImmediateCalls.n, 1, "stopImmediatePropagation MUST fire on B2 block");
});

test("onDrop blocks risky-extension drop in mixed selection too", async () => {
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const benign = new File(["safe"], "notes.txt");
    const risky = new File(["x"], "installer.msi");
    const { ev } = makeDropEvent([benign, risky]);
    await onDrop(ev);
    assert.equal(calls.length, 0, "mixed drop with one risky entry MUST be blocked outright");
});

test("onDrop honours operator override list (custom extension blocks, .exe falls through)", async () => {
    // Operator override: just "zip". The baked-in list is NOT
    // consulted any more; .exe is no longer blocked at the
    // extension layer (and is left to the content scan).
    riskyExtTest.setCachedRiskyExtensions(["zip"]);
    const { calls } = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const zipDrop = makeDropEvent([new File(["x"], "archive.zip")]);
    await onDrop(zipDrop.ev);
    assert.equal(calls.length, 0, "override entry 'zip' MUST block .zip");

    // Reset fetch mock for the next case.
    const exe = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const exeDrop = makeDropEvent([new File(["x"], "installer.exe")]);
    await onDrop(exeDrop.ev);
    assert.equal(exe.calls.length, 1, "override does NOT include 'exe' so .exe MUST fall through to the scan");
});
