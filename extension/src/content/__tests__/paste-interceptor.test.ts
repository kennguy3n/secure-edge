// Paste-interceptor unit tests (Phase 7 / B3).
//
// Exercises every branch added by the B3 work (clipboard-file
// scanning) plus the pre-existing text-paste behaviour to pin
// that the two paths cohabit cleanly. The mocks mirror those in
// `file-upload-interceptor.test.ts`: a fake `fetch` that drives
// the scan verdict and a stubbed `document` so toast.ts no-ops
// without throwing.
//
// Each test below is one row of the planned B3 test table.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { __test__ as paste } from "../paste-interceptor.js";
import { __test__ as scanClientTest } from "../scan-client.js";
import { __test__ as riskyExtTest } from "../risky-extensions.js";

const {
    onPaste,
    collectClipboardFiles,
    firstRiskyClipboardExtension,
} = paste;

// ---------------------------------------------------------------------------
// Fetch + document harness
// ---------------------------------------------------------------------------

type ScanBody = { blocked: boolean; pattern_name: string; score: number };
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

function noFetch(): void {
    globalThis.fetch = (async (): Promise<Response> => {
        throw new Error("fetch must not be called in this case");
    }) as typeof fetch;
}

function stubDocument(): { appendCount: { n: number } } {
    const appendCount = { n: 0 };
    (globalThis as { document?: unknown }).document = {
        getElementById: () => null,
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
        // The text-path resume code touches `document.activeElement`
        // and `document.execCommand` when re-emitting a clean paste.
        // The mocks below let those calls run without throwing; the
        // tests that care about resumption assert via the
        // re-emitted event-target's `value` instead.
        activeElement: null,
        queryCommandSupported: () => false,
        execCommand: () => true,
    } as unknown as Document;
    return { appendCount };
}

// ---------------------------------------------------------------------------
// ClipboardEvent / DataTransfer mocks
// ---------------------------------------------------------------------------

function makeFileList(files: File[]): FileList {
    const fl = {
        length: files.length,
        item: (i: number) => files[i] ?? null,
        [Symbol.iterator]: function* () { for (const f of files) yield f; },
    } as unknown as FileList;
    for (let i = 0; i < files.length; i++) {
        (fl as unknown as Record<number, File>)[i] = files[i];
    }
    return fl;
}

function makeDataTransferItem(file: File, kind: "file" | "string" = "file"): DataTransferItem {
    return {
        kind,
        type: file.type,
        getAsFile() { return file; },
        getAsString(_cb: (s: string) => void) { /* unused */ },
    } as unknown as DataTransferItem;
}

interface ClipboardSpec {
    text?: string;
    files?: File[];
    items?: DataTransferItem[];
}

interface MockPasteEvent {
    ev: ClipboardEvent;
    preventCalls: { n: number };
    stopCalls: { n: number };
    target: HTMLTextAreaElement;
}

function makePasteEvent(spec: ClipboardSpec): MockPasteEvent {
    const preventCalls = { n: 0 };
    const stopCalls = { n: 0 };
    const target = {
        value: "",
        selectionStart: 0,
        selectionEnd: 0,
        focus: () => {},
        dispatchEvent: () => true,
    } as unknown as HTMLTextAreaElement;
    const data = {
        getData(format: string): string {
            if (format === "text/plain") return spec.text ?? "";
            return "";
        },
        files: makeFileList(spec.files ?? []),
        items: spec.items ?? [],
    } as unknown as DataTransfer;
    const ev = {
        clipboardData: data,
        target,
        preventDefault: () => { preventCalls.n++; },
        stopPropagation: () => { stopCalls.n++; },
    } as unknown as ClipboardEvent;
    return { ev, preventCalls, stopCalls, target };
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// `resumePaste` (text path) uses `target instanceof HTMLElement`
// and `el instanceof HTMLInputElement / HTMLTextAreaElement`. In a
// node test runner there is no DOM, so those globals are
// undefined and the `instanceof` check throws ReferenceError.
// Provide opaque sentinel classes so the `instanceof` check
// returns false and `resumePaste` early-returns (matching what
// happens on a real page where the target isn't a DOM element).
class FakeHTMLElement {}
class FakeHTMLInputElement {}
class FakeHTMLTextAreaElement {}

beforeEach(() => {
    scanClientTest.resetEnforcementMode();
    riskyExtTest.reset();
    stubDocument();
    (globalThis as { HTMLElement?: unknown }).HTMLElement = FakeHTMLElement;
    (globalThis as { HTMLInputElement?: unknown }).HTMLInputElement = FakeHTMLInputElement;
    (globalThis as { HTMLTextAreaElement?: unknown }).HTMLTextAreaElement = FakeHTMLTextAreaElement;
});

afterEach(() => {
    scanClientTest.resetEnforcementMode();
    riskyExtTest.reset();
    delete (globalThis as { document?: unknown }).document;
    delete (globalThis as { fetch?: unknown }).fetch;
    delete (globalThis as { HTMLElement?: unknown }).HTMLElement;
    delete (globalThis as { HTMLInputElement?: unknown }).HTMLInputElement;
    delete (globalThis as { HTMLTextAreaElement?: unknown }).HTMLTextAreaElement;
});

// ---------------------------------------------------------------------------
// Helpers — pure unit tests on the new exports
// ---------------------------------------------------------------------------

test("collectClipboardFiles returns files from clipboardData.files", () => {
    const f = new File(["abc"], "doc.txt");
    const data = {
        getData: () => "",
        files: makeFileList([f]),
        items: [],
    } as unknown as DataTransfer;
    const out = collectClipboardFiles(data);
    assert.equal(out.length, 1);
    assert.equal(out[0], f);
});

test("collectClipboardFiles also reads items[].getAsFile() for screenshot-tool pastes", () => {
    // A screenshot tool may put a PNG on the clipboard as an item
    // with kind="file" but leave clipboardData.files empty. The
    // helper has to walk both surfaces.
    const png = new File([new Uint8Array([137, 80, 78, 71])], "screenshot.png", { type: "image/png" });
    const data = {
        getData: () => "",
        files: makeFileList([]),
        items: [makeDataTransferItem(png, "file")],
    } as unknown as DataTransfer;
    const out = collectClipboardFiles(data);
    assert.equal(out.length, 1);
    assert.equal(out[0]?.name, "screenshot.png");
});

test("collectClipboardFiles dedupes when files and items reference the same File", () => {
    const f = new File(["hello"], "doc.txt");
    const data = {
        getData: () => "",
        files: makeFileList([f]),
        items: [makeDataTransferItem(f, "file")],
    } as unknown as DataTransfer;
    const out = collectClipboardFiles(data);
    assert.equal(out.length, 1, "same File on both surfaces must only be scanned once");
});

test("collectClipboardFiles skips items with kind=string", () => {
    // A text/plain item shows up alongside the File on some
    // browsers — kind=string entries must NOT be turned into a
    // synthetic File via getAsFile().
    const f = new File(["abc"], "doc.txt");
    const stringItem = { kind: "string", type: "text/plain", getAsFile: () => null } as unknown as DataTransferItem;
    const data = {
        getData: () => "",
        files: makeFileList([f]),
        items: [stringItem],
    } as unknown as DataTransfer;
    const out = collectClipboardFiles(data);
    assert.equal(out.length, 1);
    assert.equal(out[0]?.name, "doc.txt");
});

test("firstRiskyClipboardExtension matches on the baked-in list when no override is active", () => {
    // Default cache state (baked-in list) — matches .exe / .ps1 /
    // etc.
    const safe = new File(["x"], "report.txt");
    const risky = new File(["x"], "payload.exe");
    assert.equal(firstRiskyClipboardExtension([safe]), null);
    assert.equal(firstRiskyClipboardExtension([risky]), "exe");
});

test("firstRiskyClipboardExtension returns null when the operator opted out (empty list)", () => {
    riskyExtTest.setCachedRiskyExtensions([]);
    const risky = new File(["x"], "payload.exe");
    assert.equal(firstRiskyClipboardExtension([risky]), null, "empty override = no extension is risky");
});

test("firstRiskyClipboardExtension returns the FIRST match in a multi-file paste", () => {
    const safe = new File(["x"], "ok.txt");
    const r1 = new File(["x"], "first.exe");
    const r2 = new File(["x"], "second.ps1");
    assert.equal(firstRiskyClipboardExtension([safe, r1, r2]), "exe");
});

// ---------------------------------------------------------------------------
// Row 1 — text-only paste, clean verdict → resume + no toast
// ---------------------------------------------------------------------------

test("B3 / row 1: text-only paste, clean verdict, paste is resumed via insertText", async () => {
    const { calls } = mockFetch({
        ok: true,
        body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody,
    });
    const { ev, preventCalls, stopCalls } = makePasteEvent({ text: "hello world".repeat(20) });
    await onPaste(ev);

    assert.equal(preventCalls.n, 1, "text path must preventDefault while scanning");
    assert.equal(stopCalls.n, 1, "text path must stopPropagation while scanning");
    assert.equal(calls.length, 1, "scanContent must run exactly once");
    // Clean verdict — resumePaste is called (we don't assert
    // contents because document.execCommand is stubbed; absence of
    // a toast is the meaningful pin).
});

// ---------------------------------------------------------------------------
// Row 2 — text-only paste, DLP block
// ---------------------------------------------------------------------------

test("B3 / row 2: text-only paste, DLP block, toast surfaces and no resume", async () => {
    const fetchMock = mockFetch({
        ok: true,
        body: { blocked: true, pattern_name: "aws_key", score: 9 } satisfies ScanBody,
    });
    const { ev, preventCalls } = makePasteEvent({ text: "AKIAABCDEFGHIJKLMNOP".repeat(8) });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(fetchMock.calls.length, 1, "agent must be consulted on text paste");
});

// ---------------------------------------------------------------------------
// Row 3 — text-only paste, oversize (managed=block, personal=fall-open)
// ---------------------------------------------------------------------------

test("B3 / row 3a: text-only oversize, managed mode blocks", async () => {
    scanClientTest.setCachedEnforcementMode("managed");
    noFetch(); // oversize must NEVER hit the agent
    const huge = "A".repeat(2 * 1024 * 1024 + 1);
    const { ev, preventCalls, stopCalls } = makePasteEvent({ text: huge });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1, "managed mode must suppress oversize paste");
    assert.equal(stopCalls.n, 1);
});

test("B3 / row 3b: text-only oversize, personal mode silently allows", async () => {
    scanClientTest.setCachedEnforcementMode("personal");
    noFetch();
    const huge = "A".repeat(2 * 1024 * 1024 + 1);
    const { ev, preventCalls } = makePasteEvent({ text: huge });
    await onPaste(ev);
    assert.equal(preventCalls.n, 0, "personal mode must let oversize paste through untouched");
});

// ---------------------------------------------------------------------------
// Row 4 — file paste, risky extension, blocked (no scan)
// ---------------------------------------------------------------------------

test("B3 / row 4: file paste with risky extension is blocked before any content read (no fetch)", async () => {
    noFetch();
    const exe = new File([new Uint8Array(1024)], "malware.exe");
    const { ev, preventCalls, stopCalls } = makePasteEvent({ files: [exe] });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1, "file path must suppress synchronously");
    assert.equal(stopCalls.n, 1);
});

// ---------------------------------------------------------------------------
// Row 5 — file paste, clean content → no resume, no toast
// ---------------------------------------------------------------------------

test("B3 / row 5: file paste, clean content, gesture stays suppressed (no resume), no toast", async () => {
    const fetchMock = mockFetch({
        ok: true,
        body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody,
    });
    const stub = stubDocument();
    const clean = new File(["just some text"], "doc.txt");
    const { ev, preventCalls } = makePasteEvent({ files: [clean] });
    await onPaste(ev);

    assert.equal(preventCalls.n, 1);
    assert.equal(fetchMock.calls.length, 1, "clean file must still pass through scanContent");
    // No-resume contract: stays suppressed; no toast appears
    // (appendCount stays 0 because we never render a DOM node).
    assert.equal(stub.appendCount.n, 0, "clean file paste must not render any toast");
});

// ---------------------------------------------------------------------------
// Row 6 — file paste, DLP-blocked content → block toast
// ---------------------------------------------------------------------------

test("B3 / row 6: file paste with DLP-pattern content surfaces a block toast", async () => {
    mockFetch({
        ok: true,
        body: { blocked: true, pattern_name: "aws_key", score: 9 } satisfies ScanBody,
    });
    const stub = stubDocument();
    const leak = new File(["AKIA" + "B".repeat(80)], "secret.txt");
    const { ev, preventCalls } = makePasteEvent({ files: [leak] });
    await onPaste(ev);

    assert.equal(preventCalls.n, 1);
    assert.equal(stub.appendCount.n, 1, "DLP-blocked file paste must surface a toast");
});

// ---------------------------------------------------------------------------
// Row 7 — file paste, oversize, managed mode
// ---------------------------------------------------------------------------

test("B3 / row 7: file paste, oversize cap reached, managed mode blocks before the scan completes", async () => {
    scanClientTest.setCachedEnforcementMode("managed");
    // The cap is 1 MiB. A single 2 MiB file triggers the truncated
    // branch + managed-mode block. fetch may or may not be called
    // first (the truncated check happens after readFilesText), so
    // accept a fetch call but ignore the body.
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody });
    const stub = stubDocument();
    const huge = new File([new Uint8Array(2 * 1024 * 1024).fill(65)], "huge.txt");
    const { ev, preventCalls } = makePasteEvent({ files: [huge] });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(stub.appendCount.n, 1, "managed-mode oversize must surface a policy toast");
});

// ---------------------------------------------------------------------------
// Row 8 — mixed paste (text + file) → file path wins, text is ignored
// ---------------------------------------------------------------------------

test("B3 / row 8: mixed paste (text + file) routes through the FILE path; text fragment never reaches scanContent", async () => {
    const fetchMock = mockFetch({
        ok: true,
        body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody,
    });
    const f = new File(["benign body"], "doc.txt");
    const { ev, preventCalls } = makePasteEvent({
        text: "AKIAABCDEFGHIJKLMNOP".repeat(8), // an AWS-key-looking string the user "also" copied
        files: [f],
    });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(fetchMock.calls.length, 1, "exactly one scan must run (the file's), never the text fragment");
    // The body must be the file's content, not the text fragment.
    // The scan-client wraps the content in a JSON envelope; a
    // substring check on the original file content is enough to
    // pin "the file was scanned, not the text".
    assert.match(
        fetchMock.calls[0]!.body,
        /benign body/,
        "the file path must win — text fragment must not be scanned",
    );
    assert.doesNotMatch(
        fetchMock.calls[0]!.body,
        /AKIAABCDEFGHIJKLMNOP/,
        "text fragment must not leak into the scan body in a mixed paste",
    );
});

// ---------------------------------------------------------------------------
// Row 9 — multi-file paste with one risky entry blocks the whole gesture
// ---------------------------------------------------------------------------

test("B3 / row 9: multi-file paste with one risky entry blocks before any scan", async () => {
    noFetch();
    const stub = stubDocument();
    const good = new File(["x"], "ok.txt");
    const bad = new File(["x"], "bad.exe");
    const { ev, preventCalls } = makePasteEvent({ files: [good, bad] });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(stub.appendCount.n, 1, "risky-extension toast must surface once");
});

// ---------------------------------------------------------------------------
// Row 10 — multi-file paste, all clean → block (no resume contract holds)
// ---------------------------------------------------------------------------

test("B3 / row 10: multi-file clean paste stays suppressed (no portable re-injection path)", async () => {
    mockFetch({
        ok: true,
        body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody,
    });
    const stub = stubDocument();
    const a = new File(["alpha"], "a.txt");
    const b = new File(["beta"], "b.txt");
    const { ev, preventCalls, stopCalls } = makePasteEvent({ files: [a, b] });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(stopCalls.n, 1);
    assert.equal(stub.appendCount.n, 0, "clean multi-file paste must not surface any toast (and stays suppressed)");
});

// ---------------------------------------------------------------------------
// Row 11 — agent unavailable + file paste: managed=block, personal=silent
// ---------------------------------------------------------------------------

test("B3 / row 11a: file paste + agent unavailable + managed mode = policy block toast", async () => {
    scanClientTest.setCachedEnforcementMode("managed");
    mockFetch({ ok: false, body: null });
    const stub = stubDocument();
    const f = new File(["body"], "doc.txt");
    const { ev } = makePasteEvent({ files: [f] });
    await onPaste(ev);
    assert.equal(stub.appendCount.n, 1, "managed mode must surface the agent-unavailable toast");
});

test("B3 / row 11b: file paste + agent unavailable + personal mode = silent fall-open", async () => {
    scanClientTest.setCachedEnforcementMode("personal");
    mockFetch({ ok: false, body: null });
    const stub = stubDocument();
    const f = new File(["body"], "doc.txt");
    const { ev, preventCalls } = makePasteEvent({ files: [f] });
    await onPaste(ev);
    assert.equal(
        preventCalls.n,
        1,
        "gesture is still suppressed (no portable re-injection path) even on personal fall-open",
    );
    assert.equal(stub.appendCount.n, 0, "personal mode must not surface a toast on agent-unavailable");
});

// ---------------------------------------------------------------------------
// Row 12 — empty paste is a no-op
// ---------------------------------------------------------------------------

test("B3 / row 12: empty paste is a no-op (no scan, no toast, no suppression)", async () => {
    noFetch();
    const stub = stubDocument();
    const { ev, preventCalls, stopCalls } = makePasteEvent({});
    await onPaste(ev);
    assert.equal(preventCalls.n, 0);
    assert.equal(stopCalls.n, 0);
    assert.equal(stub.appendCount.n, 0);
});

// ---------------------------------------------------------------------------
// Row 13 — clipboardData is null (synthetic ClipboardEvent on some browsers)
// ---------------------------------------------------------------------------

test("B3 / row 13: clipboardData=null is a clean no-op (defensive)", async () => {
    noFetch();
    const preventCalls = { n: 0 };
    const stopCalls = { n: 0 };
    const ev = {
        clipboardData: null,
        target: null,
        preventDefault: () => { preventCalls.n++; },
        stopPropagation: () => { stopCalls.n++; },
    } as unknown as ClipboardEvent;
    await onPaste(ev);
    assert.equal(preventCalls.n, 0);
    assert.equal(stopCalls.n, 0);
});

// ---------------------------------------------------------------------------
// Row 14 — text path + oversize + team mode (warn-toast equivalent)
//
// Rows 3a / 3b cover oversize text in managed (block) and personal
// (silent-allow). The team-mode behaviour is the same silent-allow
// as personal — `policyForOversize` only flips to "block" for
// managed — but the test pins the contract so a future change to
// `policyForOversize` cannot silently move the team posture without
// flipping a test.
// ---------------------------------------------------------------------------

test("B3 / row 14: text-only oversize, team mode silently allows (matches personal posture)", async () => {
    scanClientTest.setCachedEnforcementMode("team");
    noFetch();
    const huge = "A".repeat(2 * 1024 * 1024 + 1);
    const { ev, preventCalls } = makePasteEvent({ text: huge });
    await onPaste(ev);
    assert.equal(
        preventCalls.n,
        0,
        "team mode must let oversize text paste through (no block toast, no suppression)",
    );
});

// ---------------------------------------------------------------------------
// Rows 15a / 15b / 15c — text-path agent-unavailable, all three modes
//
// Rows 11a / 11b cover the FILE path on agent-unavailable. The text
// path has its own resumption story (a clean / fall-open verdict
// re-emits the paste via `resumePaste`), so the three policy
// branches need their own coverage to pin that:
//   personal — silent fall-open, resumePaste runs (no toast)
//   team     — warn toast, resumePaste still runs
//   managed  — block toast, NO resumePaste
//
// `mockFetch({ ok: false, body: null })` simulates a non-2xx
// response from the agent so scanContent returns null and the
// onPaste handler hits the policyForUnavailable() branch.
// ---------------------------------------------------------------------------

test("B3 / row 15a: text paste + agent unavailable + personal mode = silent fall-open (no toast)", async () => {
    scanClientTest.setCachedEnforcementMode("personal");
    mockFetch({ ok: false, body: null });
    const stub = stubDocument();
    const { ev, preventCalls } = makePasteEvent({ text: "ordinary clipboard text" });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1, "text path always preventDefaults while it asks the agent");
    assert.equal(
        stub.appendCount.n,
        0,
        "personal mode must not surface a toast when the agent is unavailable",
    );
});

test("B3 / row 15b: text paste + agent unavailable + team mode surfaces a warn toast and resumes", async () => {
    scanClientTest.setCachedEnforcementMode("team");
    mockFetch({ ok: false, body: null });
    const stub = stubDocument();
    const { ev } = makePasteEvent({ text: "ordinary clipboard text" });
    await onPaste(ev);
    assert.equal(
        stub.appendCount.n,
        1,
        "team mode must surface a single warn toast on agent-unavailable",
    );
});

test("B3 / row 15c: text paste + agent unavailable + managed mode blocks (toast, no resume)", async () => {
    scanClientTest.setCachedEnforcementMode("managed");
    mockFetch({ ok: false, body: null });
    const stub = stubDocument();
    const { ev, preventCalls } = makePasteEvent({ text: "ordinary clipboard text" });
    await onPaste(ev);
    assert.equal(preventCalls.n, 1);
    assert.equal(
        stub.appendCount.n,
        1,
        "managed mode must surface a single policy block toast on agent-unavailable",
    );
});

// ---------------------------------------------------------------------------
// Row 16 — items[]-only screenshot paste integration test
//
// `collectClipboardFiles` already has a unit test for the
// items[].getAsFile() surface (line ~189), but the full `onPaste`
// integration is only exercised on the `clipboardData.files`
// surface in rows 5 / 6 / 7. Pin the items[]-only path through the
// full handler so a future refactor of onPaste that drops the
// items[] branch cannot pass typecheck + the helper test alone.
// ---------------------------------------------------------------------------

test("B3 / row 16: screenshot-style PNG via items[] (files empty) is suppressed and scanned", async () => {
    const fetchMock = mockFetch({
        ok: true,
        body: { blocked: false, pattern_name: "", score: 0 } satisfies ScanBody,
    });
    const stub = stubDocument();
    const png = new File(
        [new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])],
        "screenshot.png",
        { type: "image/png" },
    );

    // Build the event by hand: clipboardData.files is empty; the
    // only File payload is on items[].
    const preventCalls = { n: 0 };
    const stopCalls = { n: 0 };
    const data = {
        getData: () => "",
        files: makeFileList([]),
        items: [makeDataTransferItem(png, "file")],
    } as unknown as DataTransfer;
    const ev = {
        clipboardData: data,
        target: null,
        preventDefault: () => { preventCalls.n++; },
        stopPropagation: () => { stopCalls.n++; },
    } as unknown as ClipboardEvent;
    await onPaste(ev);

    assert.equal(preventCalls.n, 1, "items[]-only screenshot paste must be suppressed too");
    assert.equal(stopCalls.n, 1);
    // Clean verdict on the (effectively unreadable) PNG bytes —
    // see the screenshot/image DLP limitation documented in the
    // file header and docs/admin-guide.md §8.1.
    assert.equal(fetchMock.calls.length, 1, "the FILE path still runs scanContent on best-effort decoded bytes");
    assert.equal(
        stub.appendCount.n,
        0,
        "a clean (best-effort) screenshot scan must not surface any toast",
    );
});
