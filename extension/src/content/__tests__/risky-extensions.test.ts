// Unit tests for the Phase 7 / B2 risky-extension matcher and
// content-side cache. The matcher is pure (no DOM / no chrome.*)
// so these tests run in the plain node test runner without any
// stubs.
//
// The interceptor hook itself is covered separately by
// file-upload-interceptor.test.ts — here we only check the
// primitive operations the interceptor depends on.

import { afterEach, test } from "node:test";
import assert from "node:assert/strict";

import {
    BAKED_IN_RISKY_EXTENSIONS,
    __test__ as rxt,
    extensionOf,
    getCachedRiskyExtensions,
    isRiskyExtension,
    normaliseEntries,
} from "../risky-extensions.js";

afterEach(() => {
    rxt.reset();
});

// --- extensionOf ----------------------------------------------------------

test("extensionOf returns the dot-less lowercase last extension", () => {
    assert.equal(extensionOf("foo.exe"), "exe");
    assert.equal(extensionOf("foo.EXE"), "exe");
    assert.equal(extensionOf("foo.bar.exe"), "exe", "must use LAST extension, not first");
    assert.equal(extensionOf("DOCUMENT.PDF"), "pdf");
});

test("extensionOf returns empty for dotless / hidden / trailing-dot names", () => {
    assert.equal(extensionOf("README"), "");
    assert.equal(extensionOf(".bashrc"), "", "leading-dot hidden files have NO extension");
    assert.equal(extensionOf("noext."), "", "trailing dot is NOT an extension");
    assert.equal(extensionOf(""), "");
    assert.equal(extensionOf("."), "");
    assert.equal(extensionOf(".."), "");
});

test("extensionOf strips directory prefix (defensive against page-leaked names)", () => {
    assert.equal(extensionOf("C:\\Users\\me\\evil.exe"), "exe");
    assert.equal(extensionOf("/tmp/payload.scr"), "scr");
    // A name with no basename after the slash is treated as empty.
    assert.equal(extensionOf("/tmp/"), "");
});

test("extensionOf is robust to non-string input", () => {
    // The function is typed `string` but the wire path might
    // unbox a runtime `null` (page-supplied File-like with a
    // non-string name). The matcher must not throw.
    assert.equal(extensionOf(undefined as unknown as string), "");
    assert.equal(extensionOf(null as unknown as string), "");
    assert.equal(extensionOf(42 as unknown as string), "");
});

// --- isRiskyExtension -----------------------------------------------------

test("isRiskyExtension matches every entry in the baked-in default list", () => {
    for (const ext of BAKED_IN_RISKY_EXTENSIONS) {
        assert.ok(
            isRiskyExtension(`file.${ext}`),
            `baked-in entry ${ext} must match against file.${ext}`,
        );
        // Case-insensitive match per the extensionOf normalisation.
        assert.ok(
            isRiskyExtension(`FILE.${ext.toUpperCase()}`),
            `baked-in entry ${ext} must match case-insensitively`,
        );
    }
});

test("isRiskyExtension rejects common benign developer extensions", () => {
    // Per the design discussion .js is INTENTIONALLY not on the
    // baked-in list (too noisy for engineers) — that exclusion is
    // pinned here so a future refactor doesn't sneak it back.
    for (const ext of ["txt", "pdf", "csv", "md", "log", "json", "html", "js", "ts"]) {
        assert.equal(
            isRiskyExtension(`harmless.${ext}`),
            false,
            `benign extension ${ext} MUST NOT be on the risky list`,
        );
    }
});

test("isRiskyExtension treats dotless / hidden files as non-risky", () => {
    assert.equal(isRiskyExtension("Makefile"), false);
    assert.equal(isRiskyExtension(".gitignore"), false);
    assert.equal(isRiskyExtension(""), false);
});

test("isRiskyExtension respects an empty list (opt-out wire shape)", () => {
    // The empty-list wire shape means "operator explicitly opted
    // out of risky-extension blocking" — the matcher must return
    // false for every input, including names that would match the
    // baked-in list.
    assert.equal(isRiskyExtension("trojan.exe", []), false);
    assert.equal(isRiskyExtension("payload.scr", []), false);
});

test("isRiskyExtension matches against a caller-supplied override list", () => {
    const list = ["foo", "bar"];
    assert.ok(isRiskyExtension("evil.foo", list));
    assert.ok(isRiskyExtension("evil.BAR", list));
    assert.equal(
        isRiskyExtension("safe.exe", list),
        false,
        "exe is on the baked-in list but NOT on the override — must miss",
    );
});

test("isRiskyExtension blocks the canonical PR7 set (.exe, .scr, .ps1, .vbs, .bat, .cmd, .msi, .iso)", () => {
    // Sample the high-signal subset called out in the plan; the
    // exhaustive check above covers the rest of the 31 entries.
    for (const ext of ["exe", "scr", "ps1", "vbs", "bat", "cmd", "msi", "iso"]) {
        assert.ok(isRiskyExtension(`evil.${ext}`), `must block .${ext}`);
    }
});

// --- normaliseEntries -----------------------------------------------------

test("normaliseEntries lowercases, strips leading dot, drops blanks", () => {
    const got = normaliseEntries([".EXE", "scr", "  PS1  ", "", "."]);
    assert.deepEqual(Array.from(got), ["exe", "scr", "ps1"]);
});

test("normaliseEntries drops non-string entries silently", () => {
    const got = normaliseEntries([
        "exe",
        42 as unknown as string,
        null as unknown as string,
        undefined as unknown as string,
        "scr",
    ]);
    assert.deepEqual(Array.from(got), ["exe", "scr"]);
});

// --- cache surface --------------------------------------------------------

test("getCachedRiskyExtensions defaults to the baked-in list before bootstrap", () => {
    assert.equal(
        getCachedRiskyExtensions().length,
        BAKED_IN_RISKY_EXTENSIONS.length,
        "default cache MUST be the baked-in list so a race-with-bootstrap falls safe",
    );
});

test("setCachedRiskyExtensions overrides the cache for tests", () => {
    rxt.setCachedRiskyExtensions(["foo"]);
    assert.deepEqual(Array.from(getCachedRiskyExtensions()), ["foo"]);
    // After the override, the matcher consults the cache via its
    // default-second-arg path: x.foo matches (override entry),
    // x.exe misses (baked-in only, not in the override). This pins
    // that getCachedRiskyExtensions is the single source of truth
    // the interceptor reads from.
    assert.equal(isRiskyExtension("x.foo", getCachedRiskyExtensions()), true);
    assert.equal(isRiskyExtension("x.exe", getCachedRiskyExtensions()), false);
});

test("__test__.reset() restores the cache to the baked-in default", () => {
    rxt.setCachedRiskyExtensions(["foo"]);
    rxt.reset();
    assert.equal(
        getCachedRiskyExtensions().length,
        BAKED_IN_RISKY_EXTENSIONS.length,
    );
});

// --- materialiseReply -----------------------------------------------------

test("materialiseReply returns the baked-in list for mode=default", () => {
    const got = rxt.materialiseReply({
        kind: "risky-extensions-result",
        mode: "default",
        extensions: [],
    });
    assert.equal(got.length, BAKED_IN_RISKY_EXTENSIONS.length);
});

test("materialiseReply returns the empty list for mode=configured with []", () => {
    const got = rxt.materialiseReply({
        kind: "risky-extensions-result",
        mode: "configured",
        extensions: [],
    });
    assert.equal(got.length, 0, "opt-out wire shape MUST yield an empty cache");
});

test("materialiseReply normalises the configured list defensively", () => {
    const got = rxt.materialiseReply({
        kind: "risky-extensions-result",
        mode: "configured",
        extensions: [".EXE", "scr", "  PS1  ", ""],
    });
    assert.deepEqual(Array.from(got), ["exe", "scr", "ps1"]);
});
