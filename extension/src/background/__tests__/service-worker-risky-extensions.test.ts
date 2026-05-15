// Service-worker risky-file-extension plumbing unit tests
// (Phase 7 / B2). Covers:
//   - cold-start fetch against /api/config/risky-extensions
//   - the three wire states (absent / explicit empty / explicit list)
//   - in-process cache + TTL
//   - chrome.storage.session mirror (default sentinel vs. array)
//   - leave-cache-on-failure semantics
//
// Mirrors the C2 test harness shape so a future cleanup pass can
// fold the two into a shared helper.

import { test } from "node:test";
import assert from "node:assert/strict";

interface FakeStorageArea {
    data: Record<string, unknown>;
    get: (key: string) => Promise<Record<string, unknown>>;
    set: (entries: Record<string, unknown>) => Promise<void>;
}

interface FakeChrome {
    runtime: {
        onMessage: { addListener: (fn: unknown) => void };
        sendMessage?: (msg: unknown) => Promise<unknown>;
    };
    storage: { session: FakeStorageArea };
    scripting?: unknown;
}

function makeFakeChrome(): FakeChrome {
    const session: FakeStorageArea = {
        data: {},
        async get(key) {
            return key in this.data ? { [key]: this.data[key] } : {};
        },
        async set(entries) {
            for (const [k, v] of Object.entries(entries)) this.data[k] = v;
        },
    };
    return {
        runtime: { onMessage: { addListener: () => { /* swallow */ } } },
        storage: { session },
        scripting: {
            registerContentScripts: async () => undefined,
            unregisterContentScripts: async () => undefined,
            getRegisteredContentScripts: async () => [],
        },
    };
}

interface FetchCall {
    url: string;
    method: string | undefined;
}

interface FetchScript {
    calls: FetchCall[];
    handler: (call: FetchCall, index: number) => Response | Promise<Response>;
}

function installFetch(script: FetchScript): void {
    let i = 0;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input.toString();
        const call: FetchCall = { url, method: init?.method ?? "GET" };
        if (!url.includes("/api/config/risky-extensions")) {
            return new Response("{}", { status: 200 });
        }
        script.calls.push(call);
        return await script.handler(call, i++);
    }) as typeof fetch;
}

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

test("getRiskyExtensions parses the absent-extensions wire shape as mode=default", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    const calls: FetchCall[] = [];
    installFetch({
        calls,
        // Agent omitted the `extensions` field: the privacy-first
        // baked-in-default wire shape.
        handler: () => jsonResponse({}),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    const got = await mod.getRiskyExtensions();
    assert.equal(got.mode, "default");
    assert.deepEqual(Array.from(got.extensions), []);
    assert.match(calls[0].url, /\/api\/config\/risky-extensions$/);
});

test("getRiskyExtensions parses the explicit empty list as mode=configured opt-out", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        // Agent explicitly opted out: `extensions: []`.
        handler: () => jsonResponse({ extensions: [] }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    const got = await mod.getRiskyExtensions();
    assert.equal(got.mode, "configured");
    assert.deepEqual(Array.from(got.extensions), []);
});

test("getRiskyExtensions parses a populated list as mode=configured", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => jsonResponse({ extensions: ["exe", "scr", "ps1"] }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    const got = await mod.getRiskyExtensions();
    assert.equal(got.mode, "configured");
    assert.deepEqual(Array.from(got.extensions), ["exe", "scr", "ps1"]);
});

test("getRiskyExtensions caches subsequent calls inside the TTL", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    const calls: FetchCall[] = [];
    installFetch({
        calls,
        handler: () => jsonResponse({ extensions: ["exe"] }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    await mod.getRiskyExtensions();
    await mod.getRiskyExtensions();
    assert.equal(calls.length, 1, "second call inside the TTL must not hit the network");
});

test("getRiskyExtensions mirrors mode=default as the 'default' storage sentinel", async () => {
    const fake = makeFakeChrome();
    (globalThis as { chrome?: unknown }).chrome = fake;
    installFetch({
        calls: [],
        handler: () => jsonResponse({}),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();
    await mod.getRiskyExtensions();

    assert.equal(
        fake.storage.session.data["secureEdge:riskyExtensions"],
        "default",
        "mode=default MUST mirror as the literal 'default' sentinel so a worker-eviction fast path knows to use the baked-in list",
    );
});

test("getRiskyExtensions mirrors mode=configured as a JSON array in storage", async () => {
    const fake = makeFakeChrome();
    (globalThis as { chrome?: unknown }).chrome = fake;
    installFetch({
        calls: [],
        handler: () => jsonResponse({ extensions: ["exe", "msi"] }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();
    await mod.getRiskyExtensions();

    const stored = fake.storage.session.data["secureEdge:riskyExtensions"];
    assert.ok(Array.isArray(stored), "configured mode MUST mirror as a JSON array");
    assert.deepEqual(stored, ["exe", "msi"]);
});

test("getRiskyExtensions leaves the previous cached value intact on a fetch failure", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => { throw new Error("network down"); },
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();
    // Seed the cache with a configured list that the failed
    // fetch would otherwise replace.
    mod.__test__.setRiskyExtensions("configured", ["exe", "scr"], Date.now());

    const got = await mod.getRiskyExtensions();
    assert.equal(got.mode, "configured");
    assert.deepEqual(Array.from(got.extensions), ["exe", "scr"]);
});

test("getRiskyExtensions re-fetches after the TTL expires", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    const calls: FetchCall[] = [];
    let next: { extensions?: string[] } = { extensions: ["exe"] };
    installFetch({
        calls,
        handler: () => jsonResponse(next),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    await mod.getRiskyExtensions();
    assert.equal(calls.length, 1);

    // Rewind the cache age past the TTL.
    mod.__test__.setRiskyExtensions(
        "configured",
        ["exe"],
        Date.now() - mod.__test__.RISKY_EXTENSIONS_TTL_MS - 1,
    );
    next = { extensions: ["msi"] };

    const got = await mod.getRiskyExtensions();
    assert.deepEqual(Array.from(got.extensions), ["msi"]);
    assert.equal(calls.length, 2);
});

test("getRiskyExtensions falls back to mode=default when agent returns non-2xx", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => new Response("", { status: 503 }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetRiskyExtensions();

    const got = await mod.getRiskyExtensions();
    // A failed fetch leaves the post-reset default in place
    // (mode=default + empty array) — the content script then uses
    // its baked-in list, falling safe.
    assert.equal(got.mode, "default");
    assert.deepEqual(Array.from(got.extensions), []);
});
