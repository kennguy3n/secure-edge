// Service-worker enforcement-mode plumbing unit tests (Phase 7 / C2).
//
// Covers the cold-start fetch against /api/config/enforcement-mode,
// the in-process cache + TTL, the chrome.storage.session mirror, and
// the runtime.sendMessage handler that content scripts call to read
// the cached value.
//
// We boot the service worker via a deferred `import("…")` so the
// fake `chrome` global is in place before the module-level
// `chrome.runtime.onMessage.addListener` runs.

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
        runtime: {
            onMessage: { addListener: () => { /* swallow */ } },
        },
        storage: { session },
        // Stub the scripting API so startDynamicHostUpdater()'s
        // try/catch swallows quietly without polluting the cache.
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
    /** Drives each successive fetch call. A function lets a test
     *  fail the first call and succeed the second to exercise the
     *  fall-back to the cached value. */
    handler: (call: FetchCall, index: number) => Response | Promise<Response>;
}

function installFetch(script: FetchScript): void {
    let i = 0;
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input.toString();
        const call: FetchCall = { url, method: init?.method ?? "GET" };
        // Only the enforcement-mode endpoint is interesting for these
        // tests. Other concurrent fetches (e.g. the dynamic-hosts
        // updater the service worker boots in the background) get a
        // benign empty reply so they don't pollute the call log.
        if (!url.includes("/api/config/enforcement-mode")) {
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

test("getEnforcementMode fetches /api/config/enforcement-mode and caches the result", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    const calls: FetchCall[] = [];
    installFetch({
        calls,
        handler: () => jsonResponse({ mode: "managed" }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();

    const first = await mod.getEnforcementMode();
    assert.equal(first, "managed");

    const second = await mod.getEnforcementMode();
    assert.equal(second, "managed");
    assert.equal(calls.length, 1, "second call inside the TTL must not hit the network");

    assert.match(calls[0].url, /\/api\/config\/enforcement-mode$/);
});

test("getEnforcementMode mirrors the fetched mode into chrome.storage.session", async () => {
    const fake = makeFakeChrome();
    (globalThis as { chrome?: unknown }).chrome = fake;
    installFetch({
        calls: [],
        handler: () => jsonResponse({ mode: "team" }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();
    await mod.getEnforcementMode();

    assert.equal(fake.storage.session.data["secureEdge:enforcementMode"], "team");
});

test("getEnforcementMode leaves the previous cached value intact on a fetch failure", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => { throw new Error("network down"); },
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();
    // Seed the cache with a managed value that the failed fetch
    // would otherwise replace.
    mod.__test__.setEnforcementMode("managed", Date.now());

    const got = await mod.getEnforcementMode();
    assert.equal(got, "managed", "failure must not flip the cache back to personal");
});

test("getEnforcementMode falls back to personal when the agent has never been reached", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => new Response("", { status: 503 }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();

    const got = await mod.getEnforcementMode();
    assert.equal(got, "personal", "no fresh value, default stance is personal");
});

test("getEnforcementMode ignores out-of-band values that aren't part of the EnforcementMode union", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    installFetch({
        calls: [],
        handler: () => jsonResponse({ mode: "strict" }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();

    const got = await mod.getEnforcementMode();
    assert.equal(got, "personal", "bogus mode is treated as a failed fetch (default stance)");
});

test("getEnforcementMode re-fetches after the TTL expires", async () => {
    (globalThis as { chrome?: unknown }).chrome = makeFakeChrome();
    const calls: FetchCall[] = [];
    let nextMode: "personal" | "team" | "managed" = "personal";
    installFetch({
        calls,
        handler: () => jsonResponse({ mode: nextMode }),
    });

    const mod = await import("../service-worker.js");
    mod.__test__.resetEnforcementMode();

    // Prime the cache with the first value.
    const first = await mod.getEnforcementMode();
    assert.equal(first, "personal");
    assert.equal(calls.length, 1);

    // Manually rewind cache age to before the TTL boundary so the
    // next call triggers another fetch.
    mod.__test__.setEnforcementMode("personal", Date.now() - mod.__test__.ENFORCEMENT_MODE_TTL_MS - 1);
    nextMode = "managed";

    const second = await mod.getEnforcementMode();
    assert.equal(second, "managed", "expired TTL must surface the new agent value");
    assert.equal(calls.length, 2);
});
