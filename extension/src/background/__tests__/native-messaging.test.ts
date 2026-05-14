// Unit tests for the Native Messaging client.
//
// The tests fake the `chrome.runtime.connectNative` API by injecting
// a global `chrome` shim. `__test__.reset()` clears the module-level
// singleton between cases.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__, scanViaNativeMessaging } from "../native-messaging.js";

type Listener<T> = (msg: T) => void;

interface FakePort {
    onMessage: { addListener(fn: Listener<unknown>): void };
    onDisconnect: { addListener(fn: Listener<void>): void };
    postMessage(msg: unknown): void;
}

interface PortHooks {
    port: FakePort;
    deliver(msg: unknown): void;
    disconnect(): void;
    posted: unknown[];
    postThrows: boolean;
}

function installFakeChrome(hooks?: { connectNativeThrows?: boolean; missingApi?: boolean }): PortHooks {
    const posted: unknown[] = [];
    let onMessage: Listener<unknown> | undefined;
    let onDisconnect: Listener<void> | undefined;
    const portState: PortHooks = {
        posted,
        postThrows: false,
        port: {
            onMessage: { addListener: (fn) => { onMessage = fn; } },
            onDisconnect: { addListener: (fn) => { onDisconnect = fn; } },
            postMessage(msg) {
                if (portState.postThrows) throw new Error("postMessage failed");
                posted.push(msg);
            },
        },
        deliver(msg) { onMessage?.(msg); },
        disconnect() { onDisconnect?.(); },
    };
    const runtime: Record<string, unknown> = {};
    if (!hooks?.missingApi) {
        runtime.connectNative = () => {
            if (hooks?.connectNativeThrows) throw new Error("not allowed");
            return portState.port;
        };
    }
    (globalThis as unknown as { chrome: unknown }).chrome = { runtime };
    return portState;
}

function clearChrome() {
    delete (globalThis as unknown as { chrome?: unknown }).chrome;
}

test("returns null when chrome.runtime.connectNative is unavailable", async () => {
    __test__.reset();
    installFakeChrome({ missingApi: true });
    const r = await scanViaNativeMessaging("hi");
    assert.equal(r, null);
    clearChrome();
});

test("returns null when connectNative throws", async () => {
    __test__.reset();
    installFakeChrome({ connectNativeThrows: true });
    const r = await scanViaNativeMessaging("hi");
    assert.equal(r, null);
    clearChrome();
});

test("round-trips a scan request and resolves with the host's result", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = scanViaNativeMessaging("hello");

    // Drain the microtask so the request is queued before we reply.
    await Promise.resolve();
    assert.equal(hooks.posted.length, 1);
    const posted = hooks.posted[0] as { id: number; kind: string; content: string };
    assert.equal(posted.kind, "scan");
    assert.equal(posted.content, "hello");
    assert.equal(typeof posted.id, "number");

    hooks.deliver({ id: posted.id, result: { blocked: true, pattern_name: "aws_key", score: 9 } });
    const r = await p;
    assert.deepEqual(r, { blocked: true, pattern_name: "aws_key", score: 9 });
    clearChrome();
});

test("resolves null when the host disconnects mid-flight", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = scanViaNativeMessaging("hello");
    await Promise.resolve();
    hooks.disconnect();
    const r = await p;
    assert.equal(r, null);
    clearChrome();
});

test("resolves null when postMessage throws", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    hooks.postThrows = true;
    const r = await scanViaNativeMessaging("hello");
    assert.equal(r, null);
    clearChrome();
});

// A2: hello handshake tests. The extension uses helloViaNativeMessaging
// at service-worker boot to fetch the per-install API token from the
// agent before any HTTP fallback runs.
import { helloViaNativeMessaging } from "../native-messaging.js";

test("helloViaNativeMessaging returns the agent's api_token", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = helloViaNativeMessaging();
    await Promise.resolve();
    assert.equal(hooks.posted.length, 1);
    const posted = hooks.posted[0] as { id: number; kind: string };
    assert.equal(posted.kind, "hello");
    hooks.deliver({ id: posted.id, api_token: "tok-abc-123" });
    const r = await p;
    assert.equal(r, "tok-abc-123");
    clearChrome();
});

test("helloViaNativeMessaging returns null on empty api_token reply", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = helloViaNativeMessaging();
    await Promise.resolve();
    const posted = hooks.posted[0] as { id: number };
    hooks.deliver({ id: posted.id, api_token: "" });
    const r = await p;
    assert.equal(r, null);
    clearChrome();
});

test("helloViaNativeMessaging returns null on host error", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = helloViaNativeMessaging();
    await Promise.resolve();
    const posted = hooks.posted[0] as { id: number };
    hooks.deliver({ id: posted.id, error: "no token configured" });
    const r = await p;
    assert.equal(r, null);
    clearChrome();
});

test("helloViaNativeMessaging returns null when host disconnects mid-flight", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const p = helloViaNativeMessaging();
    await Promise.resolve();
    hooks.disconnect();
    const r = await p;
    assert.equal(r, null);
    clearChrome();
});

test("helloViaNativeMessaging returns null when chrome.runtime.connectNative is unavailable", async () => {
    __test__.reset();
    installFakeChrome({ missingApi: true });
    const r = await helloViaNativeMessaging();
    assert.equal(r, null);
    clearChrome();
});

test("helloViaNativeMessaging and scanViaNativeMessaging route replies independently", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const helloP = helloViaNativeMessaging();
    const scanP = scanViaNativeMessaging("hello");
    await Promise.resolve();
    assert.equal(hooks.posted.length, 2);
    // Replies arrive out of order — verify each routes to the right
    // pending request map. The scan reply id is the second posted,
    // hello the first.
    const helloMsg = hooks.posted[0] as { id: number };
    const scanMsg = hooks.posted[1] as { id: number };
    hooks.deliver({ id: scanMsg.id, result: { blocked: false, pattern_name: "", score: 0 } });
    hooks.deliver({ id: helloMsg.id, api_token: "tok-xyz" });
    const [token, scan] = await Promise.all([helloP, scanP]);
    assert.equal(token, "tok-xyz");
    assert.deepEqual(scan, { blocked: false, pattern_name: "", score: 0 });
    clearChrome();
});
