// Unit tests for the Native Messaging client.
//
// The tests fake the `chrome.runtime.connectNative` API by injecting
// a global `chrome` shim. `__test__.reset()` clears the module-level
// singleton between cases.

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

// MV3 service workers expose crypto.subtle natively; under
// node:test we have to wire up Node's webcrypto so the
// MAC-compute path in native-messaging.ts has something to
// sign against. Only set if absent (newer Node exposes it
// globally already).
if (typeof (globalThis as { crypto?: unknown }).crypto === "undefined") {
    (globalThis as { crypto: unknown }).crypto = webcrypto;
}

import { __test__, helloViaNativeMessaging, scanViaNativeMessaging } from "../native-messaging.js";
import {
    computeRequestMAC,
    computeResponseMAC,
    decodeNonceHex,
    importBridgeKey,
} from "../bridge-mac.js";

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

// C1: HMAC bridge tests. The extension caches a per-connection
// nonce + signing key from the hello reply and uses them to sign
// every subsequent non-hello frame. Tests below verify the full
// MAC round-trip and the lenient/strict reply-side behaviour.

const NONCE_HEX = "00112233445566778899aabbccddeeff";

test("scan request carries a MAC after a hello surfaces nonce + token", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    // Boot the bridge: send hello, agent surfaces token + nonce.
    const helloP = helloViaNativeMessaging();
    await Promise.resolve();
    const helloPosted = hooks.posted[0] as { id: number };
    hooks.deliver({ id: helloPosted.id, api_token: "tok-abc", bridge_nonce: NONCE_HEX });
    await helloP;
    // Wait for the async key-import to settle (importKey is
    // promise-shaped under Web Crypto).
    for (let i = 0; i < 20 && !__test__.bridgeKeyReady(); i++) {
        await new Promise((r) => setTimeout(r, 1));
    }
    assert.equal(__test__.bridgeKeyReady(), true);

    // Now send a scan and verify the posted frame carries a mac.
    const scanP = scanViaNativeMessaging("AKIAEXAMPLE");
    // The MAC compute is async; poll the posted queue.
    for (let i = 0; i < 20 && hooks.posted.length < 2; i++) {
        await new Promise((r) => setTimeout(r, 1));
    }
    assert.equal(hooks.posted.length, 2);
    const scanPosted = hooks.posted[1] as { id: number; kind: string; content: string; mac?: string };
    assert.equal(scanPosted.kind, "scan");
    assert.equal(scanPosted.content, "AKIAEXAMPLE");
    assert.equal(typeof scanPosted.mac, "string");
    // The mac must be the documented HMAC-SHA256(secret, nonce || ...).
    const refKey = await importBridgeKey("tok-abc");
    const refNonce = decodeNonceHex(NONCE_HEX)!;
    const expected = await computeRequestMAC(refKey, refNonce, scanPosted.id, "scan", "AKIAEXAMPLE");
    assert.equal(scanPosted.mac, expected);

    // Deliver a properly-signed reply so the test cleans up the
    // pending entry without firing the timeout.
    const replyMAC = await computeResponseMAC(refKey, refNonce, scanPosted.id, "scan", 0x00, "", "");
    hooks.deliver({
        id: scanPosted.id,
        result: { blocked: false, pattern_name: "", score: 0 },
        mac: replyMAC,
    });
    const r = await scanP;
    assert.deepEqual(r, { blocked: false, pattern_name: "", score: 0 });
    clearChrome();
});

test("scan request has NO mac when the agent didn't surface bridge_nonce (pre-C1 agent)", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const helloP = helloViaNativeMessaging();
    await Promise.resolve();
    const helloPosted = hooks.posted[0] as { id: number };
    // Pre-C1 agent: returns api_token but no bridge_nonce.
    hooks.deliver({ id: helloPosted.id, api_token: "tok-abc" });
    await helloP;
    // bridgeKeyReady stays false — no nonce to seed with.
    assert.equal(__test__.bridgeKeyReady(), false);
    const scanP = scanViaNativeMessaging("x");
    for (let i = 0; i < 20 && hooks.posted.length < 2; i++) {
        await new Promise((r) => setTimeout(r, 1));
    }
    const scanPosted = hooks.posted[1] as { id: number; mac?: string };
    assert.equal(scanPosted.mac, undefined,
        "extension must NOT add a MAC when the agent didn't bootstrap one");
    hooks.deliver({ id: scanPosted.id, result: { blocked: false, pattern_name: "", score: 0 } });
    await scanP;
    clearChrome();
});

test("scan request has NO mac when hello surfaces empty token", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const helloP = helloViaNativeMessaging();
    await Promise.resolve();
    const helloPosted = hooks.posted[0] as { id: number };
    // Agent has no token configured; surfaces empty.
    hooks.deliver({ id: helloPosted.id, api_token: "" });
    await helloP;
    assert.equal(__test__.bridgeKeyReady(), false);
    const scanP = scanViaNativeMessaging("x");
    for (let i = 0; i < 20 && hooks.posted.length < 2; i++) {
        await new Promise((r) => setTimeout(r, 1));
    }
    const scanPosted = hooks.posted[1] as { mac?: string; id: number };
    assert.equal(scanPosted.mac, undefined);
    hooks.deliver({ id: scanPosted.id, result: { blocked: false, pattern_name: "", score: 0 } });
    await scanP;
    clearChrome();
});

test("port disconnect resets the cached bridge key + nonce", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const helloP = helloViaNativeMessaging();
    await Promise.resolve();
    const helloPosted = hooks.posted[0] as { id: number };
    hooks.deliver({ id: helloPosted.id, api_token: "tok-abc", bridge_nonce: NONCE_HEX });
    await helloP;
    for (let i = 0; i < 20 && !__test__.bridgeKeyReady(); i++) {
        await new Promise((r) => setTimeout(r, 1));
    }
    assert.equal(__test__.bridgeKeyReady(), true);
    hooks.disconnect();
    assert.equal(__test__.bridgeKeyReady(), false,
        "disconnect must clear the cached bridge key + nonce");
    clearChrome();
});

test("hello reply with malformed bridge_nonce hex is silently ignored", async () => {
    __test__.reset();
    const hooks = installFakeChrome();
    const helloP = helloViaNativeMessaging();
    await Promise.resolve();
    const helloPosted = hooks.posted[0] as { id: number };
    // Length is right but the chars aren't hex - decodeNonceHex
    // returns null and the bridge falls back to no-MAC posture.
    hooks.deliver({ id: helloPosted.id, api_token: "tok", bridge_nonce: "Z".repeat(32) });
    const r = await helloP;
    assert.equal(r, "tok");
    assert.equal(__test__.bridgeKeyReady(), false);
    clearChrome();
});
