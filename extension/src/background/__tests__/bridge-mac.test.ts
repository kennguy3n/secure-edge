// Unit tests for the extension-side bridge HMAC helpers.
//
// The determinism vectors here are computed once and pinned. They
// MUST stay byte-identical with the agent-side counterparts in
// agent/internal/api/bridge_mac_test.go — if either side's HMAC
// input layout drifts, both test suites will fail (one will pin
// the new value, the other the old).

import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

// Node's webcrypto matches the MV3 service worker's crypto.subtle
// surface byte-for-byte; we only stub the global if it isn't
// already present (newer Node versions expose it natively).
if (typeof (globalThis as { crypto?: unknown }).crypto === "undefined") {
    (globalThis as { crypto: unknown }).crypto = webcrypto;
}

import {
    BRIDGE_NONCE_LEN,
    computeRequestMAC,
    computeResponseMAC,
    constantTimeEqHex,
    decodeNonceHex,
    importBridgeKey,
} from "../bridge-mac.js";

const NONCE_HEX = "00112233445566778899aabbccddeeff";

test("decodeNonceHex accepts a well-formed 32-char lowercase hex string", () => {
    const out = decodeNonceHex(NONCE_HEX);
    assert.notEqual(out, null);
    assert.equal(out!.length, BRIDGE_NONCE_LEN);
    assert.equal(out![0], 0x00);
    assert.equal(out![1], 0x11);
    assert.equal(out![15], 0xff);
});

test("decodeNonceHex rejects empty, wrong-length, and non-hex inputs", () => {
    assert.equal(decodeNonceHex(""), null);
    assert.equal(decodeNonceHex("aa"), null); // too short
    assert.equal(decodeNonceHex("Z".repeat(32)), null); // not hex
    assert.equal(decodeNonceHex(NONCE_HEX + "00"), null); // too long
    // Uppercase hex is intentionally rejected so the agent + extension
    // canonicalise on the same encoding (lowercase).
    assert.equal(decodeNonceHex(NONCE_HEX.toUpperCase()), null);
});

test("computeRequestMAC returns 64 lowercase hex chars and is deterministic", async () => {
    const key = await importBridgeKey("test-secret");
    const nonce = decodeNonceHex(NONCE_HEX);
    assert.notEqual(nonce, null);
    const a = await computeRequestMAC(key, nonce!, 7, "scan", "AKIAEXAMPLE");
    const b = await computeRequestMAC(key, nonce!, 7, "scan", "AKIAEXAMPLE");
    assert.equal(a.length, 64);
    assert.equal(a, b);
    assert.match(a, /^[0-9a-f]+$/);
});

test("computeRequestMAC changes when any input field changes", async () => {
    const key = await importBridgeKey("k");
    const nonce = decodeNonceHex(NONCE_HEX)!;
    const altNonce = decodeNonceHex("ffeeddccbbaa99887766554433221100")!;
    const altKey = await importBridgeKey("kk");
    const base = await computeRequestMAC(key, nonce, 1, "scan", "x");
    const mutated: { name: string; mac: string }[] = [
        { name: "different-secret", mac: await computeRequestMAC(altKey, nonce, 1, "scan", "x") },
        { name: "different-nonce", mac: await computeRequestMAC(key, altNonce, 1, "scan", "x") },
        { name: "different-id", mac: await computeRequestMAC(key, nonce, 2, "scan", "x") },
        { name: "different-kind", mac: await computeRequestMAC(key, nonce, 1, "hello", "x") },
        { name: "different-content", mac: await computeRequestMAC(key, nonce, 1, "scan", "y") },
    ];
    for (const m of mutated) {
        assert.notEqual(m.mac, base, `${m.name} did not move the MAC`);
    }
});

test("request and response MACs differ for the same (key, nonce, id, kind)", async () => {
    const key = await importBridgeKey("k");
    const nonce = decodeNonceHex(NONCE_HEX)!;
    const req = await computeRequestMAC(key, nonce, 1, "scan", "");
    const resp = await computeResponseMAC(key, nonce, 1, "scan", 0x00, "", "");
    assert.notEqual(req, resp,
        "request and response MACs must differ — direction byte not in HMAC input");
});

test("computeRequestMAC matches the canonical cross-language reference vector", async () => {
    // The same (secret, nonce, id, kind, content) tuple is pinned in
    // agent/internal/api/bridge_mac_test.go::TestComputeRequestMAC_Determinism.
    // If either side's HMAC layout drifts, this assertion fails
    // on one side and the Go-side counterpart fails on the other.
    const key = await importBridgeKey("test-secret");
    const nonce = decodeNonceHex(NONCE_HEX)!;
    const got = await computeRequestMAC(key, nonce, 7, "scan", "AKIAEXAMPLE");
    assert.equal(got, "34f819f23133c9fc58b313833c1f70fb0cbedabf7adbc61ae37ce916d191dfe0");
});

test("computeResponseMAC matches the canonical cross-language reference vector", async () => {
    const key = await importBridgeKey("test-secret");
    const nonce = decodeNonceHex(NONCE_HEX)!;
    const got = await computeResponseMAC(key, nonce, 7, "scan", 0x01, "", "");
    assert.equal(got, "f902a99d89500a718a53c08c34c516a77c40fe62aa13951e9dab386fa3b7cdcf");
});

test("constantTimeEqHex returns true on identical strings and false on any diff", () => {
    assert.equal(constantTimeEqHex("abcd", "abcd"), true);
    assert.equal(constantTimeEqHex("abcd", "abce"), false);
    assert.equal(constantTimeEqHex("abcd", "abcde"), false); // length mismatch
    assert.equal(constantTimeEqHex("", ""), true);
});
