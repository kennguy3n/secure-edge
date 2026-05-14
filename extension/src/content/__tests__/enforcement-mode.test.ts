// Unit tests for the C2 enforcement-mode plumbing on the content
// side: the policy helpers in scan-client, the policy toast variants
// in toast, and the bridge handler's managed-mode block synthesis.
//
// These tests intentionally do not boot the service worker or hit
// runtime.sendMessage — the worker side is covered separately. Here
// we drive the in-process cache directly via the __test__ surface
// and assert each interceptor-facing helper behaves the way the
// recommended-order PR2 plan describes:
//
//   personal  -> agent unavailable: silent allow
//              -> oversize: silent allow
//   team      -> agent unavailable: warn + allow
//              -> oversize: silent allow
//   managed   -> agent unavailable: block + policy toast
//              -> oversize: block + policy toast

import { afterEach, test } from "node:test";
import assert from "node:assert/strict";

import {
    __test__ as scanTest,
    policyForOversize,
    policyForUnavailable,
} from "../scan-client.js";
import { __test__ as iso, POLICY_PATTERN_AGENT_UNAVAILABLE } from "../network-interceptor.js";
import { __test__ as toastTest } from "../toast.js";

const { handleBridgeMessage } = iso;

afterEach(() => {
    scanTest.resetEnforcementMode();
});

test("policyForUnavailable returns allow/warn/block for personal/team/managed", () => {
    assert.equal(policyForUnavailable("personal"), "allow");
    assert.equal(policyForUnavailable("team"), "warn");
    assert.equal(policyForUnavailable("managed"), "block");
});

test("policyForOversize is allow except in managed mode", () => {
    assert.equal(policyForOversize("personal"), "allow");
    assert.equal(policyForOversize("team"), "allow");
    assert.equal(policyForOversize("managed"), "block");
});

test("policyForUnavailable defaults to the cached mode (no explicit arg)", () => {
    // The cached default is personal; resetEnforcementMode() in the
    // afterEach restores it between cases.
    assert.equal(policyForUnavailable(), "allow");
    scanTest.setCachedEnforcementMode("team");
    assert.equal(policyForUnavailable(), "warn");
    scanTest.setCachedEnforcementMode("managed");
    assert.equal(policyForUnavailable(), "block");
});

test("policyForOversize defaults to the cached mode (no explicit arg)", () => {
    assert.equal(policyForOversize(), "allow");
    scanTest.setCachedEnforcementMode("managed");
    assert.equal(policyForOversize(), "block");
});

test("policyMessage labels agent-unavailable distinctly from oversize", () => {
    const blockAgent = toastTest.policyMessage("block", "agent-unavailable", "paste");
    const blockOver = toastTest.policyMessage("block", "oversize", "paste");
    assert.match(blockAgent, /agent unavailable/i);
    assert.match(blockAgent, /blocked by policy/i);
    assert.match(blockOver, /too large/i);
    assert.match(blockOver, /blocked by policy/i);
});

test("policyMessage warn variant says 'could not scan' rather than 'blocked'", () => {
    const warnAgent = toastTest.policyMessage("warn", "agent-unavailable", "paste");
    const warnOver = toastTest.policyMessage("warn", "oversize", "submission");
    assert.match(warnAgent, /could not scan/i);
    assert.match(warnAgent, /scan skipped/i);
    assert.match(warnOver, /could not scan/i);
    assert.match(warnOver, /skipped/i);
});

// --- Bridge handler ---------------------------------------------------------

interface RecordedReply {
    id: string;
    blocked: boolean | null;
    pattern_name?: string;
}

function recorder(): { recorded: RecordedReply[]; reply: (msg: { id: string; result: { blocked: boolean; pattern_name: string; score: number } | null }) => void } {
    const recorded: RecordedReply[] = [];
    return {
        recorded,
        reply(msg) {
            recorded.push({
                id: msg.id,
                blocked: msg.result ? msg.result.blocked : null,
                pattern_name: msg.result?.pattern_name,
            });
        },
    };
}

test("handleBridgeMessage in personal mode forwards null on agent failure (no toast)", async () => {
    let toasted = 0;
    let warned = 0;
    let blocked = 0;
    const { recorded, reply } = recorder();
    await handleBridgeMessage(
        { source: "secure-edge-bridge", kind: "scan-req", id: "a", content: "hello" },
        reply,
        async () => null,
        () => { toasted++; },
        {
            onUnavailable: () => "allow",
            showPolicyBlock: () => { blocked++; },
            showPolicyWarn: () => { warned++; },
        },
    );
    assert.deepEqual(recorded, [{ id: "a", blocked: null, pattern_name: undefined }]);
    assert.equal(toasted, 0, "no DLP-block toast on a clean fall-open");
    assert.equal(warned, 0, "personal mode does not warn");
    assert.equal(blocked, 0, "personal mode does not block");
});

test("handleBridgeMessage in team mode forwards null on agent failure but surfaces a warn toast", async () => {
    let toasted = 0;
    let warned = 0;
    let blocked = 0;
    const { recorded, reply } = recorder();
    await handleBridgeMessage(
        { source: "secure-edge-bridge", kind: "scan-req", id: "b", content: "hello" },
        reply,
        async () => null,
        () => { toasted++; },
        {
            onUnavailable: () => "warn",
            showPolicyBlock: () => { blocked++; },
            showPolicyWarn: () => { warned++; },
        },
    );
    assert.deepEqual(recorded, [{ id: "b", blocked: null, pattern_name: undefined }]);
    assert.equal(warned, 1, "team mode surfaces exactly one warn toast");
    assert.equal(blocked, 0, "team mode does not synthesise a block");
    assert.equal(toasted, 0, "team mode does not fire the DLP-block toast");
});

test("handleBridgeMessage in managed mode synthesises a blocked result + policy toast", async () => {
    let blocked = 0;
    let warned = 0;
    const { recorded, reply } = recorder();
    await handleBridgeMessage(
        { source: "secure-edge-bridge", kind: "scan-req", id: "c", content: "hello" },
        reply,
        async () => null,
        () => { /* unused */ },
        {
            onUnavailable: () => "block",
            showPolicyBlock: () => { blocked++; },
            showPolicyWarn: () => { warned++; },
        },
    );
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].id, "c");
    assert.equal(recorded[0].blocked, true);
    assert.equal(recorded[0].pattern_name, POLICY_PATTERN_AGENT_UNAVAILABLE);
    assert.equal(blocked, 1, "managed mode surfaces exactly one block toast");
    assert.equal(warned, 0, "managed mode does not warn");
});

test("handleBridgeMessage in managed mode still passes through real DLP blocks unchanged", async () => {
    let blockedToast = 0;
    let policyBlock = 0;
    const { recorded, reply } = recorder();
    await handleBridgeMessage(
        { source: "secure-edge-bridge", kind: "scan-req", id: "d", content: "secret" },
        reply,
        async () => ({ blocked: true, pattern_name: "AWS_KEY", score: 0.9 }),
        () => { blockedToast++; },
        {
            onUnavailable: () => "block",
            showPolicyBlock: () => { policyBlock++; },
        },
    );
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].blocked, true);
    assert.equal(recorded[0].pattern_name, "AWS_KEY", "real DLP verdict is not replaced");
    assert.equal(blockedToast, 1, "real DLP blocks fire the DLP-block toast");
    assert.equal(policyBlock, 0, "policy-block toast is suppressed when the agent does answer");
});

test("handleBridgeMessage passes through a clean (allowed) verdict in managed mode", async () => {
    let policyBlock = 0;
    const { recorded, reply } = recorder();
    await handleBridgeMessage(
        { source: "secure-edge-bridge", kind: "scan-req", id: "e", content: "hello" },
        reply,
        async () => ({ blocked: false, pattern_name: "", score: 0 }),
        () => { /* unused */ },
        {
            onUnavailable: () => "block",
            showPolicyBlock: () => { policyBlock++; },
        },
    );
    assert.equal(recorded.length, 1);
    assert.equal(recorded[0].blocked, false);
    assert.equal(policyBlock, 0, "policy-block toast only fires when the agent had no verdict");
});

test("setCachedEnforcementMode reflects through to policy helpers without an explicit arg", () => {
    scanTest.setCachedEnforcementMode("managed");
    assert.equal(policyForUnavailable(), "block");
    assert.equal(policyForOversize(), "block");
    scanTest.setCachedEnforcementMode("team");
    assert.equal(policyForUnavailable(), "warn");
    assert.equal(policyForOversize(), "allow");
});
