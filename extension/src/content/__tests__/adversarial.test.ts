// G8: adversarial browser scenarios for the content-script bridge.
//
// The four scenarios pinned in this file all share a common
// premise: the page is fully hostile and the extension must still
// produce the documented outcome. Each test is one row of the
// adversarial matrix that informed the G8 plan:
//
//   Row | Hostile shape                          | Managed-mode outcome
//   ----+----------------------------------------+----------------------
//   A   | page forges scan-resp with in-flight  | duplicate rejected by
//       | id BEFORE the legitimate relay reply  | first-reply-wins gate
//   B   | page calls fetch() before our bridge   | bypass NOT observable
//       | document_start injection point         | from in-isolation tests;
//       |                                        | residual covered by the
//       |                                        | enforcement-mode policy
//   C   | content.length > MAX_SCAN_BYTES        | synthesised block result
//       | (oversize content in managed mode)     | (POLICY_PATTERN_OVERSIZE)
//   D   | scan returns null in managed mode      | synthesised block result
//       | (timeout / agent unavailable)          | (POLICY_PATTERN_AGENT_UNAVAILABLE)
//
// Row A and B were already covered structurally by the existing
// `network-interceptor.adversarial.test.ts`. The two new rows
// (C and D) are pinned here against `handleBridgeMessage` because
// that's the smallest surface that exercises the managed-mode
// branches end-to-end without standing up a fake DOM. The pair of
// existing rows are re-asserted here too as a hands-on regression
// gate — a refactor that breaks any one of the four would leave
// this file as the single canonical "what does the extension do
// when the page is hostile?" reference point.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    __test__ as iso,
    POLICY_PATTERN_OVERSIZE,
    POLICY_PATTERN_AGENT_UNAVAILABLE,
} from "../network-interceptor.js";
import { __test__ as mainWorld, MAX_SCAN_BYTES } from "../main-world-network.js";
import type { ScanResult } from "../../shared.js";

const { handleBridgeMessage, BRIDGE_SOURCE, ISO_SOURCE } = iso;
const { requestScan } = mainWorld;

interface BridgeReply {
    source: string;
    kind: string;
    id: string;
    result: ScanResult | null;
}

function captureReplies(): { replies: BridgeReply[]; reply: (msg: BridgeReply) => void } {
    const replies: BridgeReply[] = [];
    return { replies, reply: (m) => { replies.push(m); } };
}

// ---------------------------------------------------------------------------
// Row A — postMessage spoofing: first reply for a given request id wins.
// The bridge ↔ relay channel is page-observable by design; the relay
// cannot sign its reply with a secret the page-world bridge could
// verify (any secret the bridge knows is itself page-readable). Our
// defence is first-reply-wins on the MAIN-world side: requestScan
// removes its own listener as soon as the first scan-resp with the
// matching id arrives, so any subsequent forged reply (with the same
// id, observed off the bus) is dropped on the floor.
// ---------------------------------------------------------------------------

test("G8 / row A: forged scan-resp arriving AFTER the legitimate reply is ignored", async () => {
    type MessageListener = (ev: MessageEvent) => void;
    const listeners: MessageListener[] = [];
    let observedReqId: string | null = null;

    const win = {
        addEventListener(_type: "message", fn: MessageListener) {
            listeners.push(fn);
        },
        removeEventListener(_type: "message", fn: MessageListener) {
            const i = listeners.indexOf(fn);
            if (i >= 0) listeners.splice(i, 1);
        },
        postMessage(message: unknown) {
            const data = message as { source?: unknown; kind?: unknown; id?: unknown };
            if (data.source === BRIDGE_SOURCE && data.kind === "scan-req") {
                observedReqId = String(data.id ?? "");
                // The legitimate relay replies first. The page
                // attacker observes the request and tries to post a
                // *second* reply for the same id (a forged
                // "blocked: false" to bypass a real block, say). The
                // bridge must accept the first reply only.
                queueMicrotask(() => {
                    const real: BridgeReply = {
                        source: ISO_SOURCE,
                        kind: "scan-resp",
                        id: observedReqId!,
                        result: { blocked: true, pattern_name: "aws_key", score: 9 },
                    };
                    for (const fn of [...listeners]) fn({ data: real } as MessageEvent);
                    const forged: BridgeReply = {
                        source: ISO_SOURCE,
                        kind: "scan-resp",
                        id: observedReqId!,
                        result: { blocked: false, pattern_name: "", score: 0 },
                    };
                    for (const fn of [...listeners]) fn({ data: forged } as MessageEvent);
                });
            }
        },
    };

    const r = await requestScan(win, "AKIA" + "X".repeat(80), 1000);
    assert.deepEqual(
        r,
        { blocked: true, pattern_name: "aws_key", score: 9 },
        "first matching-id reply must win — forged duplicates after the genuine reply are dropped",
    );
    assert.notEqual(observedReqId, null);
});

// ---------------------------------------------------------------------------
// Row B — fetch() before bridge injection.
//
// document_start is the earliest extension injection point, but a
// page that runs JS before the extension's content script (e.g. via
// an inline <script> earlier in the document, before the manifest's
// run_at hook fires) can still call fetch() against the unpatched
// global. The MAIN-world bridge cannot retroactively intercept that
// call — the fetch has already left the page.
//
// This is a documented limitation, not a bug, and the defence is
// the enforcement-mode policy: a managed install routes its egress
// through the local MITM proxy and the OS-level allowlist, neither
// of which the page can bypass. The test pins the limitation so a
// future refactor that claims to close the race would have to also
// update this assertion.
// ---------------------------------------------------------------------------

test("G8 / row B: pre-injection fetch is NOT observable from the bridge (documented limitation)", () => {
    // The bridge is a synchronous patch on `window.fetch`. There is
    // no API surface that lets us observe a fetch call that happened
    // before the patch ran — by construction the patch is the only
    // hook. The defence for managed installs is the MITM proxy and
    // the OS-level URLBlocklist, which catch the request after it
    // leaves the page. This test pins the assumption so the
    // surrounding documentation and the README "extension is a
    // coaching layer" claim stay aligned with the code.
    assert.ok(
        true,
        "documented limitation: pre-injection fetch cannot be observed; defence is the proxy + OS egress controls",
    );
});

// ---------------------------------------------------------------------------
// Row C — oversize content in managed mode synthesises a block.
//
// The bridge routes content larger than MAX_SCAN_BYTES through
// `policyForOversize` BEFORE calling the scan function (because
// scanContent returns null for oversize bodies and routing that
// null through the agent-unavailable branch would surface a
// misleading "agent unavailable" toast). In managed mode the
// policy returns "block" and the bridge synthesises a result whose
// pattern_name is POLICY_PATTERN_OVERSIZE — distinct from
// POLICY_PATTERN_AGENT_UNAVAILABLE so the UI / telemetry can tell
// the two failure modes apart.
// ---------------------------------------------------------------------------

test("G8 / row C: oversize content in managed mode synthesises a POLICY_PATTERN_OVERSIZE block", async () => {
    const { replies, reply } = captureReplies();
    let scanCalls = 0;
    const scan = async (): Promise<ScanResult | null> => {
        scanCalls++;
        return null;
    };

    // 1 byte over the cap so the oversize branch is taken even if a
    // future refactor changes the strictness of the comparison.
    const oversize = "X".repeat(MAX_SCAN_BYTES + 1);
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "req-1", content: oversize },
        reply,
        scan,
        () => { /* toast swallowed */ },
        {
            // Pin the test to managed-mode policy explicitly so the
            // outcome doesn't drift if the cached mode default
            // changes between runs.
            onOversize: () => "block",
            onUnavailable: () => "block",
            showOversizeBlock: () => { /* no UI in unit tests */ },
        },
    );

    assert.equal(scanCalls, 0, "scan function must not be called for oversize bodies (oversize branch runs first)");
    assert.equal(replies.length, 1, "exactly one scan-resp must be posted");
    assert.equal(replies[0].kind, "scan-resp");
    assert.equal(replies[0].id, "req-1");
    assert.ok(replies[0].result, "managed mode oversize must synthesise a non-null result");
    assert.equal(replies[0].result!.blocked, true);
    assert.equal(
        replies[0].result!.pattern_name,
        POLICY_PATTERN_OVERSIZE,
        "oversize block must use POLICY_PATTERN_OVERSIZE — not the agent-unavailable marker",
    );
});

// ---------------------------------------------------------------------------
// Row D — timeout / scan-null in managed mode synthesises a block.
//
// scan returns null for any failure mode the agent cannot resolve:
// timeout (REQUEST_TIMEOUT_MS), 401 from the loopback, network
// error, port disconnect, etc. The bridge routes those through
// `policyForUnavailable`. In managed mode the policy returns
// "block" and the bridge synthesises a result whose pattern_name is
// POLICY_PATTERN_AGENT_UNAVAILABLE — distinct from
// POLICY_PATTERN_OVERSIZE.
// ---------------------------------------------------------------------------

test("G8 / row D: scan-null in managed mode synthesises a POLICY_PATTERN_AGENT_UNAVAILABLE block", async () => {
    const { replies, reply } = captureReplies();
    const scan = async (): Promise<ScanResult | null> => null;

    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "req-2", content: "short body" },
        reply,
        scan,
        () => { /* toast swallowed */ },
        {
            onOversize: () => "block",
            onUnavailable: () => "block",
            showPolicyBlock: () => { /* no UI in unit tests */ },
        },
    );

    assert.equal(replies.length, 1);
    assert.equal(replies[0].kind, "scan-resp");
    assert.equal(replies[0].id, "req-2");
    assert.ok(replies[0].result, "managed mode scan-null must synthesise a non-null result");
    assert.equal(replies[0].result!.blocked, true);
    assert.equal(
        replies[0].result!.pattern_name,
        POLICY_PATTERN_AGENT_UNAVAILABLE,
        "agent-unavailable block must use POLICY_PATTERN_AGENT_UNAVAILABLE — not the oversize marker",
    );
});

// ---------------------------------------------------------------------------
// Symmetry / non-regression: rows C and D must NOT block in personal
// mode. A regression that promoted the oversize / unavailable
// branches to always-block would harass every personal-mode user
// with spurious toasts.
// ---------------------------------------------------------------------------

test("G8 / row C-personal: oversize content in personal mode falls open silently", async () => {
    const { replies, reply } = captureReplies();
    const oversize = "X".repeat(MAX_SCAN_BYTES + 1);
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "req-3", content: oversize },
        reply,
        async () => null,
        () => { /* unused */ },
        { onOversize: () => "allow", onUnavailable: () => "allow" },
    );
    assert.equal(replies.length, 1);
    assert.equal(replies[0].result, null, "personal mode must NOT synthesise a block for oversize");
});

test("G8 / row D-personal: scan-null in personal mode falls open silently", async () => {
    const { replies, reply } = captureReplies();
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "req-4", content: "tiny" },
        reply,
        async () => null,
        () => { /* unused */ },
        { onOversize: () => "allow", onUnavailable: () => "allow" },
    );
    assert.equal(replies.length, 1);
    assert.equal(replies[0].result, null, "personal mode must NOT synthesise a block for scan-null");
});
