// Adversarial bridge tests for the MAIN ↔ ISO postMessage relay
// (Phase 7 / C3).
//
// The fetch / XHR interceptor lives in two halves: a MAIN-world
// bridge (`main-world-network.ts`) that patches `window.fetch` and
// `XMLHttpRequest.prototype.send` in the page's own world, and an
// isolated-world relay (`network-interceptor.ts`) that owns the
// runtime port to the background service worker. The two halves
// communicate via `window.postMessage`. That channel is observable
// from page-world script: anything running in the page's JS context
// can read every scan-req body and forge messages on the same
// channel.
//
// This file pins the threat model of the bridge: which forgery
// shapes the relay correctly rejects, and — critically — which
// shapes the relay CANNOT reject from inside the content-script
// layer. The "cannot reject" cells are not bugs: they are the
// reason the C1 HMAC bridge (PR #26) covers the
// extension ↔ agent Native Messaging hop, and the A2 per-install
// bearer token (PR #18) covers the agent's HTTP loopback. The
// bridge channel itself is page-observable by design.
//
// Each test below is one row of an adversarial table. The columns
// are: hostile shape, the relay's observed behaviour, and the
// independent defence that handles the residual risk. Future
// regressions in the relay's input handling should flip exactly one
// of these rows.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ as iso } from "../network-interceptor.js";
import { __test__ as mainWorld } from "../main-world-network.js";
import type { ScanResult } from "../../shared.js";

const { handleBridgeMessage, isScanRequest, BRIDGE_SOURCE, ISO_SOURCE } = iso;
const { requestScan } = mainWorld;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function okScan(): ScanResult {
    return { blocked: false, pattern_name: "", score: 0 };
}

function blockedScan(name = "aws_key"): ScanResult {
    return { blocked: true, pattern_name: name, score: 9 };
}

interface BridgeReply {
    source: string;
    kind: string;
    id: string;
    result: ScanResult | null;
}

/** Capture every reply the relay tries to post. The `reply` field
 *  has a structural signature matching the `ReplyFn` type that
 *  `handleBridgeMessage` expects — using the structural shape lets
 *  these tests live next to (rather than inside) the module under
 *  test without exporting an internal type. */
function makeReplyCapture(): {
    replies: BridgeReply[];
    reply: (msg: BridgeReply) => void;
} {
    const replies: BridgeReply[] = [];
    return {
        replies,
        reply: (msg) => {
            replies.push(msg);
        },
    };
}

// ---------------------------------------------------------------------------
// Row 1 — isScanRequest type guard rejects mistyped / missing fields.
// ---------------------------------------------------------------------------

test("C3 / row 1: isScanRequest rejects every shape that isn't a well-typed scan-req", () => {
    // Non-object inputs.
    assert.equal(isScanRequest(null), false);
    assert.equal(isScanRequest(undefined), false);
    assert.equal(isScanRequest("scan-req"), false);
    assert.equal(isScanRequest(42), false);

    // Wrong source tag (a different extension on the same page).
    assert.equal(
        isScanRequest({ source: "some-other-extension", kind: "scan-req", id: "x", content: "y" }),
        false,
    );

    // Right source but wrong kind (a stale scan-resp echoed back).
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-resp", id: "x", content: "y" }),
        false,
    );

    // Right source + kind but id is not a string (number / object).
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: 1, content: "y" }),
        false,
    );
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: {}, content: "y" }),
        false,
    );

    // Right source + kind + id but content is not a string.
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: "x", content: 0 }),
        false,
    );
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: "x", content: null }),
        false,
    );
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: "x" }),
        false,
    );

    // Well-typed shape accepted.
    assert.equal(
        isScanRequest({ source: BRIDGE_SOURCE, kind: "scan-req", id: "x", content: "y" }),
        true,
    );
});

// ---------------------------------------------------------------------------
// Row 2 — isScanRequest is permissive about extra fields (additive shape).
// ---------------------------------------------------------------------------

test("C3 / row 2: isScanRequest accepts extra unknown fields (forward-compat)", () => {
    // A future version of the bridge may add fields (e.g. a request
    // hint or a tracing id). The relay must accept the new shape so
    // a phased rollout doesn't deadlock the page on a version skew.
    // The trade-off is documented: callers MUST NOT lean on the
    // absence of unknown fields for security decisions.
    assert.equal(
        isScanRequest({
            source: BRIDGE_SOURCE,
            kind: "scan-req",
            id: "x",
            content: "y",
            __forged_admin_flag: true,
            __extra_route_hint: "exfil",
        }),
        true,
    );
});

// ---------------------------------------------------------------------------
// Row 3 — handleBridgeMessage ignores junk that fails the type guard.
// ---------------------------------------------------------------------------

test("C3 / row 3: handleBridgeMessage is a no-op on every shape isScanRequest rejects", async () => {
    const { replies, reply } = makeReplyCapture();

    let scanCalls = 0;
    const scan = async (): Promise<ScanResult | null> => {
        scanCalls++;
        return okScan();
    };

    // Mistyped / missing-field shapes must NEVER reach the scan
    // function and MUST NOT trigger a reply (the relay must not
    // leak the existence of the extension to a noise sender).
    await handleBridgeMessage(null, reply, scan);
    await handleBridgeMessage("garbage", reply, scan);
    await handleBridgeMessage(
        { source: "other-extension", kind: "scan-req", id: "x", content: "y" },
        reply,
        scan,
    );
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: 1, content: "y" },
        reply,
        scan,
    );

    assert.equal(scanCalls, 0, "scan must not run for any guard-rejected shape");
    assert.deepEqual(replies, [], "relay must not emit any reply for guard-rejected shapes");
});

// ---------------------------------------------------------------------------
// Row 4 — relay processes well-formed page-forged scan-req (documented).
// ---------------------------------------------------------------------------

test("C3 / row 4: relay processes any well-formed scan-req, including page-forged ones (DOCUMENTED LIMITATION)", async () => {
    // THREAT MODEL PIN. The MAIN ↔ ISO bridge runs over
    // `window.postMessage`, which is page-observable. Any
    // page-world script can synthesise a well-formed scan-req
    // message and ask the relay to scan an attacker-controlled
    // body. The relay has no cryptographic way to distinguish a
    // forgery from a legitimate scan-req — both arrive with
    // `ev.source === window` (or null in some jsdom-shaped
    // contexts), `event.origin` reflects the page itself, and
    // there is no shared secret on this hop.
    //
    // This is NOT a defect. The bridge is just a queue between two
    // halves of the content script; it has no authority of its
    // own. The defences that matter live on the next two hops:
    //   - extension ↔ agent NM frame: HMAC seal (PR #26 / C1)
    //   - extension ↔ agent HTTP loopback: bearer token (PR #18 / A2)
    // Both hops authenticate the EXTENSION as the caller, not the
    // page, so a forged scan-req that reaches the agent still
    // looks like an extension-originated scan.
    //
    // A forged scan that returns "blocked: true" can also be used
    // by hostile page code to trigger our toast on demand. That is
    // a UX nuisance, not a privacy leak — the toast contents are
    // pattern names, which the agent's rule files already treat
    // as low-sensitivity strings (see SECURITY_RULES.md).
    //
    // This test pins the behaviour so a future "harden the bridge"
    // refactor doesn't silently start rejecting forged messages —
    // doing so would break the bridge's contract with the page-
    // world half (which also runs in the page's world and is
    // indistinguishable from forged code at the message layer).

    let scanCalls = 0;
    let lastContent = "";
    const scan = async (c: string): Promise<ScanResult | null> => {
        scanCalls++;
        lastContent = c;
        return blockedScan("aws_key");
    };
    const { replies, reply } = makeReplyCapture();

    // A page-world script crafts a well-formed scan-req. The relay
    // has no way to know this didn't come from our own bridge.
    await handleBridgeMessage(
        {
            source: BRIDGE_SOURCE,
            kind: "scan-req",
            id: "page-forged-id",
            content: "AKIA" + "A".repeat(80),
        },
        reply,
        scan,
    );

    assert.equal(scanCalls, 1, "forged scan-req still runs the scan");
    assert.equal(lastContent.startsWith("AKIA"), true);
    assert.equal(replies.length, 1, "forged scan-req still receives a reply");
    assert.equal(replies[0]?.id, "page-forged-id");
});

// ---------------------------------------------------------------------------
// Row 5 — requestScan rejects scan-resp with an unknown id.
// ---------------------------------------------------------------------------

test("C3 / row 5: requestScan ignores scan-resp messages whose id doesn't match the request", async () => {
    // The MAIN-world bridge tracks every outstanding request by a
    // freshly-generated id (see `genId` in main-world-network.ts).
    // A page-world script can synthesise scan-resp messages with
    // any id, but unless it guesses the in-flight id correctly the
    // bridge's listener simply doesn't resolve. The TOCTOU window
    // (Row 6) is the only path that survives this defence.

    type MessageListener = (ev: MessageEvent) => void;
    const listeners: MessageListener[] = [];
    const win = {
        addEventListener(_type: "message", fn: MessageListener) {
            listeners.push(fn);
        },
        removeEventListener(_type: "message", fn: MessageListener) {
            const i = listeners.indexOf(fn);
            if (i >= 0) listeners.splice(i, 1);
        },
        postMessage() {
            // Inject a forged scan-resp with a clearly wrong id on
            // the next microtask. The genuine relay never replies
            // here — only our forgery fires.
            queueMicrotask(() => {
                const reply = {
                    source: ISO_SOURCE,
                    kind: "scan-resp",
                    id: "id-the-attacker-guessed-wrong",
                    result: { blocked: true, pattern_name: "forged", score: 99 } as ScanResult,
                };
                for (const fn of [...listeners]) fn({ data: reply } as MessageEvent);
            });
        },
    };

    // 25 ms is well above the microtask delivery time but well
    // below the 1500 ms production timeout, so the test stays
    // fast. The forged reply gets delivered and discarded; the
    // genuine reply never comes, so requestScan eventually times
    // out and resolves null (fall-open).
    const r = await requestScan(win, "X".repeat(80), 25);
    assert.equal(r, null, "wrong-id forgery must not resolve the in-flight request");
});

// ---------------------------------------------------------------------------
// Row 6 — TOCTOU: matching-id forgery wins the race (documented).
// ---------------------------------------------------------------------------

test("C3 / row 6: page-forged scan-resp with the in-flight id wins the race (DOCUMENTED LIMITATION)", async () => {
    // THREAT MODEL PIN. The bridge ↔ relay channel has no shared
    // secret. A page-world script that observes a scan-req can
    // read its `id` field, immediately post a scan-resp with the
    // same id and a `result: null` (or `blocked: false`), and the
    // bridge will resolve with that forgery — short-circuiting the
    // real scan and allowing the request through.
    //
    // The MAIN-world bridge cannot defend against this without
    // co-operative validation from the relay, and the relay cannot
    // sign its reply with a secret that the page-world bridge can
    // verify (any secret the bridge knows is by definition
    // page-readable). The defence is on the NEXT hop:
    //   - if the page forges a "result: null" to skip the scan,
    //     the request still has to leave the page through
    //     fetch / XHR, where the patched implementation has
    //     already-by-design called the bridge before the network
    //     send. If the page can also patch fetch / XHR back to
    //     the originals, then it is already running in the page's
    //     world and can exfiltrate directly without going through
    //     our hooks at all — at which point there is nothing to
    //     defend.
    //   - if the page forges a "blocked: true" to harass the user
    //     with a toast, that is a UX nuisance, not an exfil. The
    //     contents of the toast are pattern names, not private
    //     data.
    //
    // This test pins the behaviour. A future refactor that
    // accidentally hardens this race (e.g. by adding a nonce that
    // only the relay knows) would also break the legitimate
    // bridge ↔ relay handshake, because the bridge has no way to
    // obtain that nonce out-of-band.

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
                // The page-world attacker sees the scan-req fly by
                // (it shares the window) and posts back a forged
                // scan-resp with the same id. This races the real
                // relay (which the test doesn't even stand up).
                queueMicrotask(() => {
                    const reply = {
                        source: ISO_SOURCE,
                        kind: "scan-resp",
                        id: observedReqId!,
                        result: null,
                    };
                    for (const fn of [...listeners]) fn({ data: reply } as MessageEvent);
                });
            }
        },
    };

    const r = await requestScan(win, "AKIA" + "X".repeat(80), 1000);
    assert.equal(
        r,
        null,
        "matching-id forgery resolves the request (documented limitation; defence is on the next hop)",
    );
    assert.notEqual(observedReqId, null, "scan-req id must have been observed by the forger");
});

// ---------------------------------------------------------------------------
// Row 7 — relay never replies to a scan-resp echoed back at it.
// ---------------------------------------------------------------------------

test("C3 / row 7: relay does not respond to its own scan-resp echoed back as a scan-req", async () => {
    // The page can copy a scan-resp message (which it sees on the
    // bus) and re-post it with `kind: scan-req` to try to convince
    // the relay to recursively scan its own output. The relay's
    // type guard checks `kind === "scan-req"`, so the recursive
    // shape is rejected at the input layer — provided the source
    // tag is still BRIDGE_SOURCE. A relay-tagged source (ISO_SOURCE)
    // is rejected purely on source mismatch.
    const { replies, reply } = makeReplyCapture();
    let scanCalls = 0;
    const scan = async (): Promise<ScanResult | null> => {
        scanCalls++;
        return okScan();
    };

    // Shape A: kind=scan-resp wrapped in BRIDGE_SOURCE.
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-resp", id: "x", content: "anything" },
        reply,
        scan,
    );
    // Shape B: kind=scan-req but with ISO_SOURCE as source.
    await handleBridgeMessage(
        { source: ISO_SOURCE, kind: "scan-req", id: "x", content: "anything" },
        reply,
        scan,
    );

    assert.equal(scanCalls, 0, "kind-confused or source-confused messages must not trigger a scan");
    assert.deepEqual(replies, [], "relay must not echo a reply for kind/source-confused messages");
});

// ---------------------------------------------------------------------------
// Row 8 — reentrancy: concurrent handleBridgeMessage calls do not leak state.
// ---------------------------------------------------------------------------

test("C3 / row 8: concurrent handleBridgeMessage calls keep their replies separate", async () => {
    // The browser can deliver overlapping `message` events to our
    // capture-phase listener (e.g. one fired from a microtask, the
    // next from a macrotask). Each invocation of handleBridgeMessage
    // is its own async closure and must reply with the id from
    // its OWN incoming message — never with the id from a sibling
    // invocation. The fact that the function is async (it awaits
    // scanContent) means an interleaving is observable.

    const { replies, reply } = makeReplyCapture();

    // The scan function records the order it was called in and
    // resolves in reverse, so the relay's "await scan(content)"
    // for message A only completes after the relay has already
    // entered the await for message B. If the two invocations
    // were sharing any module-level state (e.g. a captured `id`
    // outside the closure) we'd see one of the replies reference
    // the wrong id.
    let order = 0;
    const queue: Array<() => void> = [];
    const scan = (content: string): Promise<ScanResult | null> => {
        order++;
        return new Promise((resolve) => {
            queue.push(() => resolve({ blocked: false, pattern_name: content, score: 0 }));
        });
    };

    const a = handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "A", content: "alpha" + "X".repeat(80) },
        reply,
        scan,
    );
    const b = handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "B", content: "beta" + "X".repeat(80) },
        reply,
        scan,
    );

    // Resolve B first, then A, to interleave.
    await new Promise<void>((r) => setTimeout(r, 0));
    queue[1]?.();
    queue[0]?.();
    await Promise.all([a, b]);

    assert.equal(order, 2);
    assert.equal(replies.length, 2);
    const replyA = replies.find((r) => r.id === "A");
    const replyB = replies.find((r) => r.id === "B");
    assert.ok(replyA, "reply for message A must be present");
    assert.ok(replyB, "reply for message B must be present");
    // The pattern_name in each reply was set to the content the
    // scanner saw, so any cross-talk would manifest as A's reply
    // carrying B's content.
    const resultA = replyA["result"] as ScanResult;
    const resultB = replyB["result"] as ScanResult;
    assert.ok(resultA.pattern_name.startsWith("alpha"), "reply A must reference its own content");
    assert.ok(resultB.pattern_name.startsWith("beta"), "reply B must reference its own content");
});

// ---------------------------------------------------------------------------
// Row 9 — relay does not crash on a scan function that throws.
// ---------------------------------------------------------------------------

test("C3 / row 9: a throwing scan implementation collapses to a null verdict, not an unhandled rejection", async () => {
    // A page-shaped condition (chrome.runtime suddenly gone,
    // service worker eviction, agent crash mid-call) is observed
    // by scan-client as a rejected promise. The relay must catch
    // and surface it as `result: null` (which the bridge then
    // routes through `policyForUnavailable` in its caller). An
    // unhandled rejection here would crash the content script and
    // silently disable every interceptor on the page until the
    // next navigation — a much worse failure mode than fall-open.
    const { replies, reply } = makeReplyCapture();
    const scan = async (): Promise<ScanResult | null> => {
        throw new Error("simulated chrome.runtime collapse");
    };

    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "x", content: "Y".repeat(80) },
        reply,
        scan,
    );

    assert.equal(replies.length, 1);
    assert.equal(replies[0]?.id, "x");
    // null verdict in personal mode = fall open. The relay never
    // re-throws.
    assert.equal(replies[0]?.result, null);
});

// ---------------------------------------------------------------------------
// Row 10 — relay scrubs nothing: it doesn't trust `data.kind` semantics,
//          but it also doesn't sanitise the content field itself.
// ---------------------------------------------------------------------------

test("C3 / row 10: relay forwards the content field as-is to the scan function (no in-bridge sanitisation)", async () => {
    // The scan function (and ultimately the agent) is the
    // canonical content sink. The relay must not silently strip
    // null bytes, decode hex, normalise whitespace, etc. — every
    // transform here is an opportunity to introduce a parser
    // differential between the bridge and the agent, which is
    // exactly the kind of bug A3 / signed-rules and C1 / HMAC are
    // there to mitigate. This row pins the transparency contract.
    let observed: string | null = null;
    const scan = async (c: string): Promise<ScanResult | null> => {
        observed = c;
        return okScan();
    };
    const { reply } = makeReplyCapture();

    const malformed = "AKIA\x00\x01\x02\xff" + "X".repeat(80) + "\u0000";
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "x", content: malformed },
        reply,
        scan,
    );

    assert.equal(observed, malformed, "relay must forward the content byte-for-byte");
});
