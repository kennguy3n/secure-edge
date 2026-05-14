// Extension-side counterpart to agent/internal/api/bridge_mac.go.
//
// Phase 7 work item C1 ("HMAC bridge messages"): every non-hello
// frame on the native-messaging bridge is signed with HMAC-SHA256
// using the per-install api_token as the shared secret and a
// per-connection nonce minted by the agent in the hello reply.
//
// Wire format (must match the Go side byte-for-byte):
//
//     hmac_input = nonce_bytes
//                || direction_byte             (1 byte)
//                || id_le32                    (4 bytes, little-endian)
//                || len_prefix(kind)           (4-byte LE32 + bytes)
//                || len_prefix(content)        (4-byte LE32 + bytes)
//                                              (for requests)
//                                              -- OR --
//                || blocked_byte               (1 byte: 0x00/0x01/0xff)
//                || len_prefix(api_token)      (4-byte LE32 + bytes)
//                || len_prefix(error)          (4-byte LE32 + bytes)
//                                              (for responses)
//
// direction_byte: 0x01 for extension->agent requests, 0x02 for
// agent->extension responses. The direction byte exists so a captured
// request MAC cannot be replayed as a response MAC for the same
// (id, kind) tuple.
//
// All output MACs are lower-case hex-encoded so a round-trip through
// JSON.stringify preserves them exactly.

const utf8 = new TextEncoder();

/** Byte tag for a request frame. Must match bridgeMACDirRequest in
 *  agent/internal/api/bridge_mac.go. */
export const DIRECTION_REQUEST = 0x01;
/** Byte tag for a response frame. Must match bridgeMACDirResponse in
 *  agent/internal/api/bridge_mac.go. */
export const DIRECTION_RESPONSE = 0x02;

/** Decoded nonce length in bytes. The agent generates a 16-byte
 *  nonce per connection and surfaces it as 32-char lowercase hex. */
export const BRIDGE_NONCE_LEN = 16;

/** Import the per-install api_token as an HMAC-SHA256 signing key.
 *  The token is UTF-8-encoded and used as-is (no derivation) to
 *  match the agent's `hmac.New(sha256.New, []byte(secret))` call. */
export async function importBridgeKey(secret: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        "raw",
        utf8.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
}

/** Parse the hex nonce returned in the hello reply. Returns null
 *  for empty, malformed, or wrong-length input so callers can
 *  cleanly short-circuit MAC computation. */
export function decodeNonceHex(hex: string): Uint8Array | null {
    if (!hex || hex.length !== BRIDGE_NONCE_LEN * 2) return null;
    if (!/^[0-9a-f]+$/.test(hex)) return null;
    const out = new Uint8Array(BRIDGE_NONCE_LEN);
    for (let i = 0; i < BRIDGE_NONCE_LEN; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/** Concatenate multiple Uint8Arrays into a single allocation.
 *  Used to build the HMAC input — keeping it a single allocation
 *  avoids the cost of Web Crypto's `.update()` API which doesn't
 *  exist (subtle.sign is one-shot). */
function concat(parts: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p, off);
        off += p.length;
    }
    return out;
}

/** Emit a 4-byte little-endian length prefix followed by the
 *  UTF-8 encoding of `s`. Mirrors the Go writeLenPrefixedString. */
function lenPrefixed(s: string): Uint8Array {
    const body = utf8.encode(s);
    const out = new Uint8Array(4 + body.length);
    new DataView(out.buffer).setUint32(0, body.length, true /* little-endian */);
    out.set(body, 4);
    return out;
}

/** Emit a 4-byte little-endian uint32 for the request id. */
function u32(n: number): Uint8Array {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, n >>> 0, true);
    return out;
}

/** Hex-encode a buffer as lowercase. crypto.subtle.sign returns
 *  an ArrayBuffer so we go through Uint8Array first. */
function toHex(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
}

/** Compute the request-direction HMAC for a scan frame. */
export async function computeRequestMAC(
    key: CryptoKey,
    nonce: Uint8Array,
    id: number,
    kind: string,
    content: string,
): Promise<string> {
    const input = concat([
        nonce,
        new Uint8Array([DIRECTION_REQUEST]),
        u32(id),
        lenPrefixed(kind),
        lenPrefixed(content),
    ]);
    const sig = await crypto.subtle.sign("HMAC", key, input as BufferSource);
    return toHex(sig);
}

/** Compute the response-direction HMAC for a reply frame. Used by
 *  the extension to verify what the agent claims. */
export async function computeResponseMAC(
    key: CryptoKey,
    nonce: Uint8Array,
    id: number,
    kind: string,
    blocked: 0x00 | 0x01 | 0xff,
    apiToken: string,
    error: string,
): Promise<string> {
    const input = concat([
        nonce,
        new Uint8Array([DIRECTION_RESPONSE]),
        u32(id),
        lenPrefixed(kind),
        new Uint8Array([blocked]),
        lenPrefixed(apiToken),
        lenPrefixed(error),
    ]);
    const sig = await crypto.subtle.sign("HMAC", key, input as BufferSource);
    return toHex(sig);
}

/** Constant-time hex string equality. Web Crypto verify() is only
 *  available for asymmetric keys; for HMAC we re-sign + compare.
 *  This guard against length-leak / early-exit timing matches what
 *  Go's hmac.Equal does. */
export function constantTimeEqHex(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}
