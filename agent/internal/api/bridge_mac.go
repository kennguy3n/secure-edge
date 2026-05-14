package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Bridge MAC (work item C1).
//
// Every non-hello frame on the Native Messaging bridge carries an
// HMAC-SHA256 in the `mac` field. The MAC is keyed by the per-install
// API capability token (work item A2) and includes a per-connection
// nonce so a recorded reply from an earlier connection cannot be
// replayed into a later one.
//
// Hello messages are deliberately NOT MAC'd. The hello reply is the
// channel that issues the nonce in the first place — there is no
// shared state to authenticate against before it has been delivered.
// This is a Trust-On-First-Use bootstrap, identical in spirit to how
// the api-token bootstrap works on the HTTP fallback (PR #18). The
// `helloIssued` per-connection guard below bounds the TOFU window to
// a single hello per `connectNative` call so an attacker cannot
// re-issue hello mid-stream and have both sides agree on a forged
// nonce.
//
// The MAC input is a length-prefixed binary concatenation rather
// than a JSON canonicalisation. The extension side reproduces this
// byte-identical layout in TypeScript so we don't have to worry
// about cross-runtime JSON ordering / unicode-escape divergence.

// bridgeNonceLen is the byte length of the per-connection bridge
// nonce. 16 bytes (128 bits) is enough that two simultaneous
// connections from the same extension have a negligible collision
// probability, while being short enough to fit comfortably in a JSON
// envelope.
const bridgeNonceLen = 16

// Wire tags for the direction byte in the MAC input. Distinct tags
// prevent a captured request MAC from being replayed back as a
// response MAC (or vice versa) within the same connection.
const (
	bridgeMACDirRequest  byte = 0x01
	bridgeMACDirResponse byte = 0x02
)

// generateBridgeNonce returns a fresh per-connection nonce, encoded
// as a lowercase hex string. The hex form is what travels in the
// `bridge_nonce` field of the hello reply; the binary form (decoded
// once by both sides) is what feeds into the HMAC input.
func generateBridgeNonce() (string, error) {
	buf := make([]byte, bridgeNonceLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("bridge nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// computeRequestMAC returns the hex-encoded HMAC-SHA256 for a
// request frame. nonceHex must be the value the agent sent on the
// hello reply for this connection; secret is the per-install API
// token (re-used as the HMAC key — see plan PR6, choice Q1).
//
// The MAC covers: nonce || dir-byte || LE32(id) || LE32(len(kind))
// || kind || LE32(len(content)) || content. The kind+content
// length prefixes mean a request that swaps kind="hello" for
// kind="scan" (or vice versa) produces a different MAC even when
// content is empty, so an attacker cannot trivially re-tag a frame.
func computeRequestMAC(secret, nonceHex string, id int, kind, content string) (string, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("bridge mac: decode nonce: %w", err)
	}
	if len(nonce) == 0 {
		return "", fmt.Errorf("bridge mac: empty nonce")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(nonce)
	mac.Write([]byte{bridgeMACDirRequest})
	writeU32(mac, uint32(id))
	writeLenPrefixedString(mac, kind)
	writeLenPrefixedString(mac, content)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// computeResponseMAC returns the hex-encoded HMAC-SHA256 for a
// response frame. blocked is the bridge-visible decision bit
// extracted from Result.Blocked (or 0xff when Result is nil — e.g.
// an error reply, where the bit is irrelevant but must still be
// fixed so the MAC input is well-defined).
//
// Pattern names, scores, and other diagnostic fields are NOT
// included in the MAC input. The bridge only authenticates the
// security-relevant decision bit and the error string; an attacker
// who flips Result.PatternName from "aws_access_key_id" to
// "github_pat" without changing Result.Blocked gains nothing
// (the extension's enforcement gate keys only on Blocked), and
// constraining the MAC to those fields keeps the canonicalisation
// trivial to mirror byte-identically in the TypeScript extension.
func computeResponseMAC(secret, nonceHex string, id int, kind string, blockedByte byte, apiToken, errMsg string) (string, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", fmt.Errorf("bridge mac: decode nonce: %w", err)
	}
	if len(nonce) == 0 {
		return "", fmt.Errorf("bridge mac: empty nonce")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(nonce)
	mac.Write([]byte{bridgeMACDirResponse})
	writeU32(mac, uint32(id))
	writeLenPrefixedString(mac, kind)
	mac.Write([]byte{blockedByte})
	// apiToken is only non-empty on hello replies, but the field
	// is part of the MAC input on every response so an attacker
	// cannot strip a forged api_token onto a scan reply and have
	// the MAC still verify. Empty string on non-hello replies
	// canonicalises to LE32(0) — same length-prefix discipline.
	writeLenPrefixedString(mac, apiToken)
	writeLenPrefixedString(mac, errMsg)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// verifyRequestMAC is a constant-time comparison wrapper around
// computeRequestMAC. Returns nil on a valid MAC, an error
// otherwise. The error string never echoes the expected MAC.
func verifyRequestMAC(secret, nonceHex string, id int, kind, content, gotMAC string) error {
	want, err := computeRequestMAC(secret, nonceHex, id, kind, content)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(want), []byte(gotMAC)) {
		return fmt.Errorf("bridge mac: request MAC mismatch")
	}
	return nil
}

// writeU32 appends a little-endian uint32 to the running HMAC. The
// TypeScript mirror uses DataView.setUint32(offset, value, true) to
// produce the same four bytes.
func writeU32(w interface {
	Write([]byte) (int, error)
}, v uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	_, _ = w.Write(buf[:])
}

// writeLenPrefixedString writes LE32(len(s)) followed by the raw
// UTF-8 bytes of s. Empty strings serialise to four zero bytes.
func writeLenPrefixedString(w interface {
	Write([]byte) (int, error)
}, s string) {
	writeU32(w, uint32(len(s)))
	_, _ = w.Write([]byte(s))
}
