package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// MaxNativeMessageBytes caps both incoming and outgoing Native Messaging
// payloads. Chrome enforces a 1 MiB limit on messages from the extension
// to the host; we mirror that so we never silently truncate.
const MaxNativeMessageBytes uint32 = 1 * 1024 * 1024

// NativeMessageRequest is the wire shape received from a connected
// Chrome extension on stdin. The id is echoed back so the extension
// can correlate concurrent requests. MAC, when non-empty, is the
// hex-encoded HMAC-SHA256 the extension computed over the rest of
// the fields (work item C1) — see bridge_mac.go for the exact input
// layout. The agent checks the MAC on every non-hello request; the
// hello request itself is unauthenticated because the shared secret
// + nonce are bootstrapped by the hello reply (TOFU).
type NativeMessageRequest struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
	MAC     string `json:"mac,omitempty"`
}

// NativeMessageResponse is the wire shape returned on stdout.
// Result, APIToken, and Error are mutually exclusive per response.
// APIToken is populated on a successful "hello" reply so the
// extension can cache the per-install token for its HTTP fallback
// path (work item A2). BridgeNonce, when non-empty, is the
// per-connection nonce the agent issues on its hello reply so the
// extension can seed the MAC computation for every subsequent
// request (work item C1). MAC, when non-empty, is the hex-encoded
// HMAC-SHA256 over the rest of the response — see bridge_mac.go.
// The hello reply itself is unauthenticated for TOFU reasons; every
// scan reply IS MAC'd whenever the connection has a bridge secret.
type NativeMessageResponse struct {
	ID          int             `json:"id"`
	Result      *dlp.ScanResult `json:"result,omitempty"`
	APIToken    string          `json:"api_token,omitempty"`
	BridgeNonce string          `json:"bridge_nonce,omitempty"`
	Error       string          `json:"error,omitempty"`
	MAC         string          `json:"mac,omitempty"`
}

// NativeMessagingOptions carries optional dependencies the native
// host handler may need. Adding fields to this struct is a backwards-
// compatible change for callers, which is the reason the original
// positional-argument ServeNativeMessaging() now delegates to
// ServeNativeMessagingWithOptions().
type NativeMessagingOptions struct {
	// APIToken, when non-empty, is returned to the extension on a
	// successful "hello" message so the extension can authenticate
	// its loopback HTTP fallback. When empty (the legacy posture or
	// a deployment with api_token_path unset) the "hello" handler
	// still writes a successful reply, but the api_token field is
	// stripped from the JSON envelope by `omitempty`. The extension
	// treats a missing api_token in the hello reply as "no token
	// configured" and skips the Authorization header on every
	// subsequent HTTP fallback request. There is no error reply
	// in that case; the legacy origin-only authorisation still
	// applies on the agent side.
	APIToken string

	// BridgeMACRequired controls the staged-rollout posture of the
	// Native Messaging bridge MAC (work item C1). When false
	// (default) a request that arrives without a `mac` field — or
	// with a `mac` that fails verification — is still served as
	// before, but a one-time-per-connection warning is logged to
	// stderr so operators can confirm clients have rolled to a C1
	// extension build before flipping enforcement on.
	//
	// When true (post-rollout) a missing or invalid MAC produces an
	// error reply ("bridge MAC required" / "bridge MAC mismatch")
	// and the scan does not run. Mirrors the staged-rollout posture
	// of APITokenRequired (PR #18, A2).
	//
	// The hello request is never MAC'd (TOFU bootstrap — see
	// bridge_mac.go) so this knob does not affect the api-token
	// handshake.
	BridgeMACRequired bool

	// LogStderr, when non-nil, overrides the default os.Stderr sink
	// for the lenient-mode bridge-MAC warning. Tests inject a
	// bytes.Buffer here to assert the warning text without
	// polluting the test runner's stderr. Production callers leave
	// it nil; nativemsg.go falls back to os.Stderr in that case.
	LogStderr io.Writer
}

// ServeNativeMessaging is a backwards-compatible shim that delegates
// to ServeNativeMessagingWithOptions with an empty options struct.
// New callers should prefer ServeNativeMessagingWithOptions so they
// can pass an APIToken; this shim exists so the existing test suite
// and any third-party embedders don't have to change at the same
// time as the agent main wiring.
func ServeNativeMessaging(ctx context.Context, scanner DLPScanner, statsStore *store.Store, in io.Reader, out io.Writer) error {
	return ServeNativeMessagingWithOptions(ctx, scanner, statsStore, NativeMessagingOptions{}, in, out)
}

// ServeNativeMessagingWithOptions reads length-prefixed JSON messages
// from in, dispatches scan / hello requests, and writes JSON responses
// to out. It returns when in is closed (io.EOF), ctx is cancelled, or
// a write fails. The function is intentionally synchronous: Chrome's
// Native Messaging protocol is a half-duplex stream and the agent
// invokes Scan() before reading the next request.
//
// statsStore, when non-nil, receives bumpDLPStats() calls after every
// successful scan so that the Status page's dlp_scans_total and
// dlp_blocks_total stay correct in NM mode. Pass nil in tests that
// don't care about counters; HTTP-only deployments are unaffected.
//
// opts.APIToken, when non-empty, is the value returned on a "hello"
// request. The extension caches it in chrome.storage.session and
// attaches it to its HTTP-fallback requests.
func ServeNativeMessagingWithOptions(ctx context.Context, scanner DLPScanner, statsStore *store.Store, opts NativeMessagingOptions, in io.Reader, out io.Writer) error {
	// Per-connection bridge-MAC state (work item C1). The nonce is
	// minted once per ServeNativeMessagingWithOptions invocation
	// (i.e. once per `connectNative` call from Chrome) and surfaced
	// in the hello reply. macSecret is the shared HMAC key — the
	// same per-install API token reused for the HTTP fallback (plan
	// PR6, choice Q1: "Option A — reuse api_token"). A blank token
	// short-circuits MAC verification entirely so a pre-A2
	// deployment that has not yet wired up api_token_path keeps
	// behaving exactly as it did before C1.
	bridgeNonce, err := generateBridgeNonce()
	if err != nil {
		return fmt.Errorf("native: nonce: %w", err)
	}
	macSecret := opts.APIToken
	macAvailable := macSecret != ""
	helloIssued := false
	helloLenientWarned := false
	lastSeenID := 0 // request ids must be strictly monotonic per connection.
	logSink := opts.LogStderr
	if logSink == nil {
		logSink = os.Stderr
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		raw, err := readNativeMessage(in, MaxNativeMessageBytes)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("native: read: %w", err)
		}

		var req NativeMessageRequest
		resp := NativeMessageResponse{}
		respKind := ""     // mirror request kind into the response MAC input
		skipMAC := false   // set when the response should NOT carry a MAC (parse-error / hello reply / no secret)
		if jerr := json.Unmarshal(raw, &req); jerr != nil {
			// Best-effort error reply when we can't even parse the
			// envelope. id is left at zero — the extension treats
			// id=0 as "unsolicited" and surfaces the error to the user.
			resp.Error = "invalid request JSON"
			skipMAC = true
		} else {
			resp.ID = req.ID
			respKind = req.Kind
			switch req.Kind {
			case "scan":
				// Monotonic-id check (C1 replay defence).
				// Drop frames whose id is not strictly greater
				// than every id we have already seen on this
				// connection. This catches an attacker who
				// replays a captured (blocked=false) reply
				// frame back at us mid-stream.
				if req.ID <= lastSeenID {
					resp.Error = "bridge id rollback"
					break
				}
				lastSeenID = req.ID

				// MAC verification (only when a secret is
				// available — pre-A2 deployments with no
				// api_token_path stay on the legacy posture).
				macOK := true
				if macAvailable {
					if verr := verifyRequestMAC(macSecret, bridgeNonce, req.ID, req.Kind, req.Content, req.MAC); verr != nil {
						macOK = false
					}
				}
				if !macOK {
					if opts.BridgeMACRequired {
						if req.MAC == "" {
							resp.Error = "bridge MAC required"
						} else {
							resp.Error = "bridge MAC mismatch"
						}
						break
					}
					// Lenient mode: log once per connection and
					// continue. Operators can monitor stderr to
					// confirm clients have moved to the C1 build
					// before flipping bridge_mac_required on.
					if !helloLenientWarned {
						helloLenientWarned = true
						why := "missing"
						if req.MAC != "" {
							why = "invalid"
						}
						fmt.Fprintf(logSink, "agent: bridge MAC %s on Native Messaging request (lenient mode); enforcement is OFF (bridge_mac_required=false). flip the knob once your extension build is using the MAC.\n", why)
					}
				}

				if scanner == nil {
					resp.Error = "DLP pipeline not configured"
				} else {
					r := scanner.Scan(ctx, req.Content)
					req.Content = "" // drop reference promptly.
					resp.Result = &r
					// Mirror the HTTP scan handler: anonymous
					// aggregate counters must move whichever
					// transport the extension picked. Errors
					// are intentionally swallowed — counter
					// hiccups must never break a scan reply.
					_ = bumpDLPStats(ctx, statsStore, r.Blocked)
				}
			case "hello":
				// A2 capability-token bootstrap: the extension
				// asks for the per-install token, caches it in
				// chrome.storage.session, and attaches it to
				// every HTTP fallback. When no token is wired
				// in we still reply 200-ish (no Error) so the
				// extension treats it as "no token configured"
				// rather than a protocol-level failure.
				//
				// C1: a hello is allowed once per connection.
				// Subsequent hello frames are rejected so an
				// attacker who manages to inject a second
				// hello mid-stream cannot re-bootstrap the
				// shared nonce.
				if helloIssued {
					resp.Error = "hello already issued"
					break
				}
				helloIssued = true
				resp.APIToken = opts.APIToken
				// Only surface the bridge nonce when there is
				// actually a secret to MAC against — pre-A2
				// deployments leave api_token_path empty and
				// would otherwise pin a nonce that no MAC can
				// verify against, confusing the extension's
				// rollout-readiness probe.
				if macAvailable {
					resp.BridgeNonce = bridgeNonce
				}
				// Hello reply is intentionally NOT MAC'd: the
				// extension has no nonce or secret to verify
				// against yet — the very reply it is reading
				// is what hands them over (TOFU). See plan
				// PR6 "Bootstrap (Trust On First Use)".
				skipMAC = true
			default:
				resp.Error = fmt.Sprintf("unknown kind: %q", req.Kind)
			}
		}

		// MAC the response when we have a secret AND we're not on
		// the deliberately-unauthenticated hello path AND we
		// didn't bail out before assigning a kind. The lower-level
		// JSON marshalling sets MAC explicitly so the omitempty
		// JSON tag drops the field on the wire when it is the empty
		// string.
		if macAvailable && !skipMAC {
			blockedByte := byte(0xff)
			if resp.Result != nil {
				if resp.Result.Blocked {
					blockedByte = 0x01
				} else {
					blockedByte = 0x00
				}
			}
			macHex, macErr := computeResponseMAC(macSecret, bridgeNonce, resp.ID, respKind, blockedByte, resp.APIToken, resp.Error)
			if macErr != nil {
				return fmt.Errorf("native: mac: %w", macErr)
			}
			resp.MAC = macHex
		}

		if werr := writeNativeMessage(out, resp); werr != nil {
			return fmt.Errorf("native: write: %w", werr)
		}
	}
}

// readNativeMessage reads one length-prefixed JSON frame from r. The
// length prefix is 4 bytes, little-endian, matching Chrome's protocol.
func readNativeMessage(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("native: zero-length message")
	}
	if n > max {
		return nil, fmt.Errorf("native: message too large (%d > %d)", n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// writeNativeMessage encodes payload as JSON and writes a 4-byte
// little-endian length prefix followed by the JSON body.
func writeNativeMessage(w io.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if uint32(len(data)) > MaxNativeMessageBytes {
		return fmt.Errorf("native: response too large (%d bytes)", len(data))
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
