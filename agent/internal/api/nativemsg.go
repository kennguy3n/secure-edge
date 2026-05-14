package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/kennguy3n/secure-edge/agent/internal/dlp"
	"github.com/kennguy3n/secure-edge/agent/internal/store"
)

// MaxNativeMessageBytes caps both incoming and outgoing Native Messaging
// payloads. Chrome enforces a 1 MiB limit on messages from the extension
// to the host; we mirror that so we never silently truncate.
const MaxNativeMessageBytes uint32 = 1 * 1024 * 1024

// NativeMessageRequest is the wire shape received from a connected
// Chrome extension on stdin. The id is echoed back so the extension can
// correlate concurrent requests.
type NativeMessageRequest struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

// NativeMessageResponse is the wire shape returned on stdout.
// Result, APIToken, and Error are mutually exclusive per response.
// APIToken is populated on a successful "hello" reply so the
// extension can cache the per-install token for its HTTP fallback
// path (work item A2).
type NativeMessageResponse struct {
	ID       int             `json:"id"`
	Result   *dlp.ScanResult `json:"result,omitempty"`
	APIToken string          `json:"api_token,omitempty"`
	Error    string          `json:"error,omitempty"`
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
		if jerr := json.Unmarshal(raw, &req); jerr != nil {
			// Best-effort error reply when we can't even parse the
			// envelope. id is left at zero — the extension treats
			// id=0 as "unsolicited" and surfaces the error to the user.
			resp.Error = "invalid request JSON"
		} else {
			resp.ID = req.ID
			switch req.Kind {
			case "scan":
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
				resp.APIToken = opts.APIToken
			default:
				resp.Error = fmt.Sprintf("unknown kind: %q", req.Kind)
			}
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
