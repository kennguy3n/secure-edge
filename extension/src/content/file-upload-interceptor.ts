// File-upload interceptor content script (Phase 7 / B1).
//
// The network interceptor (main-world-network.ts) catches uploads
// that go through `fetch(url, { body: file })` or
// `xhr.send(formData)`. But some Tier-2 AI pages let the user drop a
// file into a `<input type="file">` widget that is read into page
// state via the FileReader API and shipped through a non-fetch
// pathway (websocket frame, GraphQL multipart, custom worker).
// Those code paths never touch our patched fetch / XHR, so the file
// contents would leave the page un-scanned.
//
// This interceptor closes that gap by snooping on the upload
// *gesture* itself, before the page's own code reads the file.
//
// SYNCHRONOUS-FIRST CONTRACT
// ---------------------------
// Both handlers are registered via
//   document.addEventListener("drop", (ev) => void onDrop(ev), { capture: true })
// which means the wrapper returns synchronously after kicking off
// the async body. The browser's dispatch cycle does NOT wait for
// the returned promise — it proceeds to call the page's own
// target / bubble-phase listeners during the same tick. By the
// time `await scanFileList(...)` resolves, the page has already
// consumed the event: a deferred `preventDefault()` /
// `stopPropagation()` is a no-op, and the file has already left
// the page.
//
// Therefore every observable suppression — `preventDefault`,
// `stopPropagation`, `stopImmediatePropagation`, clearing
// `input.value` — MUST happen synchronously, BEFORE the first
// `await`. The async scan only drives the toast UX after the
// suppression is already in effect. This matches the pattern in
// paste-interceptor / form-interceptor / drag-interceptor (which
// all call `preventDefault` before awaiting `scanContent`).
//
// There is no portable way to re-inject a `File` into a page's
// drop target or to programmatically re-construct `input.files`
// (most browsers make it read-only; the `DataTransfer.items`
// trick is Chromium-only and inconsistent in Safari). So a clean
// scan does NOT resume the gesture — the user must re-drag /
// re-pick if they're sure. This matches the privacy-first default
// and the existing drag-interceptor behaviour on Tier-2 pages
// without a focusable text insertion point.
//
//   - `<input type="file">` change events at capture phase: we
//     stop further dispatch via `stopImmediatePropagation` +
//     `stopPropagation`, snapshot `input.files`, clear
//     `input.value` so any later page logic that re-reads
//     `input.files` sees an empty selection, and only then scan.
//     On a clean verdict we don't resume — see above.
//   - `drop` events with `dataTransfer.files`: we call
//     `preventDefault` + `stopPropagation` synchronously, then
//     scan to surface the right toast.
//
// Privacy invariant: file contents are read into a string only for
// the scan. The string is never persisted, never logged, and is
// dropped as soon as the scan promise resolves. Only the pattern
// name surfaces through the toast.

import {
    ensureEnforcementModeBootstrapped,
    MAX_SCAN_BYTES,
    policyForOversize,
    policyForUnavailable,
    scanContent,
} from "./scan-client.js";
import { showBlockedToast, showPolicyBlockedToast, showPolicyWarnToast } from "./toast.js";

if (typeof document !== "undefined") {
    ensureEnforcementModeBootstrapped();
    // Capture-phase listeners so we see the event before the page's
    // own handlers and can preventDefault / clear the input.
    document.addEventListener("change", (ev) => void onChange(ev), { capture: true });
    document.addEventListener("drop", (ev) => void onDrop(ev), { capture: true });
}

/**
 * `<input type="file">` change handler. Fires when the user picks a
 * file via the system file-picker dialog. The selected files sit on
 * `input.files`; the page typically reads them inside its own
 * change-event listener, so this capture-phase handler races ahead.
 *
 * Sync-first contract (see header comment): we MUST suppress the
 * page's view of the selection synchronously, before any `await`.
 * `stopImmediatePropagation` blocks every later listener (including
 * other capture-phase listeners on `document`); clearing
 * `input.value` makes any later code that re-reads `input.files`
 * see an empty selection. We snapshot the files first so the async
 * scan can still inspect them.
 */
export async function onChange(ev: Event): Promise<void> {
    const input = ev.target as HTMLInputElement | null;
    if (!input || input.tagName !== "INPUT") return;
    if (input.type !== "file") return;
    const files = input.files;
    if (!files || files.length === 0) return;

    // Snapshot BEFORE clearing input.value, because setting
    // `input.value = ""` mutates `input.files` to an empty FileList
    // in the same tick.
    const snapshot: File[] = Array.from(files);

    // Synchronous suppression — see header comment. Order matters:
    // stopImmediatePropagation prevents the page's own change
    // handler from running in this same dispatch; clearing the
    // input.value means any code that re-reads input.files later
    // gets [] back.
    ev.stopImmediatePropagation();
    ev.stopPropagation();
    try {
        input.value = "";
    } catch {
        /* read-only / detached input — nothing we can do. */
    }

    // Now scan async purely for the toast UX. We don't act on the
    // verdict — the suppression is already in effect, and a clean
    // scan does not resume (see header comment on why
    // re-constructing input.files is not portable).
    await scanFileList(snapshot, "upload");
}

/**
 * Drop handler for file payloads. Plain-text drops are handled by
 * the drag interceptor (`drag-interceptor.ts`); we only act when
 * `dataTransfer.files` is non-empty.
 *
 * Sync-first contract (see header comment): `preventDefault` and
 * `stopPropagation` must run before the first `await`, otherwise
 * the page has already received the drop by the time we get back.
 */
export async function onDrop(ev: DragEvent): Promise<void> {
    const data = ev.dataTransfer;
    if (!data) return;
    const files = data.files;
    if (!files || files.length === 0) return;

    // Synchronous suppression. By the time the awaited scan
    // resolves, the page's drop listeners have already run during
    // this dispatch, so a deferred preventDefault / stopPropagation
    // would be a no-op. Re-injecting a File into the page's drop
    // target is not portable, so we never resume — the user
    // re-drags if they're sure.
    ev.preventDefault();
    ev.stopPropagation();

    // Scan async for the toast. The verdict doesn't drive any
    // further action — the drop is already suppressed above.
    await scanFileList(files, "upload");
}

type ScanVerdict = "blocked" | "allowed";

/**
 * Read up to `MAX_SCAN_BYTES` cumulative text from `files`, scan it,
 * and surface the appropriate toast. Returns "blocked" when the
 * caller should suppress / clear the upload, "allowed" otherwise.
 * Accepts a `FileList` (from `input.files` / `dataTransfer.files`)
 * or a plain `File[]` (used by `onChange` after snapshotting and
 * clearing the input).
 */
async function scanFileList(files: ArrayLike<File>, kind: "upload"): Promise<ScanVerdict> {
    const { text, truncated } = await readFilesText(files, MAX_SCAN_BYTES);
    if (text.length === 0) {
        // Empty / unreadable files (e.g. system file picker handed
        // back a zero-byte sentinel). Nothing to scan — fall open.
        return "allowed";
    }

    if (truncated) {
        // Cumulative size exceeded the cap. Treat as oversize per
        // the same policy the drop / paste interceptors use. We
        // still attempt a scan on the truncated text so DLP patterns
        // that match in the first MiB still fire — but if the agent
        // is unreachable AND we're managed, the oversize block wins.
        if (policyForOversize() === "block") {
            showPolicyBlockedToast("oversize", kind);
            return "blocked";
        }
    }

    const result = await scanContent(text);
    if (result === null) {
        const policy = policyForUnavailable();
        if (policy === "block") {
            showPolicyBlockedToast("agent-unavailable", kind);
            return "blocked";
        }
        if (policy === "warn") {
            showPolicyWarnToast("agent-unavailable", kind);
        }
        return "allowed";
    }
    if (result.blocked) {
        showBlockedToast(result.pattern_name, kind);
        return "blocked";
    }
    return "allowed";
}

/**
 * Read at most `cap` cumulative bytes of text from `files`. Each
 * file is sliced to fit the remaining budget so a single 5 GB file
 * does not buffer 5 GB into the page. Returns the decoded text plus
 * a `truncated` flag indicating whether the cap was reached.
 *
 * Binary files (e.g. PNG) decode as best-effort UTF-8 via
 * `Blob.text()` (which uses a fatal=false UTF-8 decoder under the
 * hood); the scanner still sees recognisable runs of ASCII that
 * patterns like `AKIA[0-9A-Z]{16}` can match.
 */
async function readFilesText(
    files: ArrayLike<File>,
    cap: number,
): Promise<{ text: string; truncated: boolean }> {
    const parts: string[] = [];
    let used = 0;
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (used >= cap) {
            return { text: parts.join("\n"), truncated: true };
        }
        const remaining = cap - used;
        try {
            const sliced = file.size > remaining ? file.slice(0, remaining) : file;
            const text = await sliced.text();
            parts.push(text);
            used += text.length;
        } catch {
            // Reading the slice can throw (revoked URL, torn-down
            // file descriptor). Skip the file rather than blowing
            // up the whole scan.
        }
    }
    return { text: parts.join("\n"), truncated: used >= cap };
}

export const __test__ = { onChange, onDrop, scanFileList, readFilesText };
