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
 * change-event listener.
 *
 * Sync-first contract (see header comment): we MUST suppress the
 * page's view of the selection synchronously, before any `await`.
 * In a single event dispatch the order is
 *   capture (window, document, parents...) -> target -> bubble.
 * Calling `stopPropagation()` at the capture phase prevents the
 * target / bubble phases from running at all, AND
 * `stopImmediatePropagation()` prevents any subsequent same-phase
 * listener on the same node from firing. So a page listener
 * registered on the input itself (target phase) or on any
 * ancestor (capture or bubble phase) WILL NOT fire in this
 * dispatch.
 *
 * The narrow gap that remains: a page that registers its OWN
 * capture-phase listener on `document` BEFORE this content script
 * loads (e.g. a page-bundled script that runs before our
 * registered `document_start` injection settles) sits earlier in
 * the listener list on the same target/phase. That listener will
 * have already fired by the time ours runs. We cannot prevent it.
 * The network interceptor (`main-world-network.ts`) re-scans the
 * file when it's actually shipped via fetch/XHR, which closes the
 * remaining exfil path even when the page held a File reference
 * from that earlier dispatch.
 *
 * Clearing `input.value` is the secondary defence: it empties
 * `input.files` so any deferred page logic that re-reads the
 * input later (e.g. a setTimeout or a microtask) gets an empty
 * FileList. We snapshot first because `input.value = ""` mutates
 * `input.files` synchronously, and we still want the async scan
 * to inspect the original selection.
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
 * Sync-first contract (see header comment): `preventDefault`,
 * `stopPropagation`, and `stopImmediatePropagation` must all run
 * before the first `await`, otherwise the page has already
 * received the drop by the time we get back.
 *
 * `stopImmediatePropagation` also matters for our own multi-listener
 * coexistence on Chrome: `drag-interceptor.ts` registers its own
 * capture-phase `drop` listener on `document`. Manifest load order
 * puts it earlier in the listener list, so it runs before this
 * handler. Its early-return on `getData("text/plain") === ""` keeps
 * it benign for the common file-drop case (no text payload). But
 * some OS file managers attach the file path as `text/plain`
 * alongside the File. In that case drag-interceptor would scan and
 * potentially `resumeDrop` the path text. The eventual file exfil
 * is still caught by network-interceptor, but the dual-listener
 * dance is surprising UX (a stale path string can end up inserted
 * into a focusable field). Calling `stopImmediatePropagation` here
 * does not help against earlier-registered listeners on the same
 * phase + target. Instead, we keep the call for completeness against
 * later-registered listeners and rely on drag-interceptor's own
 * `files.length > 0` short-circuit (added in `drag-interceptor.ts`,
 * tested in `drag-interceptor.test.ts`) to handle the dual-drop
 * case correctly.
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
    ev.stopImmediatePropagation();
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
 * The returned string is GUARANTEED to be at most `cap` characters
 * long. We join parts with `"\n"` separators, which means the join
 * itself can push the joined string past the cap even when the
 * per-file accounting stays under it (e.g. two files of exactly
 * cap/2 chars each yield cap + 1 chars after joining). A final
 * `slice(0, cap)` enforces the invariant unconditionally so
 * downstream `scanContent` does not silently return null on
 * `content.length > MAX_SCAN_BYTES`.
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
    let stoppedAtCap = false;
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (used >= cap) {
            stoppedAtCap = true;
            break;
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
    const joined = parts.join("\n");
    // Enforce the cap on the joined string: the `"\n"` separators
    // between parts are not counted in `used`, so a stream of
    // small-enough files can still push `joined.length` over `cap`.
    // `slice(0, cap)` is a cheap unconditional safety net.
    const text = joined.length > cap ? joined.slice(0, cap) : joined;
    const truncated = stoppedAtCap || used >= cap || joined.length > cap;
    return { text, truncated };
}

export const __test__ = { onChange, onDrop, scanFileList, readFilesText };
