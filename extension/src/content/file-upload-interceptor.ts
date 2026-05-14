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
// *gesture* itself, before the page's own code reads the file:
//
//   - `<input type="file">` change events at capture phase — the
//     File objects sit in `input.files` and the page hasn't seen
//     them yet. We read up to MAX_SCAN_BYTES of text content,
//     scan, and if blocked clear `input.value` and dispatch a
//     synthetic `change` event so React-controlled forms notice
//     the cleared selection.
//   - `drop` events with `dataTransfer.files`. The drag interceptor
//     only handles `text/plain` payloads (it returns early when
//     `dataTransfer.getData("text/plain")` is empty), so a file
//     drop falls through here. We `preventDefault()` +
//     `stopPropagation()` to keep the file from reaching the page's
//     own handler.
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
 * change-event listener, so this capture-phase handler races ahead
 * and scans the file content first.
 */
export async function onChange(ev: Event): Promise<void> {
    const input = ev.target as HTMLInputElement | null;
    if (!input || input.tagName !== "INPUT") return;
    if (input.type !== "file") return;
    const files = input.files;
    if (!files || files.length === 0) return;

    const verdict = await scanFileList(files, "upload");
    if (verdict === "blocked") {
        // Clear the selection and re-emit `change` so React-managed
        // forms notice the cleared input. Without the synthetic
        // event the page's internal state would still believe the
        // file was selected.
        try {
            input.value = "";
            input.dispatchEvent(new Event("change", { bubbles: true }));
        } catch {
            /* read-only / detached input — nothing we can do. */
        }
        // The toast was already rendered by scanFileList.
    }
}

/**
 * Drop handler for file payloads. Plain-text drops are handled by
 * the drag interceptor (`drag-interceptor.ts`); we only act when
 * `dataTransfer.files` is non-empty.
 */
export async function onDrop(ev: DragEvent): Promise<void> {
    const data = ev.dataTransfer;
    if (!data) return;
    const files = data.files;
    if (!files || files.length === 0) return;

    // We need to make the block decision before the page consumes
    // the drop. preventDefault + stopPropagation prevent the page's
    // own listeners from firing; we don't resume the drop because
    // there's no portable way to re-inject a File into an arbitrary
    // page's drop target (different from text drops which we re-
    // insert via execCommand). The user is told via toast and can
    // re-drag if they choose.
    const verdict = await scanFileList(files, "upload");
    if (verdict === "blocked") {
        ev.preventDefault();
        ev.stopPropagation();
    }
}

type ScanVerdict = "blocked" | "allowed";

/**
 * Read up to `MAX_SCAN_BYTES` cumulative text from `files`, scan it,
 * and surface the appropriate toast. Returns "blocked" when the
 * caller should suppress / clear the upload, "allowed" otherwise.
 */
async function scanFileList(files: FileList, kind: "upload"): Promise<ScanVerdict> {
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
    files: FileList,
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
