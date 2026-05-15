// Paste interceptor content script.
//
// Listens for `paste` events on Tier-2 AI tool pages and routes
// each gesture through one of two paths depending on the
// clipboard payload:
//
//   * TEXT path — `clipboardData.getData("text/plain")` returns a
//     non-empty string. The text is forwarded to `scanContent` and,
//     on a clean verdict, re-emitted into the focused element via
//     `resumePaste`. This path predates B3 (it shipped with the
//     original paste interceptor) and is unchanged below — see the
//     "TEXT PATH" block in `onPaste`.
//
//   * FILE path — `clipboardData.files` is non-empty OR
//     `clipboardData.items[i].getAsFile()` returns a File for at
//     least one item (e.g. the user copied a file in the system
//     file manager, or pasted an image from a screenshot tool).
//     The file is the upload-gesture surface that the existing
//     `<input type=file>` / drag-drop hooks in
//     `file-upload-interceptor.ts` do NOT cover, because no
//     `change` / `drop` event ever fires on a clipboard paste.
//     This path (added in PR10 / B3) closes the gap. On a clean
//     verdict the gesture is NOT resumed — there is no portable
//     way to programmatically re-construct a `DataTransfer.files`
//     list on the page side, matching the no-resume contract in
//     `file-upload-interceptor.ts`.
//
// MIXED PASTE (text + file)
// -------------------------
// The W3C Clipboard spec lets a single paste carry both text and
// file payloads (e.g. drag a file out of Finder, copy it, paste
// it into a contenteditable: the clipboard has the filename as
// text/plain AND the File itself). B3 routes mixed pastes
// through the FILE path: it is the more-conservative branch (no
// resume + content scan + risky-extension guard) and a file's
// presence on the clipboard is the strictly less-common case,
// so a false-positive on the text "filename" string is worth
// the privacy guarantee. Pages relying on the text fragment can
// re-paste after dismissing the toast.
//
// SYNCHRONOUS-FIRST CONTRACT
// --------------------------
// Same contract as `file-upload-interceptor.ts`: every observable
// suppression — `preventDefault`, `stopPropagation` — MUST fire
// synchronously BEFORE the first `await`. The browser dispatches
// the paste event to the page's own listeners during the same
// tick; a deferred suppression after `await scanContent(...)` is a
// no-op.
//
// FALL-OPEN POSTURE
// -----------------
// Failure modes match the rest of the extension. Agent
// unreachable / slow / non-2xx returns null from `scanContent`,
// which routes through `policyForUnavailable`:
//
//   personal — silent fall-open (no toast, paste resumes if TEXT)
//   team     — warn toast + fall-open
//   managed  — block + policy toast, no resume
//
// Oversize routes through `policyForOversize` with the same
// posture but a different toast.

import {
    MAX_SCAN_BYTES,
    ensureEnforcementModeBootstrapped,
    policyForOversize,
    policyForUnavailable,
    scanContent,
} from "./scan-client.js";
import {
    ensureRiskyExtensionsBootstrapped,
    extensionOf,
    getCachedRiskyExtensions,
    isRiskyExtension,
} from "./risky-extensions.js";
import {
    showBlockedToast,
    showPolicyBlockedToast,
    showPolicyWarnToast,
    showRiskyExtensionBlockedToast,
} from "./toast.js";

if (typeof document !== "undefined") {
    // Kick off a single enforcement-mode fetch on first script load so
    // managed/team posture is available by the time the user pastes.
    // The hot path below also tolerates a missed bootstrap by reading
    // the in-process cache (default "personal").
    ensureEnforcementModeBootstrapped();
    // B3 risky-extension cache bootstrap. Same fire-and-forget
    // pattern as the file-upload-interceptor — the hot path
    // defaults to the baked-in list, which is safe-by-default
    // (always block) for risky-file-paste.
    ensureRiskyExtensionsBootstrapped();
    document.addEventListener("paste", (ev) => void onPaste(ev), { capture: true });
}

export async function onPaste(ev: ClipboardEvent): Promise<void> {
    const data = ev.clipboardData;
    if (!data) return;

    // ---------- FILE PATH (B3) -------------------------------------
    //
    // Collect every File on the clipboard via two complementary
    // APIs:
    //
    //   `clipboardData.files`   — modern, populated when the user
    //                              copies one or more files in a
    //                              file manager.
    //   `clipboardData.items[]` — wider compatibility; an item with
    //                              `kind: "file"` covers screenshot
    //                              tools that put an image on the
    //                              clipboard without a File object
    //                              in `.files` (Linux / older
    //                              browsers).
    //
    // We must inspect both: `files` may be empty even though items
    // carries a `kind: "file"` entry (legacy clipboard fragments),
    // and items may be missing entirely on some browsers.
    const files = collectClipboardFiles(data);
    if (files.length > 0) {
        // Sync-first contract — see header. Suppress synchronously
        // BEFORE any await; no resume on clean verdict; B3 mixed-
        // paste rule (file path wins over text path).
        ev.preventDefault();
        ev.stopPropagation();

        // Risky-extension guard (mirrors file-upload-interceptor's
        // `firstRiskyExtensionMatch`). Filename-driven, no content
        // read — the user sees the policy toast and the file
        // contents are never decoded.
        const risky = firstRiskyClipboardExtension(files);
        if (risky !== null) {
            showRiskyExtensionBlockedToast(risky, "clipboard");
            return;
        }
        await scanClipboardFiles(files);
        return;
    }

    // ---------- TEXT PATH ------------------------------------------
    //
    // No file payload. Fall through to the original text-paste
    // logic — unchanged from the pre-B3 release.
    const text = data.getData("text/plain");
    if (!text || text.length === 0) return;

    if (text.length > MAX_SCAN_BYTES) {
        // Oversize handling depends on the enforcement mode. In
        // personal/team mode the paste proceeds silently (current
        // behaviour); in managed mode we block + surface a policy
        // toast so the user understands why the paste was rejected.
        if (policyForOversize() === "block") {
            ev.preventDefault();
            ev.stopPropagation();
            showPolicyBlockedToast("oversize", "paste");
        }
        return;
    }

    // Stop the paste while we ask the agent. We re-emit the paste
    // manually if the agent allows it (see resumePaste below).
    ev.preventDefault();
    ev.stopPropagation();

    const target = ev.target as EventTarget | null;
    const result = await scanContent(text);

    if (result === null) {
        // No verdict from the agent: behaviour depends on enforcement
        // mode. "personal" = silent fall-open (preserve pre-C2 UX);
        // "team" = warn toast + fall-open; "managed" = block.
        const policy = policyForUnavailable();
        if (policy === "block") {
            showPolicyBlockedToast("agent-unavailable", "paste");
            return;
        }
        if (policy === "warn") {
            showPolicyWarnToast("agent-unavailable", "paste");
        }
        await resumePaste(target, text);
        return;
    }
    if (!result.blocked) {
        await resumePaste(target, text);
        return;
    }
    showBlockedToast(result.pattern_name, "paste");
}

/**
 * Walk the clipboard payload and return every File reachable via
 * `clipboardData.files` AND `clipboardData.items[].getAsFile()`.
 * Dedupes by reference so a file that appears on both APIs is only
 * scanned once.
 *
 * Pure helper (no scan, no DOM mutation). The caller has already
 * decided this is the FILE path; this function only does the
 * enumeration.
 */
export function collectClipboardFiles(data: DataTransfer): File[] {
    const out: File[] = [];
    const seen = new Set<File>();

    // Primary surface: clipboardData.files (FileList).
    const fl = data.files;
    if (fl && fl.length > 0) {
        for (let i = 0; i < fl.length; i++) {
            const f = fl.item ? fl.item(i) : (fl as unknown as Record<number, File>)[i];
            if (f && !seen.has(f)) {
                seen.add(f);
                out.push(f);
            }
        }
    }

    // Secondary surface: clipboardData.items[] with kind === "file".
    // Some browsers (older Chromium, Firefox before 96) populate
    // items but leave files empty for screenshot-tool pastes.
    const items = data.items;
    if (items && items.length > 0) {
        for (let i = 0; i < items.length; i++) {
            const it = items[i];
            if (!it || it.kind !== "file") continue;
            // getAsFile() can return null (item lifecycle race);
            // skip silently. Re-reading a File from the same item
            // is idempotent — no destructive read happens here.
            let f: File | null = null;
            try {
                f = it.getAsFile ? it.getAsFile() : null;
            } catch {
                f = null;
            }
            if (f && !seen.has(f)) {
                seen.add(f);
                out.push(f);
            }
        }
    }

    return out;
}

/**
 * Synchronous risky-extension check for the clipboard FILE path.
 * Mirrors `firstRiskyExtensionMatch` in
 * `file-upload-interceptor.ts`: returns the first matched
 * extension (lowercase, dot-less) or null when no file is risky.
 * The cache snapshot is read once so a refresh racing this call
 * cannot half-apply.
 *
 * Sync-first: this is the pre-await guard. A subsequent
 * runtime.sendMessage refresh updates the cache for future calls
 * but does not retroactively change the verdict for the in-flight
 * paste.
 */
export function firstRiskyClipboardExtension(files: ArrayLike<File>): string | null {
    const list = getCachedRiskyExtensions();
    if (list.length === 0) return null;
    for (let i = 0; i < files.length; i++) {
        const f = files[i];
        if (!f) continue;
        if (isRiskyExtension(f.name, list)) {
            return extensionOf(f.name);
        }
    }
    return null;
}

/**
 * Read up to MAX_SCAN_BYTES cumulative text from `files`, scan it
 * via the existing `scanContent` helper, and surface the
 * appropriate toast. Mirrors the body of `scanFileList` in
 * `file-upload-interceptor.ts` (kept independent so the two
 * interceptors stay decoupled and a refactor of one cannot break
 * the other).
 *
 * Returns void — the gesture is already suppressed by the caller;
 * this function only owns the toast UX.
 */
async function scanClipboardFiles(files: ArrayLike<File>): Promise<void> {
    const { text, truncated } = await readClipboardFilesText(files, MAX_SCAN_BYTES);
    if (text.length === 0) {
        // Empty / unreadable files. Nothing to scan — silently
        // fall open. The paste is already suppressed; the user
        // sees no toast (consistent with file-upload-interceptor's
        // empty-file behaviour).
        return;
    }
    if (truncated) {
        if (policyForOversize() === "block") {
            showPolicyBlockedToast("oversize", "clipboard");
            return;
        }
        // Personal / team: continue with the truncated scan so any
        // DLP pattern in the first MiB still fires.
    }
    const result = await scanContent(text);
    if (result === null) {
        const policy = policyForUnavailable();
        if (policy === "block") {
            showPolicyBlockedToast("agent-unavailable", "clipboard");
            return;
        }
        if (policy === "warn") {
            showPolicyWarnToast("agent-unavailable", "clipboard");
        }
        return;
    }
    if (result.blocked) {
        showBlockedToast(result.pattern_name, "clipboard");
    }
    // Clean verdict — gesture stays suppressed (no portable
    // re-injection path). No toast.
}

/**
 * Read at most `cap` cumulative bytes of text from `files`. Each
 * file is sliced to fit the remaining budget so a multi-GB paste
 * never buffers itself into the page. Returns the decoded text
 * plus a `truncated` flag indicating whether the cap was hit.
 *
 * Identical shape to `readFilesText` in
 * `file-upload-interceptor.ts`; not shared because B3 deliberately
 * keeps the paste path's dependencies minimal (the file-upload
 * helper is not exported on the production surface).
 */
async function readClipboardFilesText(
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
            // Silently skip a file whose backing blob torn down
            // mid-read — same behaviour as readFilesText.
        }
    }
    const joined = parts.join("\n");
    const text = joined.length > cap ? joined.slice(0, cap) : joined;
    const truncated = stoppedAtCap || used >= cap || joined.length > cap;
    return { text, truncated };
}

async function resumePaste(target: EventTarget | null, text: string): Promise<void> {
    // Insert the text into the focused element. Two cases:
    //   1. <input> / <textarea> — set selectionStart/End and use
    //      document.execCommand('insertText') so the page sees the
    //      same event-stream it would have seen from a normal paste.
    //   2. contenteditable / rich editor — same insertText API.
    const el = (target instanceof HTMLElement ? target : document.activeElement) as HTMLElement | null;
    if (!el) return;
    el.focus();
    if (document.queryCommandSupported && document.queryCommandSupported("insertText")) {
        document.execCommand("insertText", false, text);
        return;
    }
    // Fallback for inputs/textareas without execCommand support.
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        const start = el.selectionStart ?? el.value.length;
        const end = el.selectionEnd ?? el.value.length;
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + text.length;
        el.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

// Export for tests; not used by the content-script entry path.
export const __test__ = {
    onPaste,
    collectClipboardFiles,
    firstRiskyClipboardExtension,
    scanClipboardFiles,
    readClipboardFilesText,
};
