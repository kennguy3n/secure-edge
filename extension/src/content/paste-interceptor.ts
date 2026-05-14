// Paste interceptor content script.
//
// Listens for `paste` events on Tier-2 AI tool pages, extracts the
// pasted text, and asks the local Secure Edge agent's DLP pipeline
// (POST /api/dlp/scan, or Native Messaging when available) whether to
// allow it. On block, the paste is suppressed and an ephemeral toast
// surfaces the matched pattern name (never the matched content) and
// auto-dismisses after 5 seconds.
//
// Failure modes (agent unreachable, slow response, non-2xx) fall open:
// the paste proceeds so an outage of the agent does not break the
// user's workflow. The popup surfaces an offline indicator.

import {
    MAX_SCAN_BYTES,
    ensureEnforcementModeBootstrapped,
    policyForOversize,
    policyForUnavailable,
    scanContent,
} from "./scan-client.js";
import { showBlockedToast, showPolicyBlockedToast, showPolicyWarnToast } from "./toast.js";

if (typeof document !== "undefined") {
    // Kick off a single enforcement-mode fetch on first script load so
    // managed/team posture is available by the time the user pastes.
    // The hot path below also tolerates a missed bootstrap by reading
    // the in-process cache (default "personal").
    ensureEnforcementModeBootstrapped();
    document.addEventListener("paste", (ev) => void onPaste(ev), { capture: true });
}

export async function onPaste(ev: ClipboardEvent): Promise<void> {
    const data = ev.clipboardData;
    if (!data) return;
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
export const __test__ = { onPaste };
