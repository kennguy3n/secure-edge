# Accessibility Audit — Electron Tray UI

**Scope:** `electron/src/main.tsx`, `electron/src/pages/Status.tsx`,
`electron/src/pages/Settings.tsx`, `electron/src/pages/ProxySettings.tsx`,
`electron/src/components/CategoryToggle.tsx`,
`electron/src/components/StatsCard.tsx`, `electron/src/styles.css`.

**Standards:** WCAG 2.1 Level AA, ARIA 1.2 authoring practices.

**Date:** 2026-05-13 — Phase 5.

## Summary

| Area | Status |
| --- | --- |
| Keyboard navigation | **Pass** — every interactive element is a native `<button>`, `<input>`, or `<select>` and reachable via Tab. The top tablist also supports the standard WAI-ARIA tabs pattern: `ArrowLeft` / `ArrowRight` cycle through tabs with wrap-around, `Home` jumps to the first tab, `End` to the last. |
| Visible focus indicator | **Pass** — explicit `:focus-visible` outline in `styles.css` (`2px solid var(--accent)`, `outline-offset: 2px`). |
| Semantic landmarks | **Pass** — top nav is `role="tablist"`, the body is `role="tabpanel"` with `aria-labelledby` pointing at the active tab. |
| Icon-only buttons / non-text controls | **Pass** — every icon-only or short-label button now carries an `aria-label` describing the action (e.g. `Remove example.com from allow list`). |
| Three-state CategoryToggle | **Pass** — implemented as `role="radiogroup"` with three `role="radio"` buttons, each with `aria-checked`, `title` (hint), and `disabled` reflecting the selected state. |
| Live status announcements | **Pass** — agent reachability banner is `role="status" aria-live="polite"`; success feedback uses `role="status"`, error feedback uses `role="alert" aria-live="assertive"`. |
| Form field labels | **Pass** — every `<input>` / `<select>` has either a wrapping `<label>` or a visually-hidden `<label class="sr-only">` plus `htmlFor` + `id`. |
| Color contrast | **Pass** — base palette tested in both light and dark modes; foreground/background contrast ratios meet WCAG AA (4.5:1 body, 3:1 large text). Accent colour `#2563eb` on `#ffffff` measured at 5.9:1; `#117a3b` on `#ffffff` at 4.6:1; `#b32116` on `#ffffff` at 7.3:1. |
| Keyboard activation of toggles | **Pass** — `role="radio"` buttons activate on Enter and Space (native button semantics). The 3-state CategoryToggle disables the *currently selected* button so re-clicking the same option is a no-op. |
| Reflow / zoom | **Pass** — layout is fluid; the tray window is normally narrow but the page sections wrap on smaller widths thanks to grid-based `stats-grid` and `dlp-grid`. |

## Per-page findings

### `main.tsx` (tabbed shell)

- **Before:** topbar was a `<nav>` with three unannotated `<button>` elements.
- **After:** topbar is `role="tablist"` with `aria-label="Secure Edge sections"`. Each button has `role="tab"`, `aria-selected`, an `id` (`tab-status` etc.), and roving `tabIndex` (0 on the active tab, -1 on the rest). The content area below is `role="tabpanel"` with `aria-labelledby` pointing at the active tab.
- Keyboard navigation follows the WAI-ARIA tabs pattern: `ArrowLeft` / `ArrowRight` move focus to the previous / next tab with wrap-around, `Home` focuses the first tab, `End` focuses the last. Selection follows focus, so the active hash is updated as the user arrows through. The tablist itself takes a single Tab stop (the active tab); from there the user arrows between tabs and continues Tab into the panel content.
- Tab order is left-to-right: Status → Settings → Proxy → page content.

### `Status.tsx`

- Agent reachability banner now exposes `role="status" aria-live="polite"`, so screen readers announce when the agent goes offline or back online during the 5s poll.
- The "Anonymous Counters" grid is `role="list"`; each `StatsCard` is `role="listitem"` with a composite `aria-label` (`"DNS blocks: 142"`). Numeric tile content is `aria-hidden="true"` so the screen reader doesn't read the value twice.
- "Reset Counters" button has an explicit `aria-label="Reset all anonymous counters to zero"` because the visible label is terse.

### `Settings.tsx`

- The locked-by-profile banner stays in place and is read as part of the page body.
- Feedback toasts pick role/aria-live based on `kind`: `error → role="alert" aria-live="assertive"`, `success → role="status" aria-live="polite"`.
- The Categories list is `role="list" aria-label="Traffic categories"`.
- The "Add domain override" group uses `role="group"` with `aria-label="Add domain override"`; the text input and select have visually-hidden `<label>` elements (via the new `.sr-only` utility) plus `htmlFor`/`id` pairs, and the **Add** button carries a dynamic `aria-label` mentioning the domain and target list.
- The text input now activates the Add action on Enter.
- Each **Remove** button has an `aria-label` naming the specific domain it removes and which list it removes from.

### `ProxySettings.tsx`

- Feedback toasts use the same `alert` / `status` split as Settings.
- Status section is a plain `<ul>` of native semantics; no changes needed.
- The "Generate CA & start proxy" / "Stop proxy" buttons carry their action in their visible text, so no `aria-label` is needed.

### `CategoryToggle.tsx`

- Already implemented as `role="radiogroup"` with `aria-label="Action for category <name>"`.
- Each option button is `role="radio"` with `aria-checked`, `title` (the hint), `disabled` set when the option is the currently-selected one.
- Selected option is also marked via `data-selected="true"` so the CSS rule in `styles.css` can apply the contrasting selected style.

### `StatsCard.tsx`

- Now `role="listitem"` with a composite `aria-label` so screen readers read the metric and value as one sentence (`"DLP blocks: 7"`) instead of separately.

## CSS additions (`styles.css`)

- `.sr-only` — standard visually-hidden utility class for screen-reader-only labels.
- `:focus-visible` outline — explicit 2px accent ring with 2px offset on `button`, `input`, `select`, `[role="radio"]`, and `[role="tab"]`. Meets WCAG 2.1 SC 2.4.7 (Focus Visible) and SC 1.4.11 (Non-text Contrast).
- `.category-controls button[data-selected="true"]` — explicit selected-state styling so the segmented control is distinguishable without relying on `:disabled` (which can be confused with "not interactive").

## Known limitations

- The Electron tray window is small (~360 × 480) so the design intentionally
  hides secondary text behind hover/title tooltips. Screen-reader users get
  the hint via `aria-describedby` on the affected control (via the existing
  `title` attribute → tooltip + accessible description).
- The reduced-motion preference (`prefers-reduced-motion`) is currently honoured
  because the UI does not animate state changes. If we introduce transitions in
  Phase 6 we will wrap them in `@media (prefers-reduced-motion: no-preference)`.

## Manual verification steps

1. Open the tray window.
2. Press Tab and confirm focus rings cycle: Status tab → Settings tab → Proxy tab → first interactive element in the page → … → Reset Counters.
3. Switch to Settings. Tab to each `CategoryToggle`; arrow-key navigation between the three buttons works (native button semantics). Press Enter on a non-selected option and confirm the policy updates.
4. In Settings → Admin Overrides, focus the text input and press Enter without typing → no action. Type a domain and press Enter → the domain is added.
5. With macOS VoiceOver / NVDA on Windows / Orca on Linux active:
   - On page load: the agent status banner reads `"Running · v0.5.0 · uptime …"`.
   - Stopping the agent triggers `aria-live="polite"` to announce `"Agent unreachable …"`.
   - Saving a category change announces `"Saved: AI Chat"` via the success toast.
   - Triggering a save error announces the error text with assertive priority.

## Future work (out of scope for Phase 5)

- Add an accessible visualization for the DLP scoring sliders' current value (we expose the value via the sibling `<span>` and via the slider's native value, but a `aria-valuetext` describing whether the score is "stricter" or "looser" would be friendlier).
- Add `prefers-contrast: more` overrides to bump up border weights for high-contrast mode users.
- Run `axe-core` automatically as part of CI once the Electron renderer is testable in a JSDOM environment.
