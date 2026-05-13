# Accessibility checklist

Secure Edge ships a small Electron tray app whose only job is to
display agent state and let the user adjust a handful of policy
toggles. The UI surface is small, which means accessibility coverage
is achievable end-to-end. This document is a manual verification
checklist for the team to run before tagging a release.

The targets are WCAG 2.1 AA.

## Visual / colour

- **SC 1.4.3 Contrast (Minimum)** — Every text element passes 4.5:1 in
  both light and dark themes. Re-check after any colour change in
  `electron/src/styles.css`.
- **SC 1.4.11 Non-text Contrast** — Form fields, toggle pills, and
  focus rings pass 3:1 against their surrounding background.
- **SC 1.4.12 Text Spacing** — Layout doesn't break when the user
  applies a 200% text scale (test via Chromium DevTools → Rendering →
  Emulate CSS media feature `prefers-reduced-motion`).
- **Dark mode** — `prefers-color-scheme: dark` swaps in the dark
  palette defined in `:root` overrides. Verify each page in both
  themes after any colour change.

## Keyboard

- **Tab navigation** — Every interactive control is reachable with
  Tab/Shift-Tab. Tab order matches visual order.
- **Focus visible** — Every focusable element shows the explicit
  outline defined in `styles.css` `:focus-visible`. The default
  Chromium ring is intentionally overridden because it varies in
  contrast across themes.
- **Arrow keys on tablist** — The top nav implements WAI-ARIA tablist
  arrow-key navigation (Home / End / Left / Right). Verify on the
  Status/Rules/Settings/Proxy tabs.
- **Setup wizard** — Step controls are reachable in sequence. Esc on
  step 3 does not bypass `Finish setup` (intentional — completion is
  the only exit).

## Screen readers

- **Tablist semantics** — `<nav role="tablist">` plus per-button
  `role="tab"` / `aria-selected` / `aria-controls` is announced
  correctly by VoiceOver, NVDA, and Orca.
- **Status banner** — Uses `role="status"` + `aria-live="polite"` so
  reachability changes are announced without interrupting the user.
- **Block notifications** — Recent-blocks list is announced when it
  updates, and its caption explains that the list is ephemeral.
- **Forms** — Every `<input>` has an associated `<label>` (either
  wrapped or via `htmlFor`).

## Motion / reduced-motion

- The renderer has no animations longer than 200 ms. If you add one,
  guard it with `@media (prefers-reduced-motion: reduce)` and provide
  an instant fallback.

## How to run the checks

1. `cd electron && npm run typecheck && npm run build`
2. Open the built renderer in Chromium with the dev tools open.
3. Tab through every control on every page in both themes.
4. Toggle `prefers-color-scheme` via DevTools → Rendering and re-run
   step 3.
5. Run the page through axe DevTools (Chrome extension). All severity
   levels above "minor" must be addressed.
