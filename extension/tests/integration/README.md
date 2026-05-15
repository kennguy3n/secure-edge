# Extension integration tests

These Playwright-based smoke tests load the built extension into a
real Chromium instance, navigate to an in-memory mock AI-tool page,
paste a fake secret, and assert that the ShieldNet Secure Edge block toast
fires. They are intentionally **not** part of the default `npm test`
run because they require a headed Chromium binary (~200 MB) and a
running agent.

## Prerequisites

- The extension is built. Running `npm run build` from `extension/`
  compiles the TypeScript sources to `extension/dist/`. The
  loadable extension root, however, is the `extension/` directory
  itself — that is where `manifest.json` lives. The manifest
  references its compiled scripts via `dist/...` relative paths, so
  Chromium needs to be pointed at `extension/`, **not**
  `extension/dist/`. Pointing Chromium at `extension/dist/` makes
  Chrome show a *"Manifest file is missing or unreadable"* error
  dialog because `dist/` is just the compiled-JS output directory.
- The ShieldNet Secure Edge agent is running on `http://127.0.0.1:8080` with
  DLP enabled.
- Playwright is installed *out of band* — it is not pinned in
  `package.json` to keep the default install footprint small:

```sh
cd extension
npm install --no-save playwright
npx playwright install chromium
```

## Running

```sh
node --import tsx tests/integration/block-toast.test.ts
```

The script is a vanilla Node test, not a Jest/Vitest suite — it uses
the same `node --test` runner the rest of the extension already uses
in `package.json`.

### Manual smoke test in a regular Chromium

The same flow can be verified by hand without Playwright:

```sh
chromium \
  --disable-extensions-except="$PWD/extension" \
  --load-extension="$PWD/extension" \
  "file://$PWD/extension/tests/integration/fixture.html"
```

Again: pass the `extension/` directory, not `extension/dist/`.

## What it covers

- Acceptance: the extension's block toast appears for an AI-tool
  host when a known-bad token is pasted into a textarea, and the
  form submission is blocked.

## What it does NOT cover

- Real production hosts. The integration test serves its own minimal
  fixture page from `file://` rather than driving chat.openai.com etc.
  Driving real hosts would need a long-lived bot account and is left
  to manual QA.
