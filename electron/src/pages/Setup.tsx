import { useEffect, useState } from 'react';

const COMPLETION_KEY = 'secureEdge.setup.completed';

/** First-run setup wizard (Phase 6 Task 21).
 *
 *  Three short steps:
 *   1. What the agent does (single paragraph)
 *   2. DNS configuration prompt (link to platform-specific docs)
 *   3. Optional DLP inspection opt-in
 *
 *  Completion is stored in window.localStorage under
 *  `secureEdge.setup.completed`. The packaged Electron app shares
 *  localStorage between sessions, so the user only sees the wizard
 *  once. The flag is intentionally NOT persisted via electron-store
 *  to keep the wizard testable in a vanilla browser.
 */
export function Setup({ onComplete }: { onComplete?: () => void }) {
  const [step, setStep] = useState(0);
  const [enableDLP, setEnableDLP] = useState(true);

  useEffect(() => {
    // No telemetry — completion is purely local UI state.
  }, []);

  const finish = () => {
    try {
      window.localStorage.setItem(COMPLETION_KEY, 'true');
      if (enableDLP) {
        window.localStorage.setItem('secureEdge.dlp.optIn', 'true');
      }
    } catch {
      // Storage unavailable (private browsing) — non-fatal.
    }
    onComplete?.();
  };

  return (
    <div className="page" aria-labelledby="setup-heading">
      <h2 id="setup-heading">Welcome to Secure Edge</h2>

      {step === 0 && (
        <>
          <p>
            Secure Edge runs locally on your machine. It inspects DNS
            traffic against community blocklists and, when you enable
            inspection, scans outbound prompts to AI tools for
            credentials and secrets — entirely on-device. No content
            ever leaves your computer.
          </p>
          <button type="button" className="reset-button" onClick={() => setStep(1)}>
            Next
          </button>
        </>
      )}

      {step === 1 && (
        <>
          <h3>Point your system DNS at Secure Edge</h3>
          <p>
            To use Secure Edge for DNS filtering, set your system DNS
            resolver to <code>127.0.0.1</code>. The packaged installer
            does this for you on most platforms; if you installed from
            source, see the documentation in <code>docs/dns-setup.md</code>.
          </p>
          <div className="category-controls">
            <button type="button" onClick={() => setStep(0)}>Back</button>
            <button type="button" className="reset-button" onClick={() => setStep(2)}>
              Next
            </button>
          </div>
        </>
      )}

      {step === 2 && (
        <>
          <h3>Enable AI prompt inspection?</h3>
          <p>
            Inspection routes pastes and form submissions into AI tools
            through a local DLP pipeline. Matched content is blocked
            before it leaves your browser. You can change this any time
            from Settings.
          </p>
          <label>
            <input
              type="checkbox"
              checked={enableDLP}
              onChange={(e) => setEnableDLP(e.target.checked)}
            />{' '}
            Enable AI prompt inspection
          </label>
          <div className="category-controls" style={{ marginTop: 16 }}>
            <button type="button" onClick={() => setStep(1)}>Back</button>
            <button type="button" className="reset-button" onClick={finish}>
              Finish setup
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/** True when the user has not yet completed the setup wizard. */
export function isSetupPending(): boolean {
  try {
    return window.localStorage.getItem(COMPLETION_KEY) !== 'true';
  } catch {
    return false;
  }
}
