import { useCallback, useEffect, useState } from 'react';
import { agent, ProxyStatus } from '../api/agent';

// ProxySettings drives the "Advanced DLP" wizard. The actual MITM
// listener lives in the Go agent (`/api/proxy/*`); this component
// only orchestrates the lifecycle and shows install instructions.

type Platform = 'macos' | 'windows' | 'linux' | 'unknown';

function detectPlatform(): Platform {
  if (typeof navigator === 'undefined') return 'unknown';
  const p = navigator.platform.toLowerCase();
  if (p.includes('mac')) return 'macos';
  if (p.includes('win')) return 'windows';
  if (p.includes('linux')) return 'linux';
  return 'unknown';
}

function installCommand(platform: Platform, caPath: string): string {
  switch (platform) {
    case 'macos':
      return `sudo scripts/macos/install-ca.sh install "${caPath}"`;
    case 'windows':
      return `powershell.exe -ExecutionPolicy Bypass -File scripts\\windows\\install-ca.ps1 -Install -CaPath "${caPath}"`;
    case 'linux':
      return `sudo scripts/linux/install-ca.sh install "${caPath}"`;
    default:
      return `Install ${caPath} into your platform's root CA trust store.`;
  }
}

function configureCommand(platform: Platform): string {
  switch (platform) {
    case 'macos':
      return 'sudo scripts/macos/configure-proxy.sh apply';
    case 'windows':
      return 'powershell.exe -ExecutionPolicy Bypass -File scripts\\windows\\configure-proxy.ps1 -Apply';
    case 'linux':
      return 'sudo scripts/linux/configure-proxy.sh apply';
    default:
      return 'Configure your OS HTTPS proxy to point at 127.0.0.1:8443.';
  }
}

type Feedback = { kind: 'success' | 'error'; message: string };

export function ProxySettings() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [busy, setBusy] = useState<'enable' | 'disable' | null>(null);
  const platform = detectPlatform();

  const refresh = useCallback(async () => {
    try {
      setStatus(await agent.getProxyStatus());
    } catch (err) {
      // 503 is expected on Phase 1/2/3 agents — show a friendly
      // message rather than the raw error string.
      const msg = String(err);
      if (msg.includes('503')) {
        setStatus(null);
        setFeedback({
          kind: 'error',
          message: 'Proxy is not configured on this agent (Phase 4 build required).',
        });
      } else {
        setFeedback({ kind: 'error', message: msg });
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 5000);
    return () => clearInterval(t);
  }, [refresh]);

  const enable = useCallback(async () => {
    setBusy('enable');
    setFeedback(null);
    try {
      const res = await agent.enableProxy();
      setFeedback({
        kind: 'success',
        message: `CA generated at ${res.ca_cert_path}. Install it, then turn on system proxy.`,
      });
      await refresh();
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setBusy(null);
    }
  }, [refresh]);

  const disable = useCallback(
    async (removeCA: boolean) => {
      setBusy('disable');
      setFeedback(null);
      try {
        const updated = await agent.disableProxy(removeCA);
        setStatus(updated);
        setFeedback({
          kind: 'success',
          message: removeCA
            ? 'Proxy stopped and CA removed from disk. Untrust it in your OS keychain.'
            : 'Proxy stopped. CA cert preserved on disk.',
        });
      } catch (err) {
        setFeedback({ kind: 'error', message: String(err) });
      } finally {
        setBusy(null);
      }
    },
    [],
  );

  const caPath = status?.ca_cert_path ?? '~/.secure-edge/ca.crt';

  return (
    <div className="page">
      <h2>Advanced DLP (Local Proxy)</h2>
      <p className="page-hint">
        Inspect Tier-2 AI traffic (e.g. ChatGPT, Claude) by routing it through
        a local MITM proxy on <code>127.0.0.1:8443</code>. Non-Tier-2 traffic
        is passed through opaquely \u2014 no decryption, no logging.
      </p>

      {feedback && (
        <div className={`feedback feedback-${feedback.kind}`}>{feedback.message}</div>
      )}

      <section className="proxy-status">
        <h3>Status</h3>
        <ul>
          <li>
            Running: <strong>{status?.running ? 'yes' : 'no'}</strong>
          </li>
          <li>
            CA on disk: <strong>{status?.ca_installed ? 'yes' : 'no'}</strong>
          </li>
          <li>
            Listen address: <code>{status?.listen_addr ?? '127.0.0.1:8443'}</code>
          </li>
          <li>
            DLP scans / blocks via proxy:{' '}
            <strong>
              {status?.dlp_scans_total ?? 0} / {status?.dlp_blocks_total ?? 0}
            </strong>
          </li>
        </ul>
      </section>

      <section className="proxy-wizard">
        <h3>Setup</h3>
        <ol>
          <li>
            <button
              type="button"
              onClick={() => void enable()}
              disabled={busy !== null}
            >
              {status?.running ? 'Restart proxy' : 'Generate CA & start proxy'}
            </button>
          </li>
          <li>
            Install the CA cert into your OS trust store:
            <pre><code>{installCommand(platform, caPath)}</code></pre>
          </li>
          <li>
            Point your OS HTTPS proxy at the local listener:
            <pre><code>{configureCommand(platform)}</code></pre>
          </li>
        </ol>
      </section>

      <section className="proxy-shutdown">
        <h3>Disable</h3>
        <div className="proxy-buttons">
          <button
            type="button"
            onClick={() => void disable(false)}
            disabled={busy !== null || !status?.running}
          >
            Stop proxy
          </button>
          <button
            type="button"
            onClick={() => void disable(true)}
            disabled={busy !== null}
          >
            Stop proxy &amp; delete CA
          </button>
        </div>
      </section>
    </div>
  );
}
