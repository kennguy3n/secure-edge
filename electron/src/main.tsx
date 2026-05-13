import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ProxySettings } from './pages/ProxySettings';
import { Rules } from './pages/Rules';
import { Settings } from './pages/Settings';
import { Setup, isSetupPending } from './pages/Setup';
import { Status } from './pages/Status';
import './styles.css';

type View = 'status' | 'settings' | 'proxy' | 'rules';

const TABS: ReadonlyArray<{ id: View; label: string }> = [
  { id: 'status', label: 'Status' },
  { id: 'rules', label: 'Rules' },
  { id: 'settings', label: 'Settings' },
  { id: 'proxy', label: 'Proxy' },
];

function parseHash(): View {
  const h = window.location.hash.replace(/^#/, '');
  if (h === 'settings') return 'settings';
  if (h === 'proxy') return 'proxy';
  if (h === 'rules') return 'rules';
  return 'status';
}

function renderView(view: View) {
  switch (view) {
    case 'settings':
      return <Settings />;
    case 'proxy':
      return <ProxySettings />;
    case 'rules':
      return <Rules />;
    default:
      return <Status />;
  }
}

function App() {
  const [view, setView] = useState<View>(parseHash);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  // Show the first-run setup wizard until the user explicitly
  // completes it. Completion writes to localStorage, so subsequent
  // launches skip straight to the regular tab view.
  const [showSetup, setShowSetup] = useState<boolean>(isSetupPending);

  useEffect(() => {
    const onHashChange = () => setView(parseHash());
    window.addEventListener('hashchange', onHashChange);
    const off = window.secureEdge?.onNavigate?.((v) => {
      // Only navigate to a recognised tab view; ignore other values
      // (e.g. 'setup') so the tablist stays consistent.
      if (v === 'status' || v === 'settings' || v === 'proxy' || v === 'rules') {
        setView(v);
      }
    });
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      off?.();
    };
  }, []);

  if (showSetup) {
    return <Setup onComplete={() => setShowSetup(false)} />;
  }

  const onTabKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    let nextIdx = idx;
    switch (e.key) {
      case 'ArrowRight':
        nextIdx = (idx + 1) % TABS.length;
        break;
      case 'ArrowLeft':
        nextIdx = (idx - 1 + TABS.length) % TABS.length;
        break;
      case 'Home':
        nextIdx = 0;
        break;
      case 'End':
        nextIdx = TABS.length - 1;
        break;
      default:
        return;
    }
    e.preventDefault();
    const next = TABS[nextIdx];
    window.location.hash = next.id;
    tabRefs.current[nextIdx]?.focus();
  };

  return (
    <div className="app">
      <nav className="topbar" role="tablist" aria-label="Secure Edge sections">
        {TABS.map((tab, idx) => {
          const selected = view === tab.id;
          return (
            <button
              key={tab.id}
              ref={(el) => {
                tabRefs.current[idx] = el;
              }}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-controls="tabpanel-main"
              aria-selected={selected}
              tabIndex={selected ? 0 : -1}
              className={selected ? 'active' : ''}
              onClick={() => (window.location.hash = tab.id)}
              onKeyDown={(e) => onTabKeyDown(e, idx)}
            >
              {tab.label}
            </button>
          );
        })}
      </nav>
      <div
        id="tabpanel-main"
        role="tabpanel"
        aria-labelledby={`tab-${view}`}
      >
        {renderView(view)}
      </div>
    </div>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<React.StrictMode><App /></React.StrictMode>);
