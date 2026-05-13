import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ProxySettings } from './pages/ProxySettings';
import { Settings } from './pages/Settings';
import { Status } from './pages/Status';
import './styles.css';

type View = 'status' | 'settings' | 'proxy';

const TABS: ReadonlyArray<{ id: View; label: string }> = [
  { id: 'status', label: 'Status' },
  { id: 'settings', label: 'Settings' },
  { id: 'proxy', label: 'Proxy' },
];

function parseHash(): View {
  const h = window.location.hash.replace(/^#/, '');
  if (h === 'settings') return 'settings';
  if (h === 'proxy') return 'proxy';
  return 'status';
}

function renderView(view: View) {
  switch (view) {
    case 'settings':
      return <Settings />;
    case 'proxy':
      return <ProxySettings />;
    default:
      return <Status />;
  }
}

function App() {
  const [view, setView] = useState<View>(parseHash);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    const onHashChange = () => setView(parseHash());
    window.addEventListener('hashchange', onHashChange);
    const off = window.secureEdge?.onNavigate?.((v) => setView(v));
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      off?.();
    };
  }, []);

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
