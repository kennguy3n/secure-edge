import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Settings } from './pages/Settings';
import { Status } from './pages/Status';
import './styles.css';

type View = 'status' | 'settings';

function parseHash(): View {
  const h = window.location.hash.replace(/^#/, '');
  return h === 'settings' ? 'settings' : 'status';
}

function App() {
  const [view, setView] = useState<View>(parseHash);

  useEffect(() => {
    const onHashChange = () => setView(parseHash());
    window.addEventListener('hashchange', onHashChange);
    const off = window.secureEdge?.onNavigate?.((v) => setView(v));
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      off?.();
    };
  }, []);

  return (
    <div className="app">
      <nav className="topbar">
        <button
          type="button"
          className={view === 'status' ? 'active' : ''}
          onClick={() => (window.location.hash = 'status')}
        >
          Status
        </button>
        <button
          type="button"
          className={view === 'settings' ? 'active' : ''}
          onClick={() => (window.location.hash = 'settings')}
        >
          Settings
        </button>
      </nav>
      {view === 'status' ? <Status /> : <Settings />}
    </div>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<React.StrictMode><App /></React.StrictMode>);
