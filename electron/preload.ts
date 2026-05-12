// Secure bridge between the renderer and the main process. Only the
// minimum surface the renderer needs is exposed.

import { contextBridge, ipcRenderer } from 'electron';

export interface SecureEdgeBridge {
  getAgentBase(): Promise<string>;
  onNavigate(cb: (view: 'status' | 'settings') => void): () => void;
}

const bridge: SecureEdgeBridge = {
  getAgentBase: () => ipcRenderer.invoke('secure-edge:get-agent-base'),
  onNavigate: (cb) => {
    const listener = (_event: unknown, view: 'status' | 'settings') => cb(view);
    ipcRenderer.on('navigate', listener);
    return () => ipcRenderer.removeListener('navigate', listener);
  },
};

contextBridge.exposeInMainWorld('secureEdge', bridge);

declare global {
  interface Window {
    secureEdge: SecureEdgeBridge;
  }
}
