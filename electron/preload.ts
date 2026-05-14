// Secure bridge between the renderer and the main process. Only the
// minimum surface the renderer needs is exposed.

import { contextBridge, ipcRenderer } from 'electron';

export type SecureEdgeView = 'status' | 'settings' | 'proxy';

export interface SecureEdgeBridge {
  getAgentBase(): Promise<string>;
  // getAPIToken returns the per-install API capability token the
  // local agent persists at its api_token_path (work item A2), or
  // null when the file does not exist / the feature is disabled.
  // The renderer attaches the value as an "Authorization: Bearer
  // <token>" header on every fetch to the agent; a null result
  // means "no token configured", which is the backwards-compatible
  // path against agents that have not enabled the middleware yet.
  getAPIToken(): Promise<string | null>;
  onNavigate(cb: (view: SecureEdgeView) => void): () => void;
}

const bridge: SecureEdgeBridge = {
  getAgentBase: () => ipcRenderer.invoke('secure-edge:get-agent-base'),
  getAPIToken: () => ipcRenderer.invoke('secure-edge:get-api-token'),
  onNavigate: (cb) => {
    const listener = (_event: unknown, view: SecureEdgeView) => cb(view);
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
