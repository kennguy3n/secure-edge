// Type augmentation for the preload bridge exposed on `window.secureEdge`.

export type SecureEdgeView = 'status' | 'settings' | 'proxy' | 'rules' | 'setup';

export interface SecureEdgeBridge {
  getAgentBase(): Promise<string>;
  // getAPIToken resolves the per-install API capability token from
  // the on-disk token file (work item A2), or null when the file is
  // absent / empty. The renderer attaches the value as a Bearer
  // header on every fetch to the local agent.
  getAPIToken(): Promise<string | null>;
  onNavigate(cb: (view: SecureEdgeView) => void): () => void;
}

declare global {
  interface Window {
    secureEdge?: SecureEdgeBridge;
  }
}

export {};
