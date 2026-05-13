// Type augmentation for the preload bridge exposed on `window.secureEdge`.

export type SecureEdgeView = 'status' | 'settings' | 'proxy';

export interface SecureEdgeBridge {
  getAgentBase(): Promise<string>;
  onNavigate(cb: (view: SecureEdgeView) => void): () => void;
}

declare global {
  interface Window {
    secureEdge?: SecureEdgeBridge;
  }
}

export {};
