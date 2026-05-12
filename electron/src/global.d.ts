// Type augmentation for the preload bridge exposed on `window.secureEdge`.

export interface SecureEdgeBridge {
  getAgentBase(): Promise<string>;
  onNavigate(cb: (view: 'status' | 'settings') => void): () => void;
}

declare global {
  interface Window {
    secureEdge?: SecureEdgeBridge;
  }
}

export {};
