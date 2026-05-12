// Thin HTTP client for the Go agent on localhost. Works both inside
// Electron (uses the secure preload bridge) and in a vanilla browser
// dev environment (falls back to a sensible default URL).

export type PolicyAction = 'allow' | 'allow_with_dlp' | 'deny';

export interface CategoryPolicy {
  category: string;
  action: PolicyAction;
}

export interface Stats {
  dns_queries_total: number;
  dns_blocks_total: number;
  dlp_scans_total: number;
  dlp_blocks_total: number;
}

export interface AgentStatus {
  status: string;
  uptime: string;
  version: string;
}

const DEFAULT_BASE =
  (typeof window !== 'undefined' && (window as { __SECURE_EDGE_AGENT__?: string }).__SECURE_EDGE_AGENT__) ||
  'http://127.0.0.1:8080';

async function baseURL(): Promise<string> {
  if (typeof window !== 'undefined' && window.secureEdge?.getAgentBase) {
    try {
      return await window.secureEdge.getAgentBase();
    } catch {
      /* fall through */
    }
  }
  return DEFAULT_BASE;
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${await baseURL()}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Agent ${res.status}: ${text || res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const agent = {
  async getStatus(): Promise<AgentStatus> {
    return http<AgentStatus>('/api/status');
  },
  async getPolicies(): Promise<CategoryPolicy[]> {
    return http<CategoryPolicy[]>('/api/policies');
  },
  async updatePolicy(category: string, action: PolicyAction): Promise<CategoryPolicy> {
    return http<CategoryPolicy>(
      `/api/policies/${encodeURIComponent(category)}`,
      { method: 'PUT', body: JSON.stringify({ action }) },
    );
  },
  async getStats(): Promise<Stats> {
    return http<Stats>('/api/stats');
  },
  async resetStats(): Promise<Stats> {
    return http<Stats>('/api/stats/reset', { method: 'POST' });
  },
};
