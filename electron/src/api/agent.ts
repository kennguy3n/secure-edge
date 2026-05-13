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
  tamper_detections_total?: number;
}

export interface DLPConfig {
  threshold_critical: number;
  threshold_high: number;
  threshold_medium: number;
  threshold_low: number;
  hotword_boost: number;
  entropy_boost: number;
  entropy_penalty: number;
  exclusion_penalty: number;
  multi_match_boost: number;
}

export interface TamperStatus {
  dns_ok: boolean;
  proxy_ok: boolean;
  last_check: string;
  detections_total: number;
}

export interface RuleOverrideLists {
  allow: string[];
  block: string[];
}

export interface AgentProfile {
  name: string;
  version: string;
  managed: boolean;
  categories?: Record<string, PolicyAction>;
}

export interface AgentStatus {
  status: string;
  uptime: string;
  version: string;
}

// ProxyStatus mirrors agent.api.ProxyStatus on the wire.
export interface ProxyStatus {
  running: boolean;
  ca_installed: boolean;
  proxy_configured: boolean;
  listen_addr: string;
  ca_cert_path?: string;
  dlp_scans_total: number;
  dlp_blocks_total: number;
}

export interface ProxyEnableResponse {
  ca_cert_path: string;
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
  async getProxyStatus(): Promise<ProxyStatus> {
    return http<ProxyStatus>('/api/proxy/status');
  },
  async enableProxy(): Promise<ProxyEnableResponse> {
    return http<ProxyEnableResponse>('/api/proxy/enable', { method: 'POST' });
  },
  async disableProxy(removeCA: boolean): Promise<ProxyStatus> {
    return http<ProxyStatus>('/api/proxy/disable', {
      method: 'POST',
      body: JSON.stringify({ remove_ca: removeCA }),
    });
  },

  // Phase 5: DLP scoring threshold tuning.
  async getDLPConfig(): Promise<DLPConfig> {
    return http<DLPConfig>('/api/dlp/config');
  },
  async updateDLPConfig(cfg: DLPConfig): Promise<DLPConfig> {
    return http<DLPConfig>('/api/dlp/config', {
      method: 'PUT',
      body: JSON.stringify(cfg),
    });
  },

  // Phase 5: tamper detection.
  async getTamperStatus(): Promise<TamperStatus> {
    return http<TamperStatus>('/api/tamper/status');
  },

  // Phase 5: enterprise profile.
  async getProfile(): Promise<AgentProfile | null> {
    try {
      return await http<AgentProfile>('/api/profile');
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Agent 404')) {
        return null;
      }
      throw err;
    }
  },

  // Phase 5: admin allow/block override list.
  async listOverrides(): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>('/api/rules/override');
  },
  async addOverride(domain: string, list: 'allow' | 'block'): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>('/api/rules/override', {
      method: 'POST',
      body: JSON.stringify({ domain, list }),
    });
  },
  async removeOverride(domain: string): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>(`/api/rules/override/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
  },
};
