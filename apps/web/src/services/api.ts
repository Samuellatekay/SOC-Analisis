import {
  EnrichedAlert,
  Case,
  CaseStatus,
  AnalyticsOverview,
  TopologyResponse,
  RiskLevel,
  SeverityLevel,
} from '../types';

const API_BASE = '/api/v1';

export const socApi = {
  async getAlerts(params?: {
    risk_level?: RiskLevel;
    severity?: SeverityLevel;
    source?: string;
    search?: string;
    include_noise?: boolean;
    limit?: number;
  }): Promise<EnrichedAlert[]> {
    const query = new URLSearchParams();
    if (params?.risk_level) query.append('risk_level', params.risk_level);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.source) query.append('source', params.source);
    if (params?.search) query.append('search', params.search);
    if (params?.include_noise !== undefined) query.append('include_noise', String(params.include_noise));
    if (params?.limit) query.append('limit', String(params.limit));

    const res = await fetch(`${API_BASE}/alerts?${query.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch alerts');
    return res.json();
  },

  async getAlertDetail(eventId: string): Promise<EnrichedAlert> {
    const res = await fetch(`${API_BASE}/alerts/${eventId}`);
    if (!res.ok) throw new Error(`Failed to fetch alert ${eventId}`);
    return res.json();
  },

  async simulateAlert(payload: { raw_alert: any; context?: any }): Promise<EnrichedAlert> {
    const res = await fetch(`${API_BASE}/alerts/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to simulate alert ingestion');
    return res.json();
  },

  async ingestWazuh(payload: any): Promise<EnrichedAlert[]> {
    const res = await fetch(`${API_BASE}/alerts/ingest/wazuh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to ingest Wazuh alert');
    return res.json();
  },

  async getCases(status?: CaseStatus): Promise<Case[]> {
    const query = status ? `?status=${status}` : '';
    const res = await fetch(`${API_BASE}/cases${query}`);
    if (!res.ok) throw new Error('Failed to fetch cases');
    return res.json();
  },

  async getCaseDetail(caseId: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases/${caseId}`);
    if (!res.ok) throw new Error(`Failed to fetch case ${caseId}`);
    return res.json();
  },

  async createCase(payload: {
    title: string;
    description: string;
    severity?: SeverityLevel;
    priority?: RiskLevel;
    assigned_to?: string;
    linked_alert_ids?: string[];
    tags?: string[];
  }): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error('Failed to create case');
    return res.json();
  },

  async updateCaseStatus(caseId: string, status: CaseStatus, comment?: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, comment }),
    });
    if (!res.ok) throw new Error('Failed to update case status');
    return res.json();
  },

  async addCaseNote(caseId: string, author: string, content: string): Promise<Case> {
    const res = await fetch(`${API_BASE}/cases/${caseId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author, content }),
    });
    if (!res.ok) throw new Error('Failed to add case note');
    return res.json();
  },

  async getAnalytics(): Promise<AnalyticsOverview> {
    const res = await fetch(`${API_BASE}/analytics/overview`);
    if (!res.ok) throw new Error('Failed to fetch analytics');
    return res.json();
  },

  async getTopology(): Promise<TopologyResponse> {
    const res = await fetch(`${API_BASE}/graph/topology`);
    if (!res.ok) throw new Error('Failed to fetch topology');
    return res.json();
  },
};
