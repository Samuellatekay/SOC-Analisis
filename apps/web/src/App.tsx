import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar, NavTab } from './components/Sidebar';
import { DashboardView } from './features/dashboard/DashboardView';
import { AlertsView } from './features/alerts/AlertsView';
import { CasesView } from './features/cases/CasesView';
import { TopologyView } from './features/topology/TopologyView';
import { SimulatorModal } from './features/simulator/SimulatorModal';
import { socApi } from './services/api';
import { EnrichedAlert, Case, CaseStatus, AnalyticsOverview, TopologyResponse, RiskLevel } from './types';

export function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [alerts, setAlerts] = useState<EnrichedAlert[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsOverview | null>(null);
  const [topology, setTopology] = useState<TopologyResponse | null>(null);

  const [selectedAlert, setSelectedAlert] = useState<EnrichedAlert | null>(null);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);

  // Filters for alerts
  const [filterRisk, setFilterRisk] = useState<RiskLevel | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showNoise, setShowNoise] = useState(false);

  // Initial data loading
  const loadData = async () => {
    try {
      const [fetchedAlerts, fetchedCases, fetchedAnalytics, fetchedTopology] = await Promise.all([
        socApi.getAlerts({
          risk_level: filterRisk !== 'all' ? filterRisk : undefined,
          search: searchQuery.trim() || undefined,
          include_noise: showNoise,
        }),
        socApi.getCases(),
        socApi.getAnalytics(),
        socApi.getTopology(),
      ]);

      setAlerts(fetchedAlerts);
      setCases(fetchedCases);
      setAnalytics(fetchedAnalytics);
      setTopology(fetchedTopology);
    } catch (err) {
      console.error('Error fetching data from SOC API:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000); // 10s auto refresh
    return () => clearInterval(interval);
  }, [filterRisk, searchQuery, showNoise]);

  const handleSimulateAlert = async (payload: { raw_alert: any; context?: any }) => {
    const newAlert = await socApi.simulateAlert(payload);
    await loadData();
    setSelectedAlert(newAlert);
  };

  const handleCreateCaseFromAlert = async (alert: EnrichedAlert) => {
    const newCase = await socApi.createCase({
      title: `Incident: ${alert.alert_type} on ${alert.dst_ip}`,
      description: `Escalated from alert ${alert.event_id}. Source: ${alert.src_ip}, Severity: ${alert.severity.toUpperCase()}, AHP Risk: ${alert.risk_score.toFixed(1)}.`,
      severity: alert.severity,
      priority: alert.risk_level,
      assigned_to: 'Senior Analyst (Tier 3)',
      linked_alert_ids: [alert.event_id],
      tags: [alert.alert_type, alert.source],
    });

    await loadData();
    setCurrentTab('cases');
  };

  const handleUpdateCaseStatus = async (caseId: string, status: CaseStatus, comment?: string) => {
    await socApi.updateCaseStatus(caseId, status, comment);
    await loadData();
  };

  const handleAddCaseNote = async (caseId: string, author: string, content: string) => {
    await socApi.addCaseNote(caseId, author, content);
    await loadData();
  };

  const unreadHigh = alerts.filter((a) => a.risk_level === 'high' && !a.filtered_as_noise).length;

  return (
    <div className="min-h-screen bg-[#0B0F19] flex flex-col text-slate-100">
      <Header
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        activeCasesCount={cases.filter((c) => c.status !== 'closed').length}
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          unreadHighAlerts={unreadHigh}
        />

        <main className="flex-1 overflow-y-auto p-6">
          {currentTab === 'dashboard' && (
            <DashboardView
              analytics={analytics}
              onNavigateToAlerts={() => setCurrentTab('alerts')}
            />
          )}

          {currentTab === 'alerts' && (
            <AlertsView
              alerts={alerts}
              selectedAlert={selectedAlert}
              onSelectAlert={setSelectedAlert}
              onCloseDrawer={() => setSelectedAlert(null)}
              onCreateCaseFromAlert={handleCreateCaseFromAlert}
              filterRisk={filterRisk}
              onFilterRiskChange={setFilterRisk}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              showNoise={showNoise}
              onToggleNoise={setShowNoise}
            />
          )}

          {currentTab === 'cases' && (
            <CasesView
              cases={cases}
              onUpdateStatus={handleUpdateCaseStatus}
              onAddNote={handleAddCaseNote}
            />
          )}

          {currentTab === 'topology' && <TopologyView topology={topology} />}
        </main>
      </div>

      <SimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onSimulate={handleSimulateAlert}
      />
    </div>
  );
}

export default App;
