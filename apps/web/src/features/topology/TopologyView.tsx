import React, { useState, useEffect, useRef, useMemo } from 'react';
import { TopologyResponse, TopologyNode, TopologyEdge } from '../../types';
import {
  Network,
  ShieldCheck,
  Server,
  Bug,
  Crosshair,
  Globe,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Eye,
  Sliders,
  Filter,
  Layers,
  Sparkles,
} from 'lucide-react';

interface TopologyViewProps {
  topology: TopologyResponse | null;
}

interface NodePosition {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export const TopologyView: React.FC<TopologyViewProps> = ({ topology }) => {
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [showLabels, setShowLabels] = useState(true);
  const [viewMode, setViewMode] = useState<'graph' | 'table'>('graph');

  // Canvas Pan & Zoom state
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);

  // Filtered nodes and edges
  const filteredNodes = useMemo(() => {
    if (!topology) return [];
    if (filterType === 'all') return topology.nodes;
    return topology.nodes.filter((n) => n.type === filterType);
  }, [topology, filterType]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    if (!topology) return [];
    return topology.edges.filter(
      (e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target)
    );
  }, [topology, filteredNodeIds]);

  // Node position map for force simulation
  const [positions, setPositions] = useState<Record<string, NodePosition>>({});

  // Initialize and run force-directed layout simulation
  useEffect(() => {
    if (!topology || topology.nodes.length === 0) return;

    const width = 860;
    const height = 560;
    const center = { x: width / 2, y: height / 2 };

    // Group nodes radially by type for an organized cyber layout
    const typeAngles: Record<string, number> = {
      asset: Math.PI * 0.5,       // Top
      vulnerability: Math.PI * 1.0, // Left
      technique: Math.PI * 1.5,    // Bottom
      apt: 0,                      // Right
      ioc: Math.PI * 0.25,        // Top-Right
    };

    const initialPos: Record<string, NodePosition> = {};
    const radiusByType: Record<string, number> = {
      asset: 130,
      vulnerability: 200,
      technique: 230,
      apt: 240,
      ioc: 250,
    };

    // Distribute nodes with slight jitter
    topology.nodes.forEach((node, i) => {
      const baseAngle = typeAngles[node.type] ?? (i * ((Math.PI * 2) / topology.nodes.length));
      const rad = radiusByType[node.type] ?? 180;
      const spread = ((i % 5) - 2) * 0.35;
      const angle = baseAngle + spread;

      initialPos[node.id] = {
        x: center.x + rad * Math.cos(angle) + (Math.random() - 0.5) * 40,
        y: center.y + rad * Math.sin(angle) + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
      };
    });

    // Run simple force relaxation for 80 steps
    const pos = { ...initialPos };
    const k = 140; // optimal distance
    for (let step = 0; step < 85; step++) {
      // Repulsion between all node pairs
      for (let i = 0; i < topology.nodes.length; i++) {
        for (let j = i + 1; j < topology.nodes.length; j++) {
          const idA = topology.nodes[i].id;
          const idB = topology.nodes[j].id;
          const pA = pos[idA];
          const pB = pos[idB];
          if (!pA || !pB) continue;

          const dx = pA.x - pB.x;
          const dy = pA.y - pB.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 320) {
            const force = (k * k) / dist;
            const fx = (dx / dist) * force * 0.08;
            const fy = (dy / dist) * force * 0.08;
            pA.x += fx;
            pA.y += fy;
            pB.x -= fx;
            pB.y -= fy;
          }
        }
      }

      // Spring attraction along edges
      topology.edges.forEach((edge) => {
        const pSrc = pos[edge.source];
        const pDst = pos[edge.target];
        if (!pSrc || !pDst) return;

        const dx = pDst.x - pSrc.x;
        const dy = pDst.y - pSrc.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist * dist) / k;
        const fx = (dx / dist) * force * 0.035;
        const fy = (dy / dist) * force * 0.035;

        pSrc.x += fx;
        pSrc.y += fy;
        pDst.x -= fx;
        pDst.y -= fy;
      });

      // Gravity to center
      topology.nodes.forEach((node) => {
        const p = pos[node.id];
        if (!p) return;
        p.x += (center.x - p.x) * 0.015;
        p.y += (center.y - p.y) * 0.015;
      });
    }

    setPositions(pos);
    if (!selectedNode && topology.nodes.length > 0) {
      setSelectedNode(topology.nodes[0]);
    }
  }, [topology]);

  // Color schemes for entity types
  const typeConfig: Record<string, { color: string; border: string; glow: string; label: string; icon: any }> = {
    asset: {
      color: '#3B82F6',
      border: '#60A5FA',
      glow: 'rgba(59, 130, 246, 0.4)',
      label: 'Asset',
      icon: Server,
    },
    technique: {
      color: '#A855F7',
      border: '#C084FC',
      glow: 'rgba(168, 85, 247, 0.4)',
      label: 'ATT&CK Technique',
      icon: Crosshair,
    },
    vulnerability: {
      color: '#EF4444',
      border: '#F87171',
      glow: 'rgba(239, 68, 68, 0.4)',
      label: 'Vulnerability (CVE)',
      icon: Bug,
    },
    apt: {
      color: '#F59E0B',
      border: '#FBBF24',
      glow: 'rgba(245, 158, 11, 0.4)',
      label: 'Threat Actor (APT)',
      icon: Globe,
    },
    ioc: {
      color: '#10B981',
      border: '#34D399',
      glow: 'rgba(16, 185, 129, 0.4)',
      label: 'IOC Artifact',
      icon: Globe,
    },
  };

  // Connected node IDs for selected/hovered highlight
  const activeFocusNode = hoveredNode || selectedNode;
  const connectedIds = useMemo(() => {
    if (!activeFocusNode || !topology) return new Set<string>();
    const ids = new Set<string>([activeFocusNode.id]);
    topology.edges.forEach((e) => {
      if (e.source === activeFocusNode.id) ids.add(e.target);
      if (e.target === activeFocusNode.id) ids.add(e.source);
    });
    return ids;
  }, [activeFocusNode, topology]);

  // Mouse pan & drag handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggingNodeId && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - pan.x) / zoom;
      const mouseY = (e.clientY - rect.top - pan.y) / zoom;
      setPositions((prev) => ({
        ...prev,
        [draggingNodeId]: {
          ...prev[draggingNodeId],
          x: mouseX,
          y: mouseY,
        },
      }));
      return;
    }

    if (isPanning) {
      setPan({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    setDraggingNodeId(null);
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    setZoom((prev) => Math.min(2.5, Math.max(0.4, prev * zoomFactor)));
  };

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  if (!topology) {
    return <div className="p-8 text-center text-slate-400">Loading knowledge graph snapshot...</div>;
  }

  const { snapshot_id, nodes, edges } = topology;

  return (
    <div className="space-y-4">
      {/* Top Banner: Semantic Integrity Snapshot */}
      <div className="bg-slate-900/70 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-500/10">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold text-white">
                Cybersecurity &amp; Asset Association Knowledge Graph
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                G* Validated: {snapshot_id}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Closed-world verification (Algoritma 2): Skema $C_S$, Relasi $C_R$, Identitas $C_I$, Freshness $C_T$, dan Provenance $C_P$.
            </p>
          </div>
        </div>

        {/* View Toggle & Entity Counter */}
        <div className="flex items-center space-x-3 text-xs">
          <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setViewMode('graph')}
              className={`px-3 py-1 rounded-md text-[11px] font-semibold transition-all ${
                viewMode === 'graph' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              Interactive Graph
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={`px-3 py-1 rounded-md text-[11px] font-semibold transition-all ${
                viewMode === 'table' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-white'
              }`}
            >
              Entity Ledger
            </button>
          </div>
          <div className="bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-slate-300 font-mono text-[11px]">
            <span className="text-cyan-400 font-bold">{nodes.length}</span> Entities |{' '}
            <span className="text-emerald-400 font-bold">{edges.length}</span> Relations
          </div>
        </div>
      </div>

      {/* Main Container: Interactive Visual Canvas + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 h-[calc(100vh-210px)]">
        {/* Left Visual Graph Canvas */}
        <div className="lg:col-span-8 flex flex-col bg-slate-950 rounded-xl border border-slate-800 overflow-hidden relative shadow-2xl">
          {/* Top Canvas Controls & Filters */}
          <div className="p-3 border-b border-slate-800/80 bg-slate-900/80 backdrop-blur flex flex-wrap items-center justify-between gap-2 z-10">
            {/* Entity Filter Pills */}
            <div className="flex items-center space-x-1">
              <span className="text-[10px] text-slate-400 font-medium uppercase tracking-wider mr-1">Filter:</span>
              {(['all', 'asset', 'vulnerability', 'technique', 'apt', 'ioc'] as const).map((t) => {
                const conf = typeConfig[t];
                const isActive = filterType === t;
                return (
                  <button
                    key={t}
                    onClick={() => setFilterType(t)}
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all ${
                      isActive
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    {t.toUpperCase()}
                  </button>
                );
              })}
            </div>

            {/* Canvas Actions */}
            <div className="flex items-center space-x-1.5">
              <button
                onClick={() => setShowLabels(!showLabels)}
                className={`p-1.5 rounded-lg border text-xs flex items-center gap-1 ${
                  showLabels
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300'
                    : 'bg-slate-900 border-slate-800 text-slate-400'
                }`}
                title="Toggle Edge Labels"
              >
                <Eye className="w-3.5 h-3.5" />
                <span className="text-[10px] font-medium hidden sm:inline">Labels</span>
              </button>

              <button
                onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
                title="Zoom In"
              >
                <ZoomIn className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
                title="Zoom Out"
              >
                <ZoomOut className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={resetView}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
                title="Reset View"
              >
                <Maximize2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* SVG Force-Directed Graph Canvas */}
          {viewMode === 'graph' ? (
            <div
              ref={containerRef}
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onWheel={handleWheel}
              className="flex-1 w-full h-full relative cursor-grab active:cursor-grabbing overflow-hidden select-none bg-[radial-gradient(#1E293B_1px,transparent_1px)] [background-size:24px_24px]"
            >
              <svg className="w-full h-full">
                <defs>
                  {/* Neon Glow Filters */}
                  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3.5" result="coloredBlur" />
                    <feMerge>
                      <feMergeNode in="coloredBlur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>

                  {/* Arrow Marker */}
                  <marker
                    id="arrowhead"
                    markerWidth="8"
                    markerHeight="6"
                    refX="18"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 8 3, 0 6" fill="#475569" />
                  </marker>
                  <marker
                    id="arrowhead-active"
                    markerWidth="9"
                    markerHeight="7"
                    refX="20"
                    refY="3.5"
                    orient="auto"
                  >
                    <polygon points="0 0, 9 3.5, 0 7" fill="#06B6D4" />
                  </marker>
                </defs>

                <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
                  {/* EDGES */}
                  {filteredEdges.map((edge, idx) => {
                    const src = positions[edge.source];
                    const dst = positions[edge.target];
                    if (!src || !dst) return null;

                    const isEdgeActive =
                      activeFocusNode &&
                      (edge.source === activeFocusNode.id || edge.target === activeFocusNode.id);
                    const isFaded = activeFocusNode && !isEdgeActive;

                    const midX = (src.x + dst.x) / 2;
                    const midY = (src.y + dst.y) / 2;

                    return (
                      <g key={idx} className="transition-opacity duration-300">
                        {/* Connecting Line */}
                        <line
                          x1={src.x}
                          y1={src.y}
                          x2={dst.x}
                          y2={dst.y}
                          stroke={isEdgeActive ? '#06B6D4' : '#334155'}
                          strokeWidth={isEdgeActive ? 2.5 : 1.2}
                          strokeDasharray={edge.label.includes('USES') ? '4,3' : undefined}
                          opacity={isFaded ? 0.15 : 0.85}
                          markerEnd={isEdgeActive ? 'url(#arrowhead-active)' : 'url(#arrowhead)'}
                        />

                        {/* Edge Label Badge */}
                        {showLabels && !isFaded && (
                          <g transform={`translate(${midX}, ${midY})`}>
                            <rect
                              x="-38"
                              y="-8"
                              width="76"
                              height="16"
                              rx="4"
                              fill="#0B0F19"
                              stroke={isEdgeActive ? '#06B6D4' : '#1E293B'}
                              strokeWidth="1"
                              opacity="0.9"
                            />
                            <text
                              x="0"
                              y="3"
                              textAnchor="middle"
                              fontSize="8"
                              fontWeight="600"
                              fontFamily="monospace"
                              fill={isEdgeActive ? '#22D3EE' : '#94A3B8'}
                            >
                              {edge.label}
                            </text>
                          </g>
                        )}
                      </g>
                    );
                  })}

                  {/* NODES */}
                  {filteredNodes.map((node) => {
                    const pos = positions[node.id];
                    if (!pos) return null;

                    const cfg = typeConfig[node.type] || typeConfig.asset;
                    const isSelected = selectedNode?.id === node.id;
                    const isHovered = hoveredNode?.id === node.id;
                    const isConnected = connectedIds.has(node.id);
                    const isFaded = activeFocusNode && !isConnected;

                    const radius = isSelected ? 24 : 19;

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedNode(node);
                        }}
                        onMouseEnter={() => setHoveredNode(node)}
                        onMouseLeave={() => setHoveredNode(null)}
                        onMouseDown={(e) => {
                          e.stopPropagation();
                          setDraggingNodeId(node.id);
                        }}
                        className="cursor-pointer transition-opacity duration-300"
                        opacity={isFaded ? 0.2 : 1}
                      >
                        {/* Outer Glow Ring on Selected/Hover */}
                        {(isSelected || isHovered) && (
                          <circle
                            r={radius + 8}
                            fill="none"
                            stroke={cfg.border}
                            strokeWidth="2"
                            strokeDasharray="4,4"
                            className="animate-spin"
                            style={{ animationDuration: '8s' }}
                          />
                        )}

                        {/* Node Bubble */}
                        <circle
                          r={radius}
                          fill="#0F172A"
                          stroke={isSelected ? '#38BDF8' : cfg.border}
                          strokeWidth={isSelected ? 3 : 2}
                          filter={isSelected ? 'url(#glow)' : undefined}
                        />

                        {/* Node Inner Icon / Initial */}
                        <text
                          textAnchor="middle"
                          dy="4"
                          fontSize="10"
                          fontWeight="bold"
                          fontFamily="sans-serif"
                          fill={cfg.color}
                          pointerEvents="none"
                        >
                          {node.type === 'asset'
                            ? '💻'
                            : node.type === 'vulnerability'
                            ? '🛡️'
                            : node.type === 'technique'
                            ? '🎯'
                            : node.type === 'apt'
                            ? '🕵️'
                            : '⚡'}
                        </text>

                        {/* Node Name Label */}
                        <text
                          y={radius + 14}
                          textAnchor="middle"
                          fontSize="9.5"
                          fontWeight="600"
                          fontFamily="'Plus Jakarta Sans', sans-serif"
                          fill={isSelected ? '#38BDF8' : '#F1F5F9'}
                          pointerEvents="none"
                          className="drop-shadow-md"
                        >
                          {node.label.length > 20 ? node.label.slice(0, 18) + '...' : node.label}
                        </text>

                        {/* Node Type Subtitle */}
                        <text
                          y={radius + 24}
                          textAnchor="middle"
                          fontSize="7.5"
                          fontFamily="monospace"
                          fill="#64748B"
                          pointerEvents="none"
                        >
                          {node.type.toUpperCase()}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>

              {/* Watermark Helper in bottom corner */}
              <div className="absolute bottom-3 left-3 bg-slate-900/80 backdrop-blur px-2.5 py-1.5 rounded-lg border border-slate-800 text-[10px] text-slate-400 font-mono space-y-0.5 pointer-events-none">
                <div>🖱️ Scroll: Zoom in/out | Drag: Pan Canvas</div>
                <div>🔵 Drag node to pin position | Click to inspect</div>
              </div>
            </div>
          ) : (
            /* Alternate Table / Ledger View */
            <div className="flex-1 overflow-y-auto p-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {filteredNodes.map((node) => {
                  const cfg = typeConfig[node.type];
                  const Icon = cfg.icon;
                  const isSelected = selectedNode?.id === node.id;
                  return (
                    <div
                      key={node.id}
                      onClick={() => setSelectedNode(node)}
                      className={`p-3 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-cyan-500/15 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                          : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2.5">
                          <div
                            className="p-1.5 rounded-md"
                            style={{ backgroundColor: `${cfg.color}20`, color: cfg.color }}
                          >
                            <Icon className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="text-xs font-bold text-white">{node.label}</div>
                            <div className="text-[10px] text-slate-400 font-mono">ID: {node.id}</div>
                          </div>
                        </div>
                        <span
                          className="text-[10px] font-mono uppercase px-2 py-0.5 rounded border"
                          style={{
                            backgroundColor: `${cfg.color}15`,
                            color: cfg.color,
                            borderColor: `${cfg.color}40`,
                          }}
                        >
                          {node.type}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Right Detail & Relationship Inspector */}
        <div className="lg:col-span-4 flex flex-col bg-slate-900/70 rounded-xl border border-slate-800 overflow-hidden">
          <div className="p-4 border-b border-slate-800 bg-slate-950/70 flex justify-between items-center">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Graph Entity &amp; Provenance Inspector
            </h3>
            {selectedNode && (
              <span className="text-[10px] font-mono text-cyan-400 uppercase">
                {selectedNode.type}
              </span>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {selectedNode ? (
              <div className="space-y-4">
                {/* Node Banner Card */}
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 relative overflow-hidden">
                  <div
                    className="absolute top-0 left-0 w-1.5 h-full"
                    style={{ backgroundColor: typeConfig[selectedNode.type]?.color || '#3B82F6' }}
                  ></div>
                  <div className="text-[10px] text-slate-400 font-mono">ID: {selectedNode.id}</div>
                  <h4 className="text-sm font-bold text-white">{selectedNode.label}</h4>

                  {/* Attributes Pills */}
                  <div className="flex flex-wrap gap-2 pt-1 text-xs">
                    {selectedNode.criticality && (
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40">
                        Criticality: {selectedNode.criticality}
                      </span>
                    )}
                    {selectedNode.cvss && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40 font-bold">
                        CVSS: {selectedNode.cvss}
                      </span>
                    )}
                    {selectedNode.tactic && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                        Tactic: {selectedNode.tactic}
                      </span>
                    )}
                  </div>
                </div>

                {/* Graph Associations (In & Out edges) */}
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-300 flex items-center justify-between">
                    <span>Connected Relations ({connectedIds.size - 1})</span>
                    <span className="text-[10px] font-mono text-slate-500">Cypher 1-Hop</span>
                  </div>

                  <div className="space-y-2">
                    {edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((e, idx) => {
                        const isOut = e.source === selectedNode.id;
                        const otherNodeId = isOut ? e.target : e.source;
                        const otherNode = nodes.find((n) => n.id === otherNodeId);

                        return (
                          <div
                            key={idx}
                            onClick={() => otherNode && setSelectedNode(otherNode)}
                            className="p-2.5 rounded-lg bg-slate-950 hover:bg-slate-900 border border-slate-800/80 cursor-pointer transition-colors space-y-1.5"
                          >
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="text-slate-400 font-mono">
                                {isOut ? 'Outgoing Target' : 'Incoming Source'}
                              </span>
                              <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono font-bold text-[9px]">
                                {e.label}
                              </span>
                            </div>
                            <div className="text-xs font-semibold text-white flex items-center justify-between">
                              <span>{otherNode?.label || otherNodeId}</span>
                              <span className="text-[10px] text-slate-400 font-mono uppercase">
                                {otherNode?.type}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>

                {/* Semantic Integrity Stamp */}
                <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-[11px] text-slate-400 space-y-1">
                  <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-xs">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Semantic Integrity Validated</span>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-relaxed font-mono">
                    Entity verified against canonical registry. No unresolved identity conflicts or expired TTL detected.
                  </p>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs">
                Click any node on the graph canvas to inspect its relationships and ATT&CK parameters.
              </div>
            )}
          </div>

          {/* Footer note */}
          <div className="p-3 border-t border-slate-800 bg-slate-950/60 text-[10px] text-slate-500 text-center font-mono">
            Daily Knowledge Sync at 01:00 Asia/Jakarta | MITRE ATT&CK v15
          </div>
        </div>
      </div>
    </div>
  );
};
