import React from 'react';
import { CriterionScore } from '../types';

interface AHPScoreRadarProps {
  criteria: CriterionScore[];
  finalScore: number;
}

export const AHPScoreRadar: React.FC<AHPScoreRadarProps> = ({ criteria, finalScore }) => {
  const size = 260;
  const center = size / 2;
  const radius = size * 0.38;
  const numAxes = criteria.length || 6;

  // Calculate polygon coordinates for normalized scores [0, 1]
  const points = criteria.map((c, i) => {
    const angle = (Math.PI * 2 / numAxes) * i - Math.PI / 2;
    // Normalized score of criterion C_i
    const val = Math.min(1.0, Math.max(0.05, c.score));
    const r = radius * val;
    const x = center + r * Math.cos(angle);
    const y = center + r * Math.sin(angle);
    return { x, y, label: c.criterion_name, score: c.score, weight: c.criterion_weight, angle };
  });

  const polygonPoints = points.map(p => `${p.x},${p.y}`).join(' ');

  // Background concentric web rings (0.25, 0.5, 0.75, 1.0)
  const levels = [0.25, 0.5, 0.75, 1.0];

  return (
    <div className="flex flex-col items-center justify-center p-3 bg-slate-900/60 rounded-xl border border-slate-800">
      <div className="relative">
        <svg width={size} height={size} className="overflow-visible">
          {/* Background concentric polygons */}
          {levels.map((lvl, idx) => {
            const levelPoints = Array.from({ length: numAxes }).map((_, i) => {
              const angle = (Math.PI * 2 / numAxes) * i - Math.PI / 2;
              const r = radius * lvl;
              return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
            }).join(' ');

            return (
              <polygon
                key={idx}
                points={levelPoints}
                fill="none"
                stroke="#1E293B"
                strokeWidth="1"
                strokeDasharray={lvl < 1.0 ? "2,2" : undefined}
              />
            );
          })}

          {/* Radial Axis lines */}
          {Array.from({ length: numAxes }).map((_, i) => {
            const angle = (Math.PI * 2 / numAxes) * i - Math.PI / 2;
            const x = center + radius * Math.cos(angle);
            const y = center + radius * Math.sin(angle);
            return (
              <line
                key={i}
                x1={center}
                y1={center}
                x2={x}
                y2={y}
                stroke="#334155"
                strokeWidth="1"
              />
            );
          })}

          {/* Filled radar polygon */}
          <polygon
            points={polygonPoints}
            fill={finalScore >= 80 ? 'rgba(239, 68, 68, 0.25)' : finalScore >= 60 ? 'rgba(245, 158, 11, 0.25)' : 'rgba(59, 130, 246, 0.25)'}
            stroke={finalScore >= 80 ? '#EF4444' : finalScore >= 60 ? '#F59E0B' : '#3B82F6'}
            strokeWidth="2.5"
            className="transition-all duration-500"
          />

          {/* Points on polygon */}
          {points.map((p, i) => (
            <circle
              key={i}
              cx={p.x}
              cy={p.y}
              r="4.5"
              fill={finalScore >= 80 ? '#EF4444' : finalScore >= 60 ? '#F59E0B' : '#3B82F6'}
              stroke="#0B0F19"
              strokeWidth="2"
            />
          ))}
        </svg>

        {/* Center score badge */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className={`text-2xl font-bold font-mono ${
            finalScore >= 80 ? 'text-red-400' : finalScore >= 60 ? 'text-amber-400' : 'text-emerald-400'
          }`}>
            {finalScore.toFixed(1)}
          </span>
          <span className="text-[10px] text-slate-400 uppercase tracking-widest">AHP Risk</span>
        </div>
      </div>

      {/* Criteria labels below radar */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2 text-xs w-full">
        {criteria.map((c, i) => (
          <div key={i} className="flex justify-between items-center text-slate-300 py-0.5 border-b border-slate-800/40">
            <span className="truncate max-w-[110px]" title={c.criterion_name}>
              {c.criterion_name.replace("Attack ", "").replace("Threat ", "")}
            </span>
            <span className="font-mono text-cyan-400 font-semibold">
              {(c.score * 100).toFixed(0)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
