import React from 'react';

interface TimeSeriesChartProps {
  data: number[];
  isPeriodic?: boolean;
  periodHours?: number;
  height?: number;
}

export const TimeSeriesChart: React.FC<TimeSeriesChartProps> = ({
  data,
  isPeriodic = false,
  periodHours = 24,
  height = 90,
}) => {
  if (!data || data.length === 0) {
    return <div className="text-xs text-slate-500 py-4 text-center">No time-series data</div>;
  }

  const width = 360;
  const padding = 10;
  const maxVal = Math.max(...data, 1);
  const minVal = Math.min(...data, 0);
  const range = maxVal - minVal || 1;

  const points = data.map((val, idx) => {
    const x = padding + (idx / (data.length - 1)) * (width - 2 * padding);
    const y = height - padding - ((val - minVal) / range) * (height - 2 * padding);
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
      <div className="flex justify-between items-center mb-1 text-[11px] text-slate-400">
        <span className="font-mono">Triplet Time-Series $x_g(h)$ ({data.length}h)</span>
        {isPeriodic && (
          <span className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-1.5 py-0.5 rounded text-[10px]">
            Periodic Cycle: ~{periodHours}h
          </span>
        )}
      </div>

      <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-20 overflow-visible">
        {/* Baseline grid */}
        <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#1E293B" strokeWidth="1" />
        <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#1E293B" strokeWidth="1" strokeDasharray="3,3" />

        {/* Path line */}
        <polyline
          fill="none"
          stroke={isPeriodic ? '#06B6D4' : '#F59E0B'}
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          points={points}
        />
      </svg>
      <div className="flex justify-between text-[10px] text-slate-500 mt-0.5 font-mono">
        <span>-72h</span>
        <span>-36h</span>
        <span>Now</span>
      </div>
    </div>
  );
};
