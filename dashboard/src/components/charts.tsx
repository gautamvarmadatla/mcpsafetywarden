import { useState } from "react";
import Severity, { type Level } from "./ui/Severity";

export function Sparkline({ values, width = 64, height = 18 }: { values: number[]; width?: number; height?: number }) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: "block", overflow: "visible" }} aria-hidden="true">
      <path d={d} fill="none" stroke="var(--muted)" strokeWidth="1.25" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="2" fill="var(--text)" />
    </svg>
  );
}

export type Bucket = { label: string; runs: number; failures: number };

export function ActivityBars({ buckets, total, failed }: { buckets: Bucket[]; total: number; failed: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(...buckets.map((b) => b.runs), 1);
  const w = 480 / Math.max(buckets.length, 1);
  const h = hover != null ? buckets[hover] : null;
  const ticks = [0, 6, 12, 18].filter((i) => i < buckets.length);
  return (
    <div>
      <div className="chart-read">
        <span>{h ? h.label : "Last 24 hours"}</span>
        <span>
          <b>{(h ? h.runs : total).toLocaleString()}</b> calls · <b>{h ? h.failures : failed}</b> failed
        </span>
      </div>
      <svg className="bars" viewBox="0 0 480 120" preserveAspectRatio="none" onMouseLeave={() => setHover(null)} role="img" aria-label="Calls per hour">
        {buckets.map((b, i) => {
          const bh = (b.runs / max) * 112;
          const fh = Math.min(bh, b.runs ? (b.failures / b.runs) * bh : 0);
          const x = i * w + Math.min(3, w * 0.15);
          const bw = Math.max(1, w - Math.min(6, w * 0.3));
          return (
            <g key={i} onMouseEnter={() => setHover(i)}>
              <rect x={i * w} y={0} width={w} height={120} fill="transparent" />
              <rect x={x} y={120 - bh} width={bw} height={Math.max(0, bh - fh)} rx="1.5" fill="var(--chart)" />
              {fh > 0 && <rect x={x} y={120 - fh} width={bw} height={fh} rx="1.5" fill="var(--crit)" />}
            </g>
          );
        })}
      </svg>
      <div className="axis">
        {ticks.map((i) => (
          <span key={i}>{buckets[i].label.split(" ")[0]}</span>
        ))}
        <span>now</span>
      </div>
    </div>
  );
}

const STACK_COLOR: Record<Level, string> = {
  CRITICAL: "var(--crit)",
  HIGH: "var(--high)",
  MEDIUM: "var(--med)",
  LOW: "var(--low)",
  NONE: "var(--chart)",
};

export function RiskStack({ counts }: { counts: Record<string, number> }) {
  const order: Level[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"];
  const total = order.reduce((s, l) => s + (counts[l] ?? 0), 0) || 1;
  return (
    <>
      <div className="stack" aria-hidden="true">
        {order.map((l) => (counts[l] ? <i key={l} style={{ flex: counts[l], background: STACK_COLOR[l] }} /> : null))}
      </div>
      <div className="legend">
        {order.map((l) => (
          <div key={l}>
            <Severity level={l} label={l === "NONE" ? "No findings" : undefined} />
            <span className="num">{(counts[l] ?? 0).toLocaleString()}</span>
            <span className="pct">{Math.round(((counts[l] ?? 0) / total) * 100)}%</span>
          </div>
        ))}
      </div>
    </>
  );
}
