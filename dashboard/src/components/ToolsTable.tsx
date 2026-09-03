import type { Tool } from "@/lib/types";
import { fmtLatency, fmtPct, humanize } from "@/lib/format";
import { Sparkline } from "./charts";
import { EffectLabel, PolicyLabel } from "./FindingPanel";

export default function ToolsTable({
  tools,
  activity,
  onOpen,
  showServer = true,
}: {
  tools: Tool[];
  activity?: Record<string, number[]>;
  onOpen: (key: string) => void;
  showServer?: boolean;
}) {
  return (
    <table className="t">
      <thead>
        <tr>
          <th>Tool</th>
          {showServer && <th>Server</th>}
          <th>Effect</th>
          <th>Destructiveness</th>
          <th className="r">Runs</th>
          <th>7 days</th>
          <th className="r">Failures</th>
          <th className="r">p50 / p95</th>
          <th>Policy</th>
        </tr>
      </thead>
      <tbody>
        {tools.map((t) => {
          const key = `${t.server_id}::${t.tool_name}`;
          const spark = activity?.[key];
          return (
            <tr key={key} className="row" tabIndex={0} onClick={() => onOpen(key)} onKeyDown={(e) => e.key === "Enter" && onOpen(key)}>
              <td>
                <span className="mono">{t.tool_name}</span>
              </td>
              {showServer && <td className="mono muted">{t.server_id}</td>}
              <td>
                <EffectLabel effect={t.effect_class} />
              </td>
              <td className="t2">{humanize(t.destructiveness)}</td>
              <td className="r tnum">{t.run_count.toLocaleString()}</td>
              <td>{spark ? <Sparkline values={spark} /> : <span className="muted">-</span>}</td>
              <td className="r tnum t2">{t.run_count ? fmtPct(t.failure_rate) : "-"}</td>
              <td className="r tnum t2">
                {fmtLatency(t.latency_p50_ms)} <span className="muted">/ {fmtLatency(t.latency_p95_ms)}</span>
              </td>
              <td>
                <PolicyLabel policy={t.policy} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
