import { useState } from "react";
import { Link } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import { usePolicyActions } from "@/lib/policies";
import type { Policy } from "@/lib/types";
import { absoluteTime, clockTime, fmtBytes, fmtLatency, fmtNum, fmtPct, humanize, relativeTime } from "@/lib/format";
import SidePanel from "./ui/SidePanel";
import Seg from "./ui/Seg";
import Severity from "./ui/Severity";
import { EffectLabel } from "./FindingPanel";

export default function ToolPanel({ toolKey, onClose }: { toolKey: string | null; onClose: () => void }) {
  const [serverId, toolName] = toolKey ? toolKey.split("::") : [null, null];
  const { change } = usePolicyActions();
  const [saving, setSaving] = useState(false);
  const { data: tool, mutate, error } = useSWR(toolKey ? ["tool", serverId, toolName] : null, () => api.tool(serverId!, toolName!));
  const { data: findings } = useSWR(toolKey ? ["findings", ""] : null, () => api.findings());
  const related = (findings?.items ?? []).filter((f) => f.server_id === serverId && f.name === toolName);
  const p = (tool?.profile ?? {}) as Record<string, number | string | null>;

  const setPolicy = async (v: "default" | Policy) => {
    if (!tool || !serverId || !toolName) return;
    const next = v === "default" ? null : v;
    if (next === tool.policy) return;
    setSaving(true);
    await change(serverId, toolName, next, tool.policy);
    await mutate();
    setSaving(false);
  };

  return (
    <SidePanel
      open={!!toolKey}
      onClose={onClose}
      header={
        toolKey && (
          <span className="mono muted">
            {serverId}.{toolName}
          </span>
        )
      }
      footer={
        toolKey && (
          <>
            <Link className="btn" to={`/history?server=${encodeURIComponent(serverId!)}&tool=${encodeURIComponent(toolName!)}`}>
              <span className="spin" />
              View calls
            </Link>
            <Link className="btn quiet" to={`/servers/${encodeURIComponent(serverId!)}`}>
              <span className="spin" />
              Open {serverId}
            </Link>
          </>
        )
      }
    >
      {error && <p className="muted">This tool could not be loaded.</p>}
      {tool && (
        <>
          <h2 className="mono" style={{ fontSize: 19 }}>
            {tool.tool_name}
          </h2>
          <div className="metaline">
            <span title={absoluteTime(tool.discovered_at)}>
              Discovered <b>{relativeTime(tool.discovered_at)}</b>
            </span>
          </div>

          <h4>Policy</h4>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <Seg
              label="Policy"
              options={[
                { value: "default", label: "Default" },
                { value: "allow", label: "Allow" },
                { value: "block", label: "Block" },
              ]}
              value={tool.policy ?? "default"}
              onChange={setPolicy}
            />
            <span className="muted" style={{ fontSize: 13 }}>
              {saving
                ? "Saving…"
                : tool.policy === "block"
                  ? "Calls are refused."
                  : tool.policy === "allow"
                    ? "Runs without a preflight check."
                    : "Falls back to risk gating."}
            </span>
          </div>

          {related.length > 0 && (
            <>
              <h4>Findings</h4>
              {related.map((f) => (
                <Link
                  key={f.finding}
                  className="list-row"
                  style={{ textDecoration: "none", color: "inherit" }}
                  to={`/findings?open=${encodeURIComponent(`${f.server_id}::${f.name}`)}`}
                >
                  <Severity level={f.risk_level} />
                  <div className="grow">
                    <div className="title">{f.finding}</div>
                  </div>
                </Link>
              ))}
            </>
          )}

          {tool.description && (
            <>
              <h4>Description</h4>
              <div className="codebox">{tool.description}</div>
            </>
          )}

          <h4>Behaviour</h4>
          <dl className="kv">
            <dt>Effect</dt>
            <dd>
              <EffectLabel effect={p.effect_class as string} />
            </dd>
            <dt>Destructiveness</dt>
            <dd className="t2">{humanize(p.destructiveness as string)}</dd>
            <dt>Retry safety</dt>
            <dd className="t2">{humanize(p.retry_safety as string)}</dd>
            <dt>Runs</dt>
            <dd className="tnum">{fmtNum(p.run_count as number)}</dd>
            <dt>Failure rate</dt>
            <dd className="tnum">{fmtPct(p.failure_rate as number)}</dd>
            <dt>Latency p50 / p95</dt>
            <dd className="tnum">
              {fmtLatency(p.latency_p50_ms as number)} / {fmtLatency(p.latency_p95_ms as number)}
            </dd>
            <dt>Output p95</dt>
            <dd className="tnum">{fmtBytes(p.output_size_p95_bytes as number)}</dd>
          </dl>

          <h4>Recent calls</h4>
          {tool.recent_runs.length === 0 ? (
            <p className="muted">No calls recorded yet.</p>
          ) : (
            <ul className="tool-runs">
              {tool.recent_runs.map((r) => (
                <li key={r.run_id} title={absoluteTime(r.timestamp)}>
                  <span className="tnum muted">{clockTime(r.timestamp)}</span>
                  <span className={r.success ? "ok" : "bad"}>{r.success ? "Succeeded" : "Failed"}</span>
                  <span className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {r.notes}
                  </span>
                  <span className="tnum t2" style={{ textAlign: "right" }}>
                    {fmtLatency(r.latency_ms)}
                  </span>
                </li>
              ))}
            </ul>
          )}

          <details style={{ marginTop: 22 }}>
            <summary className="muted" style={{ cursor: "pointer", fontSize: 13, fontWeight: 500 }}>
              Input schema
            </summary>
            <pre className="codebox" style={{ marginTop: 8 }}>
              {JSON.stringify(tool.schema, null, 2)}
            </pre>
          </details>
        </>
      )}
    </SidePanel>
  );
}
