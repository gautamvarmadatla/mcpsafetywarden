import { Link } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { useScans } from "@/lib/scans";
import { usePolicyActions } from "@/lib/policies";
import { fmtLatency, fmtNum, humanize, relativeTime, absoluteTime } from "@/lib/format";
import SidePanel from "./ui/SidePanel";
import Severity from "./ui/Severity";
import Button from "./ui/Button";
import { useState } from "react";

export function PolicyLabel({ policy }: { policy: string | null | undefined }) {
  if (policy === "block") return <span className="pol-block">Blocked</span>;
  if (policy === "allow") return <span className="pol-allow">Allowed</span>;
  return <span className="pol-none">Default</span>;
}

export function EffectLabel({ effect }: { effect: string | null | undefined }) {
  return <span className={effect === "destructive" ? "eff-destructive" : "t2"}>{humanize(effect)}</span>;
}

export default function FindingPanel({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const scans = useScans();
  const { change } = usePolicyActions();
  const [busy, setBusy] = useState(false);
  const { data: tool, mutate } = useSWR(finding ? ["tool", finding.server_id, finding.name] : null, () =>
    api.tool(finding!.server_id, finding!.name)
  );
  const profile = (tool?.profile ?? {}) as Record<string, number | string | null>;
  const blocked = tool?.policy === "block";

  const toggle = async () => {
    if (!finding || !tool) return;
    setBusy(true);
    await change(finding.server_id, finding.name, blocked ? null : "block", tool.policy);
    await mutate();
    setBusy(false);
  };

  return (
    <SidePanel
      open={!!finding}
      onClose={onClose}
      header={
        finding && (
          <>
            <Severity level={finding.risk_level} chip />
            <span className="mono muted">
              {finding.server_id}.{finding.name}
            </span>
          </>
        )
      }
      footer={
        finding && (
          <>
            {tool && (
              <Button variant="primary" loading={busy} onClick={toggle}>
                {blocked ? `Unblock ${finding.name}` : `Block ${finding.name}`}
              </Button>
            )}
            <Button loading={scans.isBusy(finding.server_id)} onClick={() => scans.requestScan([finding.server_id])}>
              Scan {finding.server_id}
            </Button>
            <span className="note">{blocked ? "Calls are refused by policy." : ""}</span>
          </>
        )
      }
    >
      {finding && (
        <>
          <h2>{finding.finding || finding.name}</h2>
          <div className="metaline">
            <span title={absoluteTime(finding.scanned_at)}>
              Scanned <b>{relativeTime(finding.scanned_at)}</b>
            </span>
            {finding.provider && (
              <span>
                Provider <b>{finding.provider}</b>
              </span>
            )}
            {(finding.risk_tags ?? []).map((t) => (
              <span key={t} className="tag">
                {humanize(t)}
              </span>
            ))}
          </div>
          {finding.exploitation_scenario && (
            <>
              <h4>How it could be exploited</h4>
              <p>{finding.exploitation_scenario}</p>
            </>
          )}
          {finding.remediation && (
            <>
              <h4>Remediation</h4>
              <p>{finding.remediation}</p>
            </>
          )}
          {(finding.mitre_techniques ?? []).length > 0 && (
            <>
              <h4>ATT&CK techniques</h4>
              <p className="mono">{finding.mitre_techniques!.join(", ")}</p>
            </>
          )}
          {tool?.description && (
            <>
              <h4>Tool description</h4>
              <div className="codebox">{tool.description}</div>
            </>
          )}
          {tool && (
            <>
              <h4>Behaviour</h4>
              <dl className="kv">
                <dt>Effect</dt>
                <dd>
                  <EffectLabel effect={profile.effect_class as string} />
                </dd>
                <dt>Destructiveness</dt>
                <dd className="t2">{humanize(profile.destructiveness as string)}</dd>
                <dt>Runs</dt>
                <dd className="tnum">{fmtNum(profile.run_count as number)}</dd>
                <dt>Latency p50 / p95</dt>
                <dd className="tnum">
                  {fmtLatency(profile.latency_p50_ms as number)} / {fmtLatency(profile.latency_p95_ms as number)}
                </dd>
                <dt>Policy</dt>
                <dd>
                  <PolicyLabel policy={tool.policy} />
                </dd>
              </dl>
            </>
          )}
          <p style={{ marginTop: 20 }}>
            <Link className="link" to={`/servers/${encodeURIComponent(finding.server_id)}?tab=scan`} style={{ color: "var(--accent)" }}>
              Open {finding.server_id} scan report
            </Link>
          </p>
        </>
      )}
    </SidePanel>
  );
}
