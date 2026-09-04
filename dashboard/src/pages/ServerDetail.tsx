import { useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api, ApiError } from "@/lib/api";
import type { Finding, Snapshot } from "@/lib/types";
import { useScans } from "@/lib/scans";
import { absoluteTime, humanize, relativeTime } from "@/lib/format";
import Severity, { normLevel, RANK } from "@/components/ui/Severity";
import Button from "@/components/ui/Button";
import ToolsTable from "@/components/ToolsTable";
import ToolPanel from "@/components/ToolPanel";
import FindingPanel from "@/components/FindingPanel";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

const TABS = [
  { id: "tools", label: "Tools" },
  { id: "scan", label: "Scan" },
  { id: "drift", label: "Drift" },
  { id: "source", label: "Source" },
] as const;
type TabId = (typeof TABS)[number]["id"];

function describeDrift(snaps: Snapshot[], i: number) {
  const cur = snaps[i];
  const prev = snaps[i + 1];
  if (!prev) return <span>Initial snapshot, {cur.tool_names.length} tools</span>;
  if (!cur.drift_from_previous) return <span>No changes, {cur.tool_names.length} tools</span>;
  const added = cur.tool_names.filter((n) => !prev.tool_names.includes(n));
  const removed = prev.tool_names.filter((n) => !cur.tool_names.includes(n));
  if (!added.length && !removed.length)
    return (
      <span>
        <b>Tool definitions changed.</b> Names are the same but a description or schema differs. Review before the next call.
      </span>
    );
  return (
    <span>
      {added.length > 0 && (
        <>
          <b>
            {added.length} tool{added.length > 1 ? "s" : ""} added:
          </b>{" "}
          <span className="mono">{added.join(", ")}</span>
        </>
      )}
      {added.length > 0 && removed.length > 0 && ". "}
      {removed.length > 0 && (
        <>
          <b>
            {removed.length} removed:
          </b>{" "}
          <span className="mono">{removed.join(", ")}</span>
        </>
      )}
    </span>
  );
}

export default function ServerDetail() {
  const { serverId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabId) || "tools";
  const openTool = params.get("open");
  const [openFinding, setOpenFinding] = useState<Finding | null>(null);
  const scans = useScans();

  const { data: server, error: serverError, isLoading } = useSWR(["server", serverId], () => api.server(serverId));
  const { data: tools } = useSWR(["tools", "server", serverId], () => api.tools({ server_id: serverId, limit: 200 }));
  const { data: scan, error: scanError } = useSWR(["server-scan", serverId], () => api.serverScan(serverId));
  const { data: snaps } = useSWR(tab === "drift" ? ["snapshots", serverId] : null, () => api.serverSnapshots(serverId));
  const { data: activity } = useSWR(["activity", 7], () => api.activity(7));

  const findings = useMemo(
    () =>
      (scan?.tool_findings ?? [])
        .map((f) => ({ ...f, server_id: serverId, scanned_at: scan!.scanned_at, provider: scan!.provider ?? undefined }) as Finding)
        .sort((a, b) => RANK[normLevel(b.risk_level)] - RANK[normLevel(a.risk_level)]),
    [scan, serverId]
  );

  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null) next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  };

  if (serverError instanceof ApiError && serverError.status === 404) {
    return (
      <Empty title={`No server called ${serverId}`} action={<Link className="btn" to="/servers">Back to servers</Link>}>
        It may have been removed, or the link is out of date.
      </Empty>
    );
  }
  if (serverError) return <ErrorBanner error={serverError} />;
  if (isLoading || !server) return <SkeletonRows />;

  const busy = scans.isBusy(serverId);

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1 className="mono" style={{ fontSize: 22 }}>
            {server.server_id}
          </h1>
          <div className="metaline">
            <span>
              <b>{humanize(server.transport)}</b>
            </span>
            <span>
              <b>{tools?.total ?? "…"}</b> tools
            </span>
            <span title={absoluteTime(scan?.scanned_at)}>
              Last scan <b>{scan ? relativeTime(scan.scanned_at) : "never"}</b>
            </span>
            {scan && <Severity level={scan.overall_risk_level} />}
            {busy && <span>Scan in progress</span>}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Link className="btn quiet" to={`/history?server=${encodeURIComponent(serverId)}`}>
            <span className="spin" />
            Open history
          </Link>
          <Button variant="primary" loading={busy} onClick={() => scans.requestScan([serverId])}>
            Scan {serverId}
          </Button>
        </div>
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={tab === t.id ? "on" : ""} onClick={() => update({ tab: t.id === "tools" ? null : t.id, open: null })}>
            {t.label}
            {t.id === "tools" && tools && <span className="c">{tools.total}</span>}
            {t.id === "scan" && scan && <span className="c">{findings.length}</span>}
          </button>
        ))}
      </div>

      {tab === "tools" &&
        (!tools ? (
          <SkeletonRows />
        ) : tools.total === 0 ? (
          <Empty title="No tools discovered">The server has not been inspected yet, or it exposes no tools.</Empty>
        ) : (
          <>
            <ToolsTable tools={tools.items} activity={activity?.tools} showServer={false} onOpen={(k) => update({ open: k })} />
            {tools.total > tools.items.length && (
              <div className="foot-note">
                Showing {tools.items.length} of {tools.total}.{" "}
                <Link className="link" style={{ color: "var(--accent)" }} to={`/tools?q=${encodeURIComponent(serverId)}`}>
                  See all in Tools
                </Link>
              </div>
            )}
          </>
        ))}

      {tab === "scan" &&
        (scanError ? (
          <ErrorBanner error={scanError} />
        ) : scan === undefined ? (
          <SkeletonRows />
        ) : scan === null ? (
          <Empty title="Not scanned yet" action={<Button variant="primary" loading={busy} onClick={() => scans.requestScan([serverId])}>Scan {serverId}</Button>}>
            A scan probes this server's tools for injection, exfiltration and destructive behaviour.
          </Empty>
        ) : (
          <>
            {scan.summary_text && <p className="summary">{scan.summary_text}</p>}
            <div className="metaline" style={{ margin: "-8px 0 20px" }}>
              <span title={absoluteTime(scan.scanned_at)}>
                Scanned <b>{relativeTime(scan.scanned_at)}</b>
              </span>
              {scan.provider && (
                <span>
                  Provider <b>{scan.provider}</b>
                </span>
              )}
              {scan.model_id && (
                <span>
                  Model <b>{scan.model_id}</b>
                </span>
              )}
              <span>
                Overall <Severity level={scan.overall_risk_level} />
              </span>
            </div>
            {findings.length === 0 ? (
              <Empty title="No tool findings">The latest scan did not flag any tools on this server.</Empty>
            ) : (
              findings.map((f) => (
                <div key={f.name + f.finding} className="frow" role="button" tabIndex={0} onClick={() => setOpenFinding(f)} onKeyDown={(e) => e.key === "Enter" && setOpenFinding(f)}>
                  <Severity level={f.risk_level} />
                  <div style={{ minWidth: 0 }}>
                    <div className="ttl">{f.finding || f.name}</div>
                    <div className="where mono">{f.name}</div>
                  </div>
                  <div className="tags">
                    {(f.risk_tags ?? []).slice(0, 3).map((t) => (
                      <span key={t} className="tag">
                        {humanize(t)}
                      </span>
                    ))}
                  </div>
                  <div className="time">{relativeTime(f.scanned_at)}</div>
                </div>
              ))
            )}
            {scan.server_risks.length > 0 && (
              <>
                <div className="sect-t" style={{ marginTop: 32 }}>
                  Server-level risks<span>{scan.server_risks.length}</span>
                </div>
                {scan.server_risks.map((r, i) => (
                  <div key={i} className="frow" style={{ gridTemplateColumns: "104px 1fr", cursor: "default" }}>
                    <Severity level={r.risk_level} />
                    <div>
                      <div className="ttl" style={{ whiteSpace: "normal", fontWeight: 400 }}>
                        {r.risk}
                      </div>
                      {!!r.tools_involved?.length && <div className="where mono">{r.tools_involved.join(" · ")}</div>}
                    </div>
                  </div>
                ))}
              </>
            )}
          </>
        ))}

      {tab === "drift" &&
        (!snaps ? (
          <SkeletonRows />
        ) : snaps.length === 0 ? (
          <Empty title="No snapshots yet">Snapshots of the tool list are taken each time the server is inspected.</Empty>
        ) : (
          <ul className="drift">
            {snaps.map((s, i) => (
              <li key={s.snapshot_id} className={s.drift_from_previous ? "changed" : ""}>
                <i />
                <span className="mono">{s.tools_hash.slice(0, 8)}</span>
                <span className="d">{describeDrift(snaps, i)}</span>
                <span className="when" title={absoluteTime(s.snapshot_at)}>
                  {relativeTime(s.snapshot_at)}
                </span>
              </li>
            ))}
          </ul>
        ))}

      {tab === "source" && (
        <dl className="kv">
          <dt>Transport</dt>
          <dd>{humanize(server.transport)}</dd>
          {server.url ? (
            <>
              <dt>URL</dt>
              <dd className="mono">{server.url}</dd>
            </>
          ) : (
            <>
              <dt>Command</dt>
              <dd className="mono">{server.command}</dd>
              <dt>Arguments</dt>
              <dd className="mono">{server.args.length ? server.args.join(" ") : <span className="muted">None</span>}</dd>
            </>
          )}
          <dt>Registered</dt>
          <dd title={absoluteTime(server.registered_at)}>{relativeTime(server.registered_at)}</dd>
          <dt>Source repository</dt>
          <dd className="mono">
            {server.source_hash?.github_url ? (
              <a className="link" style={{ color: "var(--accent)" }} href={server.source_hash.github_url} target="_blank" rel="noreferrer">
                {server.source_hash.github_url}
              </a>
            ) : (
              <span className="muted">Not linked</span>
            )}
          </dd>
          {server.source_hash && (
            <>
              <dt>Source hash</dt>
              <dd className="mono">{server.source_hash.files_hash.slice(0, 16)}</dd>
              <dt>Last checked</dt>
              <dd title={absoluteTime(server.source_hash.last_checked_at)}>{relativeTime(server.source_hash.last_checked_at)}</dd>
            </>
          )}
        </dl>
      )}

      <ToolPanel toolKey={openTool} onClose={() => update({ open: null })} />
      <FindingPanel finding={openFinding} onClose={() => setOpenFinding(null)} />
    </div>
  );
}
