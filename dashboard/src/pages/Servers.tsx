import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import { relativeTime, absoluteTime, humanize } from "@/lib/format";
import { useScans } from "@/lib/scans";
import Severity, { normLevel, RANK } from "@/components/ui/Severity";
import Seg from "@/components/ui/Seg";
import Button from "@/components/ui/Button";
import { Sparkline } from "@/components/charts";
import AddServerDialog from "@/components/AddServerDialog";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

type Filter = "all" | "risk" | "unscanned";

export default function Servers() {
  const navigate = useNavigate();
  const scans = useScans();
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const addOpen = params.get("add") === "1";
  const { data, error, isLoading, mutate } = useSWR("servers", api.servers, { refreshInterval: 30000 });
  const { data: activity } = useSWR(["activity", 7], () => api.activity(7));

  const setAdd = (open: boolean) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (open) next.set("add", "1");
      else next.delete("add");
      return next;
    }, { replace: true });
  };

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data ?? [])
      .filter((s) => !needle || `${s.server_id} ${s.command ?? ""} ${s.url ?? ""}`.toLowerCase().includes(needle))
      .filter((s) =>
        filter === "risk" ? RANK[normLevel(s.latest_scan_risk)] >= 3 : filter === "unscanned" ? !s.latest_scan_at : true
      )
      .sort((a, b) => RANK[normLevel(b.latest_scan_risk)] - RANK[normLevel(a.latest_scan_risk)] || a.server_id.localeCompare(b.server_id));
  }, [data, q, filter]);

  const atRisk = (data ?? []).filter((s) => RANK[normLevel(s.latest_scan_risk)] >= 3).length;
  const unscanned = (data ?? []).filter((s) => !s.latest_scan_at).length;
  const open = (id: string) => navigate(`/servers/${encodeURIComponent(id)}`);

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Servers</h1>
          <div className="sub">MCP servers registered with the proxy.</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {unscanned > 0 && (
            <Button loading={scans.isBusy()} onClick={() => scans.requestScan((data ?? []).filter((s) => !s.latest_scan_at).map((s) => s.server_id))}>
              Scan {unscanned} unscanned
            </Button>
          )}
          <Button variant="primary" onClick={() => setAdd(true)}>
            Add server…
          </Button>
        </div>
      </div>

      {error && <ErrorBanner error={error} onRetry={() => mutate()} />}

      {isLoading && !data ? (
        <SkeletonRows />
      ) : (data ?? []).length === 0 ? (
        <Empty title="No servers registered" action={<Button variant="primary" onClick={() => setAdd(true)}>Add server…</Button>}>
          Add a server manually or register the ones your MCP clients already use.
        </Empty>
      ) : (
        <>
          <div className="toolbar">
            <input className="input" data-search placeholder="Search servers" value={q} onChange={(e) => setQ(e.target.value)} />
            <Seg
              label="Filter"
              options={[
                { value: "all", label: "All", count: data?.length },
                { value: "risk", label: "Critical or high", count: atRisk },
                { value: "unscanned", label: "Not scanned", count: unscanned },
              ]}
              value={filter}
              onChange={setFilter}
            />
            <span className="sp" />
            <span className="kbd">/</span>
          </div>
          <table className="t">
            <thead>
              <tr>
                <th>Server</th>
                <th>Transport</th>
                <th>Target</th>
                <th className="r">Tools</th>
                <th>Calls, 7 days</th>
                <th>Risk</th>
                <th className="r">Last scan</th>
                <th className="r">Last call</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="muted" style={{ textAlign: "center", height: 120 }}>
                    No servers match.
                  </td>
                </tr>
              )}
              {rows.map((s) => (
                <tr key={s.server_id} className="row" tabIndex={0} onClick={() => open(s.server_id)} onKeyDown={(e) => e.key === "Enter" && open(s.server_id)}>
                  <td>
                    <span className="mono" style={{ fontWeight: 500 }}>
                      {s.server_id}
                    </span>
                  </td>
                  <td className="t2">{humanize(s.transport)}</td>
                  <td className="mono muted trunc" style={{ maxWidth: 320 }}>
                    {s.url || s.command}
                  </td>
                  <td className="r tnum">{s.tool_count}</td>
                  <td>{activity?.servers[s.server_id] ? <Sparkline values={activity.servers[s.server_id]} /> : <span className="muted">-</span>}</td>
                  <td>{s.latest_scan_at ? <Severity level={s.latest_scan_risk} /> : <span className="muted">Not scanned</span>}</td>
                  <td className="r muted" title={absoluteTime(s.latest_scan_at)}>
                    {s.latest_scan_at ? relativeTime(s.latest_scan_at) : "-"}
                  </td>
                  <td className="r muted" title={absoluteTime(s.last_run_at)}>
                    {s.last_run_at ? relativeTime(s.last_run_at) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="foot-note">
            {rows.length.toLocaleString()} of {(data ?? []).length.toLocaleString()} servers
          </div>
        </>
      )}

      <AddServerDialog open={addOpen} onClose={() => setAdd(false)} />
    </div>
  );
}
