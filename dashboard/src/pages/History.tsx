import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api, errorMessage } from "@/lib/api";
import type { Run } from "@/lib/types";
import { absoluteTime, clockTime, dayLabel, fmtBytes, fmtLatency } from "@/lib/format";
import { download, toCsv } from "@/lib/csv";
import Seg from "@/components/ui/Seg";
import Button from "@/components/ui/Button";
import SidePanel from "@/components/ui/SidePanel";
import { useToast } from "@/components/ui/Toast";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

const PAGE = 200;
type Outcome = "all" | "ok" | "failed";

function outcome(r: Run) {
  if (r.success) return <span className="t2">Succeeded</span>;
  if (r.is_tool_error) return <span className="bad" style={{ fontWeight: 500 }}>Tool error</span>;
  return <span className="pol-block">Failed</span>;
}

export default function History() {
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const server = params.get("server");
  const tool = params.get("tool");
  const result = (params.get("result") as Outcome) || "all";
  const [q, setQ] = useState(params.get("q") ?? "");
  const [older, setOlder] = useState<Run[]>([]);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [exhausted, setExhausted] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [openRun, setOpenRun] = useState<Run | null>(null);

  const apiParams = { server_id: server, tool_name: tool, success: result === "all" ? null : result === "ok", limit: PAGE };
  const { data, error, isLoading, mutate } = useSWR(["runs", server, tool, result], () => api.runs(apiParams), { refreshInterval: 30000 });

  useEffect(() => {
    setOlder([]);
    setExhausted(false);
  }, [server, tool, result]);

  const setParam = (k: string, v: string | null) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
      return next;
    }, { replace: true });
  };

  const all = useMemo(() => [...(data?.items ?? []), ...older], [data, older]);
  const needle = q.trim().toLowerCase();
  const rows = needle
    ? all.filter((r) => `${r.server_id}.${r.tool_name} ${r.notes ?? ""}`.toLowerCase().includes(needle))
    : all;
  const total = data?.total ?? 0;
  const canLoadOlder = !exhausted && all.length < total && !needle;

  const loadOlder = async () => {
    const last = all[all.length - 1];
    if (!last) return;
    setLoadingOlder(true);
    try {
      const res = await api.runs({ ...apiParams, before_id: last.run_id, before_ts: last.timestamp });
      setOlder((o) => [...o, ...res.items]);
      if (res.items.length < PAGE) setExhausted(true);
    } catch (e) {
      toast(`Could not load older calls: ${errorMessage(e)}`);
    } finally {
      setLoadingOlder(false);
    }
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const out: Run[] = [];
      let cursor: Run | undefined;
      for (let i = 0; i < 20; i++) {
        const res = await api.runs({ ...apiParams, limit: 500, before_id: cursor?.run_id, before_ts: cursor?.timestamp });
        out.push(...res.items);
        if (res.items.length < 500) break;
        cursor = res.items[res.items.length - 1];
      }
      const filtered = needle ? out.filter((r) => `${r.server_id}.${r.tool_name} ${r.notes ?? ""}`.toLowerCase().includes(needle)) : out;
      const csv = toCsv(filtered as unknown as Record<string, unknown>[], [
        "run_id",
        "timestamp",
        "server_id",
        "tool_name",
        "success",
        "is_tool_error",
        "latency_ms",
        "output_size",
        "notes",
      ]);
      download(`history-${new Date().toISOString().slice(0, 10)}.csv`, csv);
      toast(`Exported ${filtered.length.toLocaleString()} call${filtered.length === 1 ? "" : "s"} to CSV.`);
    } catch (e) {
      toast(`Export failed: ${errorMessage(e)}`);
    } finally {
      setExporting(false);
    }
  };

  let lastDay = "";

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Execution history</h1>
          <div className="sub">Every call that passed through the proxy, newest first.</div>
        </div>
        <Button loading={exporting} onClick={exportCsv} disabled={!total}>
          Export CSV
        </Button>
      </div>

      <div className="toolbar">
        <input
          className="input"
          data-search
          placeholder="Filter by server, tool or note"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setParam("q", e.target.value);
          }}
        />
        <Seg
          label="Outcome"
          options={[
            { value: "all", label: "All" },
            { value: "ok", label: "Succeeded" },
            { value: "failed", label: "Failed" },
          ]}
          value={result}
          onChange={(v) => setParam("result", v === "all" ? null : v)}
        />
        {(server || tool) && (
          <Button size="sm" variant="quiet" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            {server && <span className="mono">{server}</span>}
            {tool && <span className="mono">.{tool}</span>}
            <span aria-hidden="true">×</span>
          </Button>
        )}
        <span className="sp" />
        <span className="kbd">/</span>
      </div>

      {error && <ErrorBanner error={error} onRetry={() => mutate()} />}

      {isLoading && !data ? (
        <SkeletonRows />
      ) : total === 0 ? (
        <Empty title={server || tool || result !== "all" ? "No calls match these filters" : "No calls recorded yet"}>
          Calls made through <code>safe_tool_call</code> are recorded here with their latency and outcome.
        </Empty>
      ) : (
        <>
          <table className="t">
            <thead>
              <tr>
                <th style={{ width: 110 }}>Time</th>
                <th>Call</th>
                <th>Result</th>
                <th className="r">Latency</th>
                <th className="r">Output</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted" style={{ textAlign: "center", height: 120 }}>
                    No calls match “{q}”.
                  </td>
                </tr>
              )}
              {rows.map((r) => {
                const day = new Date(r.timestamp).toDateString();
                const header = day !== lastDay;
                lastDay = day;
                return (
                  <Fragment key={r.run_id}>
                    {header && (
                      <tr className="day">
                        <td colSpan={6}>{dayLabel(r.timestamp)}</td>
                      </tr>
                    )}
                    <tr className={`row${r.success ? "" : " blocked"}`} tabIndex={0} onClick={() => setOpenRun(r)} onKeyDown={(e) => e.key === "Enter" && setOpenRun(r)}>
                      <td className="muted tnum" title={absoluteTime(r.timestamp)}>
                        {clockTime(r.timestamp)}
                      </td>
                      <td>
                        <span className="mono">
                          {r.server_id}
                          <span className="muted">.</span>
                          {r.tool_name}
                        </span>
                      </td>
                      <td>{outcome(r)}</td>
                      <td className="r tnum t2">{fmtLatency(r.latency_ms)}</td>
                      <td className="r tnum t2">{fmtBytes(r.output_size)}</td>
                      <td className="muted trunc">{r.notes}</td>
                    </tr>
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          <div className="pager">
            <span>
              Showing {rows.length.toLocaleString()} of {total.toLocaleString()}
            </span>
            <span className="sp" />
            {canLoadOlder && (
              <Button size="sm" loading={loadingOlder} onClick={loadOlder}>
                Load older calls
              </Button>
            )}
          </div>
        </>
      )}

      <SidePanel
        open={!!openRun}
        onClose={() => setOpenRun(null)}
        header={
          openRun && (
            <span className="mono">
              {openRun.server_id}.{openRun.tool_name}
            </span>
          )
        }
      >
        {openRun && (
          <>
            <h2>{openRun.success ? "Call succeeded" : openRun.is_tool_error ? "Tool returned an error" : "Call failed"}</h2>
            <dl className="kv">
              <dt>Time</dt>
              <dd>{absoluteTime(openRun.timestamp)}</dd>
              <dt>Latency</dt>
              <dd className="tnum">{fmtLatency(openRun.latency_ms)}</dd>
              <dt>Output size</dt>
              <dd className="tnum">{fmtBytes(openRun.output_size)}</dd>
              <dt>Run</dt>
              <dd className="mono">#{openRun.run_id}</dd>
            </dl>
            {openRun.notes && (
              <>
                <h4>Note</h4>
                <p>{openRun.notes}</p>
              </>
            )}
            <h4>Output preview</h4>
            {openRun.output_preview ? <pre className="codebox">{openRun.output_preview}</pre> : <p className="muted">No output was captured.</p>}
            <p style={{ marginTop: 20, display: "flex", gap: 16 }}>
              <Link className="link" style={{ color: "var(--accent)" }} to={`/tools?open=${encodeURIComponent(`${openRun.server_id}::${openRun.tool_name}`)}`}>
                Open tool
              </Link>
              <Link
                className="link"
                style={{ color: "var(--accent)" }}
                to={`/history?server=${encodeURIComponent(openRun.server_id)}&tool=${encodeURIComponent(openRun.tool_name)}`}
                onClick={() => setOpenRun(null)}
              >
                All calls to this tool
              </Link>
            </p>
          </>
        )}
      </SidePanel>
    </div>
  );
}
