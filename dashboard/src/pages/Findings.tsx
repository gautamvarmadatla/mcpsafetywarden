import { useEffect, useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import { useScans } from "@/lib/scans";
import { relativeTime, humanize } from "@/lib/format";
import type { Finding } from "@/lib/types";
import Severity, { normLevel, RANK, type Level } from "@/components/ui/Severity";
import Seg from "@/components/ui/Seg";
import Button from "@/components/ui/Button";
import FindingPanel from "@/components/FindingPanel";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";
import { isTyping } from "@/components/Shell";

const LEVELS: (Level | "ALL")[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const keyOf = (f: Finding) => `${f.server_id}::${f.name}`;

export default function Findings() {
  const navigate = useNavigate();
  const scans = useScans();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "server" ? "server" : "tool";
  const sev = (params.get("severity")?.toUpperCase() as Level | undefined) ?? "ALL";
  const open = params.get("open");
  const sel = params.get("sel");

  const { data, error, isLoading, mutate } = useSWR(["findings", ""], () => api.findings(), { refreshInterval: 60000 });

  const update = (patch: Record<string, string | null>, replace = true) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v === null) next.delete(k);
        else next.set(k, v);
      }
      return next;
    }, { replace });
  };

  const sorted = useMemo(
    () =>
      [...(data?.items ?? [])].sort(
        (a, b) => RANK[normLevel(b.risk_level)] - RANK[normLevel(a.risk_level)] || (b.scanned_at ?? "").localeCompare(a.scanned_at ?? "")
      ),
    [data]
  );
  const visible = sev === "ALL" ? sorted : sorted.filter((f) => normLevel(f.risk_level) === sev);
  const openFinding = open ? sorted.find((f) => keyOf(f) === open) ?? null : null;
  const serverRisks = useMemo(
    () => [...(data?.server_risks ?? [])].sort((a, b) => RANK[normLevel(b.risk_level)] - RANK[normLevel(a.risk_level)]),
    [data]
  );

  useEffect(() => {
    if (tab !== "tool") return;
    const onKey = (e: KeyboardEvent) => {
      if (isTyping() || e.metaKey || e.ctrlKey || e.altKey || document.querySelector(".pal-wrap.on, .dialog-wrap")) return;
      if (e.key !== "j" && e.key !== "k" && e.key !== "Enter") return;
      if (e.key === "Enter" && (document.activeElement as HTMLElement | null)?.closest("button, a, [role=button], [role=link]")) return;
      const keys = visible.map(keyOf);
      if (!keys.length) return;
      const cur = keys.indexOf(sel ?? "");
      if (e.key === "Enter") {
        if (cur >= 0) update({ open: keys[cur] }, false);
        return;
      }
      e.preventDefault();
      const next = e.key === "j" ? Math.min(cur + 1, keys.length - 1) : Math.max(cur - 1, 0);
      update({ sel: keys[next], ...(open ? { open: keys[next] } : {}) });
      document.querySelector<HTMLElement>(`[data-key="${CSS.escape(keys[next])}"]`)?.focus();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const counts = data?.counts ?? {};
  const total = sorted.length;

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Security findings</h1>
          <div className="sub">From the latest scan of each server, sorted by severity.</div>
        </div>
        <Button loading={scans.isBusy()} onClick={() => scans.requestScan("all")}>
          Scan all servers
        </Button>
      </div>

      <div className="tabs">
        <button className={tab === "tool" ? "on" : ""} onClick={() => update({ tab: null })}>
          Tool findings <span className="c">{total}</span>
        </button>
        <button className={tab === "server" ? "on" : ""} onClick={() => update({ tab: "server", open: null })}>
          Server risks <span className="c">{serverRisks.length}</span>
        </button>
      </div>

      {error && <ErrorBanner error={error} onRetry={() => mutate()} />}

      {isLoading && !data ? (
        <SkeletonRows />
      ) : tab === "server" ? (
        serverRisks.length === 0 ? (
          <Empty title="No server-level risks">Risks that span several tools on one server appear here after a scan.</Empty>
        ) : (
          serverRisks.map((r, i) => (
            <div
              key={i}
              className="frow"
              style={{ gridTemplateColumns: "104px 1fr 200px" }}
              role="link"
              tabIndex={0}
              onClick={() => navigate(`/servers/${encodeURIComponent(r.server_id)}?tab=scan`)}
              onKeyDown={(e) => e.key === "Enter" && navigate(`/servers/${encodeURIComponent(r.server_id)}?tab=scan`)}
            >
              <Severity level={r.risk_level} />
              <div style={{ minWidth: 0 }}>
                <div className="ttl" style={{ whiteSpace: "normal", fontWeight: 400 }}>
                  {r.risk}
                </div>
                {!!r.tools_involved?.length && <div className="where mono">{r.tools_involved.join(" · ")}</div>}
              </div>
              <div className="mono muted" style={{ textAlign: "right" }}>
                {r.server_id}
              </div>
            </div>
          ))
        )
      ) : total === 0 ? (
        <Empty title="No findings" action={<Button variant="primary" onClick={() => scans.requestScan("all")}>Scan all servers</Button>}>
          Findings appear here after a security scan. Scans probe each server's tools for injection, exfiltration and destructive behaviour.
        </Empty>
      ) : (
        <>
          <div className="toolbar">
            <Seg
              label="Severity"
              options={LEVELS.map((l) => ({
                value: l,
                label: l === "ALL" ? "All" : l[0] + l.slice(1).toLowerCase(),
                count: l === "ALL" ? total : counts[l] ?? 0,
              }))}
              value={sev}
              onChange={(v) => update({ severity: v === "ALL" ? null : v.toLowerCase() })}
            />
            <span className="sp" />
            <span className="muted" style={{ fontSize: 13 }}>
              Move with <span className="kbd">j</span> <span className="kbd">k</span>, open with <span className="kbd">Enter</span>
            </span>
          </div>
          {visible.length === 0 && <Empty title={`No ${sev.toLowerCase()} findings`} />}
          {visible.map((f) => {
            const k = keyOf(f);
            return (
              <div
                key={k}
                data-key={k}
                className={`frow${sel === k || open === k ? " sel" : ""}`}
                role="button"
                tabIndex={0}
                onClick={() => update({ open: k, sel: k }, false)}
                onKeyDown={(e) => e.key === "Enter" && update({ open: k, sel: k }, false)}
              >
                <Severity level={f.risk_level} />
                <div style={{ minWidth: 0 }}>
                  <div className="ttl">{f.finding || f.name}</div>
                  <div className="where mono">
                    {f.server_id}.{f.name}
                  </div>
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
            );
          })}
        </>
      )}

      <FindingPanel finding={openFinding} onClose={() => update({ open: null })} />
    </div>
  );
}
