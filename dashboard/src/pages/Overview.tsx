import { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import { useScans } from "@/lib/scans";
import { relativeTime, humanize } from "@/lib/format";
import Severity, { normLevel, RANK } from "@/components/ui/Severity";
import Button from "@/components/ui/Button";
import { ActivityBars, RiskStack, type Bucket } from "@/components/charts";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

function hourBuckets(series: { hour: string; runs: number; failures: number }[]): Bucket[] {
  const byHour = new Map(series.map((s) => [s.hour.slice(0, 13), s]));
  const now = new Date();
  const out: Bucket[] = [];
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3_600_000);
    const key = d.toISOString().slice(0, 13);
    const s = byHour.get(key);
    const start = new Date(d);
    start.setMinutes(0, 0, 0);
    const end = new Date(start.getTime() + 3_600_000);
    const fmt = (x: Date) => x.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
    out.push({ label: `${fmt(start)} to ${fmt(end)}`, runs: s?.runs ?? 0, failures: s?.failures ?? 0 });
  }
  return out;
}

const EFFECT_ORDER = ["read_only", "additive_write", "mutating_write", "external_action", "destructive", "unknown"];

export default function Overview() {
  const navigate = useNavigate();
  const scans = useScans();
  const { data: o, error, mutate, isLoading } = useSWR("overview", api.overview, { refreshInterval: 30000 });
  const { data: stats } = useSWR(["run-stats", 24], () => api.runStats(24), { refreshInterval: 60000 });
  const { data: findings } = useSWR(["findings", ""], () => api.findings());
  const { data: servers } = useSWR("servers", api.servers);

  const buckets = useMemo(() => hourBuckets(stats?.series ?? []), [stats]);
  const failed24 = buckets.reduce((s, b) => s + b.failures, 0);
  const calls24 = buckets.reduce((s, b) => s + b.runs, 0);

  const attention = useMemo(
    () =>
      [...(findings?.items ?? [])]
        .sort((a, b) => RANK[normLevel(b.risk_level)] - RANK[normLevel(a.risk_level)])
        .slice(0, 5),
    [findings]
  );
  const recentScans = useMemo(() => {
    const seen = new Set<string>();
    return (o?.recent_scans ?? []).filter((s) => !seen.has(s.server_id) && seen.add(s.server_id));
  }, [o]);
  const scannedWeek = (servers ?? []).filter((s) => s.latest_scan_at && Date.now() - new Date(s.latest_scan_at).getTime() < 7 * 86_400_000).length;
  const findingTotal = o ? Object.values(o.finding_counts).reduce((a, b) => a + b, 0) : 0;
  const effects = o ? EFFECT_ORDER.filter((k) => o.effect_distribution[k]).map((k) => [k, o.effect_distribution[k]] as const) : [];
  const effectMax = Math.max(1, ...effects.map((e) => e[1]));

  if (error) return <ErrorBanner error={error} onRetry={() => mutate()} />;

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Overview</h1>
          <div className="sub">{o ? `Security posture across ${o.server_count.toLocaleString()} server${o.server_count === 1 ? "" : "s"}.` : "Loading security posture."}</div>
        </div>
        {o && o.server_count > 0 && (
          <Button variant="primary" loading={scans.isBusy()} onClick={() => scans.requestScan("all")}>
            Scan all servers
          </Button>
        )}
      </div>

      {isLoading && !o ? (
        <SkeletonRows rows={8} />
      ) : o && o.server_count === 0 ? (
        <Empty title="No servers registered yet" action={<Button variant="primary" onClick={() => navigate("/servers?add=1")}>Add server…</Button>}>
          Register an MCP server to start profiling its tools, or run <code>mcpsafetywarden discover</code> to find the ones your clients already use.
        </Empty>
      ) : o ? (
        <>
          <div className="kpis">
            <div className="kpi">
              <div className="l">Servers</div>
              <div className="v">{o.server_count.toLocaleString()}</div>
              <div className="d">{servers ? `${scannedWeek} scanned this week` : " "}</div>
            </div>
            <div className="kpi">
              <div className="l">Tools</div>
              <div className="v">{o.tool_count.toLocaleString()}</div>
              <div className="d">{o.blocked_tools} blocked by policy</div>
            </div>
            <div className="kpi">
              <div className="l">Open findings</div>
              <div className="v">{findingTotal}</div>
              <div className="d">
                {findingTotal === 0 ? (
                  <span>{o.last_scan_at ? "Nothing found in the latest scans" : "No scans yet"}</span>
                ) : (
                  <>
                    {(o.finding_counts.CRITICAL ?? 0) > 0 && <Severity level="CRITICAL" label={`${o.finding_counts.CRITICAL} critical`} />}
                    {(o.finding_counts.HIGH ?? 0) > 0 && <Severity level="HIGH" label={`${o.finding_counts.HIGH} high`} />}
                    {!(o.finding_counts.CRITICAL || o.finding_counts.HIGH) && <span>None critical or high</span>}
                  </>
                )}
              </div>
            </div>
            <div className="kpi">
              <div className="l">Calls, last 24 hours</div>
              <div className="v">{(stats ? calls24 : o.runs_24h).toLocaleString()}</div>
              <div className="d">
                {failed24} failed <span className="muted">{calls24 ? `${((failed24 / calls24) * 100).toFixed(1)}%` : ""}</span>
              </div>
            </div>
          </div>

          <div className="two">
            <div>
              <div className="sect-t">
                Activity<span>Calls per hour</span>
              </div>
              {calls24 === 0 ? (
                <Empty title="No calls in the last 24 hours">Calls made through the proxy appear here.</Empty>
              ) : (
                <ActivityBars buckets={buckets} total={calls24} failed={failed24} />
              )}
            </div>
            <div>
              <div className="sect-t">
                Tool risk<span>{o.tool_count.toLocaleString()} tools profiled</span>
              </div>
              <RiskStack counts={o.tool_risk_distribution} />
            </div>

            <div>
              <div className="sect-t">
                Needs attention
                <Link className="link" to="/findings" style={{ fontSize: 13.5, fontWeight: 400, color: "var(--muted)" }}>
                  View all {findingTotal}
                </Link>
              </div>
              {attention.length === 0 ? (
                <Empty title="Nothing needs attention">{o.last_scan_at ? "The latest scans found no issues." : "Run a scan to check your servers."}</Empty>
              ) : (
                attention.map((f) => (
                  <div
                    key={`${f.server_id}::${f.name}`}
                    className="list-row"
                    role="link"
                    tabIndex={0}
                    onClick={() => navigate(`/findings?open=${encodeURIComponent(`${f.server_id}::${f.name}`)}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/findings?open=${encodeURIComponent(`${f.server_id}::${f.name}`)}`)}
                  >
                    <Severity level={f.risk_level} />
                    <div className="grow">
                      <div className="title">{f.finding || f.name}</div>
                      <div className="meta mono">
                        {f.server_id}.{f.name}
                      </div>
                    </div>
                    <span className="time">{relativeTime(f.scanned_at)}</span>
                  </div>
                ))
              )}
            </div>
            <div>
              <div className="sect-t">
                Tools by effect<span>Profiled behaviour</span>
              </div>
              <div className="eff">
                {effects.map(([k, v]) => (
                  <div key={k}>
                    <span className={k === "destructive" ? "eff-destructive" : "t2"}>{humanize(k)}</span>
                    <span className="track">
                      <i className={k === "destructive" ? "hot" : ""} style={{ width: `${(v / effectMax) * 100}%` }} />
                    </span>
                    <span className="tnum" style={{ textAlign: "right" }}>
                      {v.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
              <div className="sect-t" style={{ marginTop: 32 }}>
                Recent scans
                <Link className="link" to="/servers" style={{ fontSize: 13.5, fontWeight: 400, color: "var(--muted)" }}>
                  All servers
                </Link>
              </div>
              {recentScans.length === 0 ? (
                <Empty title="No scans yet">Scan a server to see its risk here.</Empty>
              ) : (
                recentScans.map((s) => (
                  <div
                    key={s.server_id}
                    className="list-row"
                    role="link"
                    tabIndex={0}
                    onClick={() => navigate(`/servers/${encodeURIComponent(s.server_id)}`)}
                    onKeyDown={(e) => e.key === "Enter" && navigate(`/servers/${encodeURIComponent(s.server_id)}`)}
                  >
                    <span className="mono grow">{s.server_id}</span>
                    <span className="muted" style={{ fontSize: 13 }}>
                      {s.provider}
                    </span>
                    <Severity level={s.overall_risk_level} />
                    <span className="time" style={{ width: 64, textAlign: "right" }}>
                      {relativeTime(s.scanned_at)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
