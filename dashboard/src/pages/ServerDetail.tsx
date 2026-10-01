import { useState } from "react";
import useSWR from "swr";
import { useParams } from "react-router-dom";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { RiskBadge, EffectBadge, TransportBadge, PolicyBadge } from "@/components/ui/Badge";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { relativeTime, fmtLatency, capitalize } from "@/lib/utils";
import { AlertTriangle, CheckCircle, Clock } from "lucide-react";

const TABS = ["Tools", "Scan", "Drift", "Source"] as const;

export default function ServerDetail() {
  const { serverId } = useParams<{ serverId: string }>();
  const [tab, setTab] = useState<(typeof TABS)[number]>("Tools");

  const { data: tools, isLoading: toolsLoading } = useSWR(
    `server-tools-${serverId}`,
    () => api.serverTools(serverId!),
    { refreshInterval: 30_000 }
  );
  const { data: scan } = useSWR(`server-scan-${serverId}`, () =>
    api.serverScan(serverId!).catch(() => null)
  );
  const { data: snapshots } = useSWR(`server-snaps-${serverId}`, () =>
    api.serverSnapshots(serverId!)
  );
  const { data: server } = useSWR(`server-${serverId}`, () => api.server(serverId!));

  const s = server as any;
  const toolList: any[] = (tools as any)?.items ?? [];
  const sc = scan as any;
  const snaps: any[] = (snapshots as any) ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold font-mono">{serverId}</h1>
          <div className="flex items-center gap-2 mt-1">
            {s && <TransportBadge transport={s.transport} />}
            {sc && <RiskBadge level={sc.overall_risk_level} />}
            {s?.command && (
              <span className="text-xs text-muted-foreground font-mono">{s.command}</span>
            )}
          </div>
        </div>
      </div>

      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm transition-colors border-b-2 -mb-px ${
              tab === t
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Tools" && (
        <>
          {toolsLoading ? (
            <PageLoading />
          ) : toolList.length === 0 ? (
            <Empty message="No tools discovered. Run mcpsafetywarden inspect." />
          ) : (
            <Card className="p-0">
              <Table>
                <Thead>
                  <Tr>
                    <Th>Tool</Th>
                    <Th>Effect</Th>
                    <Th>Destructiveness</Th>
                    <Th>Latency p50/p95</Th>
                    <Th>Failure rate</Th>
                    <Th>Runs</Th>
                    <Th>Policy</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {toolList.map((t: any) => (
                    <Tr key={t.tool_id}>
                      <Td>
                        <div>
                          <p className="text-xs font-mono text-foreground">{t.tool_name}</p>
                          {t.description && (
                            <p className="text-xs text-muted-foreground truncate max-w-xs">
                              {t.description}
                            </p>
                          )}
                        </div>
                      </Td>
                      <Td>
                        <EffectBadge cls={t.effect_class} />
                      </Td>
                      <Td>
                        <span className="text-xs text-muted-foreground">
                          {capitalize(t.destructiveness)}
                        </span>
                      </Td>
                      <Td className="font-mono text-xs">
                        {fmtLatency(t.latency_p50_ms)} / {fmtLatency(t.latency_p95_ms)}
                      </Td>
                      <Td>
                        <span
                          className={`text-xs ${
                            (t.failure_rate ?? 0) > 0.2
                              ? "text-red-400"
                              : (t.failure_rate ?? 0) > 0.05
                              ? "text-yellow-400"
                              : "text-muted-foreground"
                          }`}
                        >
                          {t.run_count ? `${((t.failure_rate ?? 0) * 100).toFixed(0)}%` : "-"}
                        </span>
                      </Td>
                      <Td className="text-muted-foreground text-xs">{t.run_count ?? 0}</Td>
                      <Td>
                        <PolicyBadge policy={t.policy} />
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </Card>
          )}
        </>
      )}

      {tab === "Scan" && (
        <>
          {!sc ? (
            <Empty message="No scan yet. Run: mcpsafetywarden scan this-server" />
          ) : (
            <div className="space-y-4">
              <Card>
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <p className="text-xs text-muted-foreground">Overall Risk</p>
                    <RiskBadge level={sc.overall_risk_level} />
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">Provider</p>
                    <p className="text-xs text-foreground">{sc.provider}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-muted-foreground">Scanned</p>
                    <p className="text-xs">{relativeTime(sc.scanned_at)}</p>
                  </div>
                </div>
                {sc.summary_text && (
                  <p className="text-sm text-muted-foreground border-t border-border pt-3">
                    {sc.summary_text}
                  </p>
                )}
              </Card>

              {(sc.tool_findings ?? []).length > 0 && (
                <Card className="p-0">
                  <div className="px-4 py-3 border-b border-border">
                    <p className="text-sm font-medium">Tool Findings ({sc.tool_findings.length})</p>
                  </div>
                  <div className="divide-y divide-border/50">
                    {sc.tool_findings.map((f: any, i: number) => (
                      <div key={i} className="px-4 py-3">
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="text-xs font-mono font-medium">{f.name}</span>
                          <RiskBadge level={f.risk_level} />
                          {(f.risk_tags ?? []).map((tag: string) => (
                            <span key={tag} className="text-xs text-muted-foreground bg-accent px-1.5 py-0.5 rounded">
                              {tag}
                            </span>
                          ))}
                        </div>
                        <p className="text-xs text-muted-foreground">{f.finding}</p>
                        {f.exploitation_scenario && (
                          <details className="mt-1">
                            <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                              Exploitation scenario
                            </summary>
                            <p className="text-xs text-muted-foreground mt-1 pl-2 border-l border-border">
                              {f.exploitation_scenario}
                            </p>
                          </details>
                        )}
                        {f.remediation && (
                          <p className="text-xs text-green-400/80 mt-1">Fix: {f.remediation}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {(sc.server_risks ?? []).length > 0 && (
                <Card className="p-0">
                  <div className="px-4 py-3 border-b border-border">
                    <p className="text-sm font-medium">Server-level Risks</p>
                  </div>
                  <div className="divide-y divide-border/50">
                    {sc.server_risks.map((r: any, i: number) => (
                      <div key={i} className="px-4 py-3 flex items-start gap-3">
                        <RiskBadge level={r.risk_level} />
                        <div>
                          <p className="text-xs text-muted-foreground">{r.risk}</p>
                          {r.tools_involved?.length > 0 && (
                            <p className="text-xs text-muted-foreground mt-0.5">
                              Tools: {r.tools_involved.join(", ")}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </div>
          )}
        </>
      )}

      {tab === "Drift" && (
        <div className="space-y-3">
          {snaps.length === 0 ? (
            <Empty message="No snapshots. Run mcpsafetywarden inspect to create a baseline." />
          ) : (
            snaps.map((snap: any) => (
              <Card key={snap.snapshot_id} className="flex items-start gap-3">
                {snap.drift_from_previous ? (
                  <AlertTriangle className="h-4 w-4 text-orange-400 flex-shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle className="h-4 w-4 text-green-400 flex-shrink-0 mt-0.5" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      <Clock className="inline h-3 w-3 mr-1" />
                      {relativeTime(snap.snapshot_at)}
                    </span>
                    {snap.drift_from_previous && (
                      <span className="text-xs text-orange-400 font-medium">DRIFT DETECTED</span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {snap.tool_names?.length ?? 0} tools · hash {snap.tools_hash}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">
                    {snap.tool_names?.join(", ")}
                  </p>
                </div>
              </Card>
            ))
          )}
        </div>
      )}

      {tab === "Source" && (
        <div>
          {!s?.source_hash ? (
            <Empty message="No source scan. Pass --github-url when scanning to enable source analysis." />
          ) : (
            <Card>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground">GitHub URL</p>
                  <p className="text-sm font-mono">{s.source_hash.github_url}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Source hash</p>
                  <p className="text-sm font-mono">{s.source_hash.files_hash}</p>
                </div>
                <div className="flex gap-6">
                  <div>
                    <p className="text-xs text-muted-foreground">First seen</p>
                    <p className="text-xs">{relativeTime(s.source_hash.first_seen_at)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Last checked</p>
                    <p className="text-xs">{relativeTime(s.source_hash.last_checked_at)}</p>
                  </div>
                </div>
                {s.source_hash.files_hash !== s.source_hash.files_hash && (
                  <p className="text-sm text-orange-400 flex items-center gap-1">
                    <AlertTriangle className="h-4 w-4" /> Hash changed since first scan
                  </p>
                )}
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
