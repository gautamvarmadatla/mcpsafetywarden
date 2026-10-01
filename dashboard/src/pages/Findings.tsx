import { useState } from "react";
import useSWR from "swr";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { RiskBadge } from "@/components/ui/Badge";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { relativeTime } from "@/lib/utils";
import { ChevronDown, ChevronRight } from "lucide-react";

const TABS = ["Tool Findings", "Server Risks"] as const;

export default function Findings() {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Tool Findings");
  const [riskFilter, setRiskFilter] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const params: Record<string, string> = { limit: "500" };
  if (riskFilter) params.risk_level = riskFilter;

  const { data, isLoading } = useSWR(
    ["findings", riskFilter],
    () => api.findings(params),
    { refreshInterval: 60_000 }
  );

  const d = data as any;
  const findings: any[] = d?.items ?? [];
  const serverRisks: any[] = d?.server_risks ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Security Findings</h1>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground"
        >
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
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
            {t} {t === "Tool Findings" ? `(${findings.length})` : `(${serverRisks.length})`}
          </button>
        ))}
      </div>

      {isLoading ? (
        <PageLoading />
      ) : tab === "Tool Findings" ? (
        findings.length === 0 ? (
          <Empty message="No findings. Run a security scan first." />
        ) : (
          <Card className="p-0">
            <div className="divide-y divide-border/50">
              {findings.map((f: any, i: number) => (
                <div key={i} className="px-4 py-3">
                  <button
                    className="w-full flex items-start gap-3 text-left"
                    onClick={() => setExpanded(expanded === i ? null : i)}
                  >
                    {expanded === i ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-medium">{f.name}</span>
                        <RiskBadge level={f.risk_level} />
                        <span className="text-xs text-muted-foreground font-mono">{f.server_id}</span>
                        {(f.risk_tags ?? []).map((tag: string) => (
                          <span
                            key={tag}
                            className="text-xs text-muted-foreground bg-accent px-1.5 py-0.5 rounded"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">{f.finding}</p>
                    </div>
                    <span className="text-xs text-muted-foreground flex-shrink-0">
                      {f.scanned_at && relativeTime(f.scanned_at)}
                    </span>
                  </button>

                  {expanded === i && (
                    <div className="ml-7 mt-3 space-y-2.5">
                      {f.finding && (
                        <div>
                          <p className="text-xs font-medium text-foreground mb-1">Finding</p>
                          <p className="text-xs text-muted-foreground">{f.finding}</p>
                        </div>
                      )}
                      {f.exploitation_scenario && (
                        <div>
                          <p className="text-xs font-medium text-orange-400 mb-1">Exploitation</p>
                          <p className="text-xs text-muted-foreground">{f.exploitation_scenario}</p>
                        </div>
                      )}
                      {f.remediation && (
                        <div>
                          <p className="text-xs font-medium text-green-400 mb-1">Remediation</p>
                          <p className="text-xs text-muted-foreground">{f.remediation}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Card>
        )
      ) : serverRisks.length === 0 ? (
        <Empty message="No server-level risks found." />
      ) : (
        <Card className="p-0">
          <div className="divide-y divide-border/50">
            {serverRisks.map((r: any, i: number) => (
              <div key={i} className="px-4 py-3 flex items-start gap-3">
                <RiskBadge level={r.risk_level} />
                <div className="min-w-0">
                  <p className="text-xs text-muted-foreground">{r.risk}</p>
                  {r.tools_involved?.length > 0 && (
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Tools: {r.tools_involved.join(", ")}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-0.5 font-mono">{r.server_id}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
