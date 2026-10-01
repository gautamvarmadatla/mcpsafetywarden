import useSWR from "swr";
import { api } from "@/api/client";
import { StatCard, Card, CardTitle } from "@/components/ui/Card";
import { RiskBadge, TransportBadge } from "@/components/ui/Badge";
import { PageLoading } from "@/components/ui/Loading";
import { relativeTime, RISK_DOT, capitalize } from "@/lib/utils";
import { Server, Wrench, ShieldAlert, Activity } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { useNavigate } from "react-router-dom";

const RISK_HEX: Record<string, string> = {
  CRITICAL: "#f87171",
  HIGH: "#fb923c",
  MEDIUM: "#facc15",
  LOW: "#4ade80",
  NONE: "#475569",
};

const EFFECT_HEX: Record<string, string> = {
  read_only: "#60a5fa",
  additive_write: "#22d3ee",
  mutating_write: "#facc15",
  external_action: "#fb923c",
  destructive: "#f87171",
  unknown: "#475569",
};

export default function Overview() {
  const { data, isLoading } = useSWR("overview", api.overview, { refreshInterval: 30_000 });
  const nav = useNavigate();

  if (isLoading) return <PageLoading />;
  const d = data as any;
  if (!d) return null;

  const riskData = Object.entries(d.risk_distribution ?? {}).map(([k, v]) => ({
    name: k,
    value: v as number,
    color: RISK_HEX[k] ?? "#475569",
  }));

  const effectData = Object.entries(d.effect_distribution ?? {}).map(([k, v]) => ({
    name: capitalize(k),
    value: v as number,
    color: EFFECT_HEX[k] ?? "#475569",
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Overview</h1>
        <p className="text-sm text-muted-foreground">MCP workspace security posture</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Registered Servers"
          value={d.server_count ?? 0}
          icon={Server}
        />
        <StatCard
          label="Total Tools"
          value={d.tool_count ?? 0}
          icon={Wrench}
        />
        <StatCard
          label="Critical / High Findings"
          value={`${d.critical_findings ?? 0} / ${d.high_findings ?? 0}`}
          color={(d.critical_findings ?? 0) > 0 ? "text-red-400" : (d.high_findings ?? 0) > 0 ? "text-orange-400" : "text-green-400"}
          icon={ShieldAlert}
        />
        <StatCard
          label="Runs (24h)"
          value={d.runs_24h ?? 0}
          sub={`${d.blocked_tools ?? 0} tools blocked`}
          icon={Activity}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardTitle className="mb-4">Risk Distribution</CardTitle>
          {riskData.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No scans yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={riskData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} innerRadius={40}>
                  {riskData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "hsl(222 47% 8%)", border: "1px solid hsl(216 34% 17%)", borderRadius: 6 }}
                  labelStyle={{ color: "hsl(213 31% 91%)" }}
                  itemStyle={{ color: "hsl(213 31% 91%)" }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
          <div className="flex flex-wrap gap-2 mt-2">
            {riskData.map((r) => (
              <span key={r.name} className="flex items-center gap-1 text-xs text-muted-foreground">
                <span className="w-2 h-2 rounded-full" style={{ background: r.color }} />
                {r.name} ({r.value})
              </span>
            ))}
          </div>
        </Card>

        <Card>
          <CardTitle className="mb-4">Tools by Effect Class</CardTitle>
          {effectData.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">No profiles yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={effectData} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(216 34% 17%)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: "hsl(215 20% 65%)" }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: "hsl(215 20% 65%)" }} width={90} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "hsl(222 47% 8%)", border: "1px solid hsl(216 34% 17%)", borderRadius: 6 }}
                  cursor={{ fill: "hsl(216 34% 17%)" }}
                />
                <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                  {effectData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardTitle className="mb-3">Recent Alerts</CardTitle>
          {(d.recent_activity ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No recent alerts</p>
          ) : (
            <div className="space-y-2">
              {(d.recent_activity ?? []).slice(0, 8).map((a: any) => (
                <div key={a.run_id} className="flex items-start justify-between gap-2 py-1.5">
                  <div className="min-w-0">
                    <p className="text-xs font-mono text-foreground truncate">
                      {a.server_id}::{a.tool_name}
                    </p>
                    {a.notes && (
                      <p className="text-xs text-muted-foreground truncate">{a.notes}</p>
                    )}
                  </div>
                  <span className="text-xs text-muted-foreground whitespace-nowrap">
                    {relativeTime(a.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <CardTitle className="mb-3">Recent Scans</CardTitle>
          {(d.recent_scans ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No scans yet</p>
          ) : (
            <div className="space-y-2">
              {(d.recent_scans ?? []).map((s: any, i: number) => (
                <div
                  key={i}
                  className="flex items-center justify-between py-1.5 cursor-pointer hover:text-foreground"
                  onClick={() => nav(`/servers/${s.server_id}`)}
                >
                  <div className="min-w-0">
                    <p className="text-xs font-mono text-foreground truncate">{s.server_id}</p>
                    <p className="text-xs text-muted-foreground">{s.provider}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <RiskBadge level={s.overall_risk_level} />
                    <span className="text-xs text-muted-foreground">{relativeTime(s.scanned_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
