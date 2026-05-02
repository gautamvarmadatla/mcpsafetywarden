import { useState } from "react";
import useSWR from "swr";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { fmtLatency, fmtBytes } from "@/lib/utils";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { CheckCircle, XCircle } from "lucide-react";

export default function History() {
  const [serverId, setServerId] = useState("");
  const [toolName, setToolName] = useState("");
  const [successFilter, setSuccessFilter] = useState<"" | "true" | "false">("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const params: Record<string, string> = { limit: "200" };
  if (serverId) params.server_id = serverId;
  if (toolName) params.tool_name = toolName;
  if (successFilter !== "") params.success = successFilter;

  const { data, isLoading } = useSWR(
    ["runs", serverId, toolName, successFilter],
    () => api.runs(params),
    { refreshInterval: 15_000 }
  );

  const { data: stats } = useSWR("runs-stats", () => api.runsStats(24), { refreshInterval: 30_000 });

  const runs: any[] = (data as any)?.items ?? [];
  const series: any[] = (stats as any)?.series ?? [];

  return (
    <div className="space-y-5">
      <h1 className="text-lg font-semibold">Execution History</h1>

      {series.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card>
            <p className="text-xs text-muted-foreground mb-3">Runs per hour (24h)</p>
            <ResponsiveContainer width="100%" height={100}>
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(216 34% 17%)" />
                <XAxis dataKey="hour" hide />
                <YAxis tick={{ fontSize: 10, fill: "hsl(215 20% 65%)" }} width={30} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "hsl(222 47% 8%)", border: "1px solid hsl(216 34% 17%)", borderRadius: 6 }}
                  labelFormatter={(v) => v?.toString().slice(11, 16)}
                  formatter={(v) => [v, "runs"]}
                />
                <Line type="monotone" dataKey="runs" stroke="#60a5fa" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>

          <Card>
            <p className="text-xs text-muted-foreground mb-3">P95 latency ms (24h)</p>
            <ResponsiveContainer width="100%" height={100}>
              <LineChart data={series}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(216 34% 17%)" />
                <XAxis dataKey="hour" hide />
                <YAxis tick={{ fontSize: 10, fill: "hsl(215 20% 65%)" }} width={40} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: "hsl(222 47% 8%)", border: "1px solid hsl(216 34% 17%)", borderRadius: 6 }}
                  labelFormatter={(v) => v?.toString().slice(11, 16)}
                  formatter={(v: any) => [fmtLatency(v), "p95"]}
                />
                <Line type="monotone" dataKey="latency_p95" stroke="#fb923c" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </div>
      )}

      <div className="flex gap-2 flex-wrap">
        <input
          placeholder="Server ID"
          value={serverId}
          onChange={(e) => setServerId(e.target.value)}
          className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground placeholder:text-muted-foreground"
        />
        <input
          placeholder="Tool name"
          value={toolName}
          onChange={(e) => setToolName(e.target.value)}
          className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground placeholder:text-muted-foreground"
        />
        <select
          value={successFilter}
          onChange={(e) => setSuccessFilter(e.target.value as any)}
          className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground"
        >
          <option value="">All results</option>
          <option value="true">Success only</option>
          <option value="false">Failures only</option>
        </select>
      </div>

      {isLoading ? (
        <PageLoading />
      ) : runs.length === 0 ? (
        <Empty message="No runs yet." />
      ) : (
        <Card className="p-0">
          <div className="divide-y divide-border/50">
            {runs.map((r: any) => (
              <div key={r.run_id}>
                <button
                  className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-accent/20 text-left"
                  onClick={() => setExpanded(expanded === r.run_id ? null : r.run_id)}
                >
                  {r.success ? (
                    <CheckCircle className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5 text-red-400 flex-shrink-0" />
                  )}
                  <span className="text-xs font-mono text-foreground flex-1">
                    {r.server_id}::{r.tool_name}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono w-16 text-right">
                    {fmtLatency(r.latency_ms)}
                  </span>
                  <span className="text-xs text-muted-foreground w-14 text-right">
                    {fmtBytes(r.output_size)}
                  </span>
                  <span className="text-xs text-muted-foreground w-28 text-right">
                    {r.timestamp?.slice(0, 19).replace("T", " ")}
                  </span>
                </button>
                {expanded === r.run_id && (
                  <div className="px-10 pb-3 space-y-1.5">
                    {r.notes && (
                      <p className="text-xs text-orange-400">{r.notes}</p>
                    )}
                    {r.output_preview && (
                      <pre className="text-xs text-muted-foreground bg-background/50 rounded p-2 overflow-x-auto max-h-32">
                        {r.output_preview}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
