import useSWR from "swr";
import { useNavigate } from "react-router-dom";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { RiskBadge, TransportBadge } from "@/components/ui/Badge";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { relativeTime } from "@/lib/utils";
import { ChevronRight, Server } from "lucide-react";

export default function Servers() {
  const { data, isLoading } = useSWR("servers", api.servers, { refreshInterval: 15_000 });
  const nav = useNavigate();
  const servers: any[] = data as any ?? [];

  if (isLoading) return <PageLoading />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Servers</h1>
        <p className="text-sm text-muted-foreground">{servers.length} registered</p>
      </div>

      {servers.length === 0 ? (
        <Empty message="No servers registered. Use mcpsafetywarden register to add one." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {servers.map((s: any) => (
            <Card
              key={s.server_id}
              className="cursor-pointer hover:border-border/80 transition-colors"
              onClick={() => nav(`/servers/${s.server_id}`)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2 min-w-0">
                  <Server className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <span className="text-sm font-medium truncate">{s.server_id}</span>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <TransportBadge transport={s.transport} />
                  <RiskBadge level={s.latest_scan_risk} />
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{s.tool_count} tools</span>
                  <span>{s.last_run_at ? relativeTime(s.last_run_at) : "no runs"}</span>
                </div>
                {(s.command || s.url) && (
                  <p className="text-xs text-muted-foreground font-mono truncate">
                    {s.command ?? s.url}
                  </p>
                )}
                {s.latest_scan_at && (
                  <p className="text-xs text-muted-foreground">
                    Scanned {relativeTime(s.latest_scan_at)}
                  </p>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
