import { useState } from "react";
import useSWR from "swr";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { EffectBadge, PolicyBadge, RiskBadge } from "@/components/ui/Badge";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { fmtLatency, fmtBytes, capitalize } from "@/lib/utils";
import { X } from "lucide-react";

const EFFECT_OPTIONS = ["read_only", "additive_write", "mutating_write", "external_action", "destructive"];

export default function Tools() {
  const [effectFilter, setEffectFilter] = useState("");
  const [policyFilter, setPolicyFilter] = useState("");
  const [search, setSearch] = useState("");
  const [selectedTool, setSelectedTool] = useState<any>(null);

  const params: Record<string, string> = {};
  if (effectFilter) params.effect_class = effectFilter;
  if (policyFilter) params.policy = policyFilter;

  const { data, isLoading } = useSWR(
    ["tools", effectFilter, policyFilter],
    () => api.tools(Object.keys(params).length ? params : undefined),
    { refreshInterval: 30_000 }
  );

  const { data: toolDetail } = useSWR(
    selectedTool ? `tool-${selectedTool.server_id}-${selectedTool.tool_name}` : null,
    () => api.tool(selectedTool.server_id, selectedTool.tool_name)
  );

  const allTools: any[] = (data as any)?.items ?? [];
  const filtered = search
    ? allTools.filter(
        (t) =>
          t.tool_name.toLowerCase().includes(search.toLowerCase()) ||
          t.server_id.toLowerCase().includes(search.toLowerCase())
      )
    : allTools;

  const td = toolDetail as any;

  return (
    <div className="flex gap-5 h-full">
      <div className="flex-1 min-w-0 space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-semibold">Tools</h1>
          <span className="text-sm text-muted-foreground">{filtered.length} tools</span>
        </div>

        <div className="flex gap-2 flex-wrap">
          <input
            type="text"
            placeholder="Search tools..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none focus:ring-1 focus:ring-ring text-foreground placeholder:text-muted-foreground"
          />
          <select
            value={effectFilter}
            onChange={(e) => setEffectFilter(e.target.value)}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground"
          >
            <option value="">All effects</option>
            {EFFECT_OPTIONS.map((e) => (
              <option key={e} value={e}>{e.replace(/_/g, " ")}</option>
            ))}
          </select>
          <select
            value={policyFilter}
            onChange={(e) => setPolicyFilter(e.target.value)}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground"
          >
            <option value="">All policies</option>
            <option value="allow">Allow</option>
            <option value="block">Block</option>
          </select>
        </div>

        {isLoading ? (
          <PageLoading />
        ) : filtered.length === 0 ? (
          <Empty />
        ) : (
          <Card className="p-0">
            <Table>
              <Thead>
                <Tr>
                  <Th>Tool</Th>
                  <Th>Server</Th>
                  <Th>Effect</Th>
                  <Th>Destruct.</Th>
                  <Th>p50 / p95</Th>
                  <Th>Fail%</Th>
                  <Th>Runs</Th>
                  <Th>Policy</Th>
                </Tr>
              </Thead>
              <Tbody>
                {filtered.map((t: any) => (
                  <Tr
                    key={t.tool_id}
                    onClick={() => setSelectedTool(t)}
                    className={selectedTool?.tool_id === t.tool_id ? "bg-accent/30" : ""}
                  >
                    <Td>
                      <span className="text-xs font-mono">{t.tool_name}</span>
                    </Td>
                    <Td className="text-xs text-muted-foreground font-mono">{t.server_id}</Td>
                    <Td>
                      <EffectBadge cls={t.effect_class} />
                    </Td>
                    <Td className="text-xs text-muted-foreground">{capitalize(t.destructiveness)}</Td>
                    <Td className="text-xs font-mono text-muted-foreground">
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
                    <Td className="text-xs text-muted-foreground">{t.run_count ?? 0}</Td>
                    <Td>
                      <PolicyBadge policy={t.policy} />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </Card>
        )}
      </div>

      {selectedTool && (
        <div className="w-80 flex-shrink-0 space-y-4">
          <Card>
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-xs font-mono font-medium">{selectedTool.tool_name}</p>
                <p className="text-xs text-muted-foreground">{selectedTool.server_id}</p>
              </div>
              <button onClick={() => setSelectedTool(null)}>
                <X className="h-4 w-4 text-muted-foreground hover:text-foreground" />
              </button>
            </div>
            {td?.description && (
              <p className="text-xs text-muted-foreground mb-3">{td.description}</p>
            )}
            <div className="space-y-2">
              <EffectBadge cls={selectedTool.effect_class} />
              {selectedTool.policy && <PolicyBadge policy={selectedTool.policy} />}
            </div>
          </Card>

          {td?.profile && (
            <Card>
              <p className="text-xs font-medium mb-2">Profile</p>
              <div className="space-y-1.5 text-xs">
                {[
                  ["Retry safety", capitalize(td.profile.retry_safety ?? "unknown")],
                  ["Destructiveness", capitalize(td.profile.destructiveness ?? "unknown")],
                  ["Output risk", capitalize(td.profile.output_risk ?? "unknown")],
                  ["Open world", td.profile.open_world ? "Yes" : "No"],
                  ["p50 latency", fmtLatency(td.profile.latency_p50_ms)],
                  ["p95 latency", fmtLatency(td.profile.latency_p95_ms)],
                  ["Output size p95", fmtBytes(td.profile.output_size_p95_bytes)],
                  ["Schema stability", td.profile.schema_stability != null ? `${(td.profile.schema_stability * 100).toFixed(0)}%` : "-"],
                  ["Runs", td.profile.run_count ?? 0],
                ].map(([label, value]) => (
                  <div key={label as string} className="flex justify-between">
                    <span className="text-muted-foreground">{label}</span>
                    <span className="text-foreground">{value as string}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {td?.recent_runs && td.recent_runs.length > 0 && (
            <Card>
              <p className="text-xs font-medium mb-2">Recent runs</p>
              <div className="space-y-1.5">
                {td.recent_runs.map((r: any) => (
                  <div key={r.run_id} className="flex items-center justify-between text-xs">
                    <span className={r.success ? "text-green-400" : "text-red-400"}>
                      {r.success ? "ok" : "fail"}
                    </span>
                    <span className="text-muted-foreground font-mono">{fmtLatency(r.latency_ms)}</span>
                    <span className="text-muted-foreground">{r.timestamp?.slice(11, 19)}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
