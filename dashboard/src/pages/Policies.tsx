import { useState } from "react";
import useSWR from "swr";
import { api } from "@/api/client";
import { Card } from "@/components/ui/Card";
import { PolicyBadge } from "@/components/ui/Badge";
import { Table, Thead, Tbody, Th, Td, Tr } from "@/components/ui/Table";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { relativeTime } from "@/lib/utils";
import { Trash2, ShieldAlert } from "lucide-react";

export default function Policies() {
  const { data, isLoading, mutate } = useSWR("policies", api.policies, {
    refreshInterval: 30_000,
  });
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ server_id: "", tool_name: "", policy: "block" });
  const [bulking, setBulking] = useState(false);

  const policies: any[] = (data as any) ?? [];

  const handleDelete = async (serverId: string, toolName: string) => {
    await api.deletePolicy(serverId, toolName);
    mutate();
  };

  const handleAdd = async () => {
    if (!form.server_id || !form.tool_name) return;
    await api.setPolicy(form.server_id, form.tool_name, form.policy);
    setForm({ server_id: "", tool_name: "", policy: "block" });
    setAdding(false);
    mutate();
  };

  const handleBulkBlock = async () => {
    setBulking(true);
    const result = await api.bulkBlockHigh() as any;
    setBulking(false);
    mutate();
    alert(`Blocked ${result.count} tools with HIGH/CRITICAL findings.`);
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Policies</h1>
        <div className="flex gap-2">
          <button
            onClick={handleBulkBlock}
            disabled={bulking}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-orange-400/30 text-orange-400 rounded-md hover:bg-orange-400/10 transition-colors disabled:opacity-50"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            {bulking ? "Blocking..." : "Block all HIGH+"}
          </button>
          <button
            onClick={() => setAdding(true)}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md hover:bg-accent transition-colors"
          >
            + Add policy
          </button>
        </div>
      </div>

      {adding && (
        <Card>
          <p className="text-sm font-medium mb-3">New policy</p>
          <div className="flex gap-2 flex-wrap">
            <input
              placeholder="Server ID"
              value={form.server_id}
              onChange={(e) => setForm({ ...form, server_id: e.target.value })}
              className="px-3 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none text-foreground placeholder:text-muted-foreground"
            />
            <input
              placeholder="Tool name"
              value={form.tool_name}
              onChange={(e) => setForm({ ...form, tool_name: e.target.value })}
              className="px-3 py-1.5 text-sm bg-background border border-border rounded-md focus:outline-none text-foreground placeholder:text-muted-foreground"
            />
            <select
              value={form.policy}
              onChange={(e) => setForm({ ...form, policy: e.target.value })}
              className="px-3 py-1.5 text-sm bg-background border border-border rounded-md text-foreground"
            >
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
            <button
              onClick={handleAdd}
              className="px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-md hover:opacity-90"
            >
              Save
            </button>
            <button
              onClick={() => setAdding(false)}
              className="px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground"
            >
              Cancel
            </button>
          </div>
        </Card>
      )}

      {isLoading ? (
        <PageLoading />
      ) : policies.length === 0 ? (
        <Empty message="No policies set. All tools are in default (gated) mode." />
      ) : (
        <Card className="p-0">
          <Table>
            <Thead>
              <Tr>
                <Th>Server</Th>
                <Th>Tool</Th>
                <Th>Policy</Th>
                <Th>Set</Th>
                <Th></Th>
              </Tr>
            </Thead>
            <Tbody>
              {policies.map((p: any) => (
                <Tr key={`${p.server_id}::${p.tool_name}`}>
                  <Td className="font-mono text-xs">{p.server_id}</Td>
                  <Td className="font-mono text-xs">{p.tool_name}</Td>
                  <Td>
                    <PolicyBadge policy={p.policy} />
                  </Td>
                  <Td className="text-xs text-muted-foreground">
                    {p.set_at && relativeTime(p.set_at)}
                  </Td>
                  <Td>
                    <button
                      onClick={() => handleDelete(p.server_id, p.tool_name)}
                      className="text-muted-foreground hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}
