import { useCallback, useEffect, useState } from "react";
import useSWR from "swr";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api } from "@/api/client";
import { PageLoading, Empty } from "@/components/ui/Loading";
import { RISK_COLORS } from "@/lib/utils";

const TYPE_COLORS: Record<string, string> = {
  agent_client: "#60a5fa",
  mcp_config: "#94a3b8",
  mcp_server: "#22d3ee",
  tool: "#a78bfa",
  finding: "#f87171",
  mitre_technique: "#c084fc",
  credential_surface: "#fb923c",
  package: "#6ee7b7",
  cve: "#f87171",
  package_provenance: "#94a3b8",
  image: "#94a3b8",
  runtime_call: "#64748b",
  cve_blast_radius: "#f87171",
  iac_resource: "#94a3b8",
};

const EDGE_STYLES: Record<string, { stroke: string; strokeDasharray?: string; strokeWidth?: number }> = {
  declares: { stroke: "#475569", strokeDasharray: "4 2" },
  exposes: { stroke: "#22d3ee" },
  affected_by: { stroke: "#f87171" },
  can_exfiltrate: { stroke: "#fb923c", strokeDasharray: "6 2", strokeWidth: 2 },
  maps_to: { stroke: "#c084fc", strokeDasharray: "3 2" },
  uses_credential: { stroke: "#fb923c", strokeDasharray: "4 2" },
  cross_server_exfil: { stroke: "#ef4444", strokeWidth: 2.5 },
  depends_on: { stroke: "#475569" },
  blocked_by: { stroke: "#4ade80" },
  invoked: { stroke: "#64748b", strokeDasharray: "2 2" },
  default: { stroke: "#475569" },
};

function buildFlow(objects: any[], relations: any[]) {
  const COLS = 6;
  const nodes: Node[] = objects.map((obj, i) => {
    const color = TYPE_COLORS[obj.type] ?? "#475569";
    const riskLevel = obj.metadata?.risk_level ?? obj.metadata?.overall_risk_level;
    const border = riskLevel ? (RISK_COLORS[riskLevel]?.match(/border-(\S+)/)?.[0] ?? "") : "";
    return {
      id: obj.id,
      position: { x: (i % COLS) * 200, y: Math.floor(i / COLS) * 120 },
      data: { label: obj.name?.slice(0, 28) ?? obj.id.slice(0, 28), type: obj.type, obj },
      style: {
        background: `${color}15`,
        border: `1px solid ${color}60`,
        borderRadius: 6,
        padding: "6px 10px",
        fontSize: 11,
        color: "#e2e8f0",
        minWidth: 120,
        maxWidth: 180,
      },
    };
  });

  const edges: Edge[] = relations.map((rel, i) => {
    const style = EDGE_STYLES[rel.relation] ?? EDGE_STYLES.default;
    return {
      id: `e${i}`,
      source: rel.source,
      target: rel.target,
      label: rel.relation,
      labelStyle: { fontSize: 9, fill: "#64748b" },
      style,
      markerEnd: { type: MarkerType.ArrowClosed, color: style.stroke, width: 12, height: 12 },
      animated: rel.relation === "can_exfiltrate" || rel.relation === "cross_server_exfil",
    };
  });

  return { nodes, edges };
}

export default function Graph() {
  const [serverId, setServerId] = useState("");
  const [rebuilding, setRebuilding] = useState(false);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  const { data, isLoading, mutate } = useSWR(
    ["graph", serverId],
    () => api.graph(serverId || undefined),
    { revalidateOnFocus: false }
  );

  const d = data as any;
  const { nodes: initNodes, edges: initEdges } = buildFlow(d?.objects ?? [], d?.relations ?? []);
  const [nodes, setNodes, onNodesChange] = useNodesState(initNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initEdges);

  useEffect(() => {
    if (d) {
      const { nodes: n, edges: e } = buildFlow(d.objects ?? [], d.relations ?? []);
      setNodes(n);
      setEdges(e);
    }
  }, [d]);

  const handleRebuild = async () => {
    setRebuilding(true);
    await api.rebuildGraph(serverId || undefined);
    await mutate();
    setRebuilding(false);
  };

  if (isLoading) return <PageLoading />;

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] space-y-3">
      <div className="flex items-center justify-between flex-shrink-0">
        <h1 className="text-lg font-semibold">Risk Graph</h1>
        <div className="flex gap-2">
          <input
            placeholder="Filter by server ID..."
            value={serverId}
            onChange={(e) => setServerId(e.target.value)}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md focus:outline-none text-foreground placeholder:text-muted-foreground"
          />
          <button
            onClick={handleRebuild}
            disabled={rebuilding}
            className="px-3 py-1.5 text-sm bg-card border border-border rounded-md hover:bg-accent transition-colors disabled:opacity-50"
          >
            {rebuilding ? "Rebuilding..." : "Rebuild"}
          </button>
        </div>
      </div>

      {nodes.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <Empty message="No graph data. Click Rebuild or run mcpsafetywarden scan first." />
        </div>
      ) : (
        <div className="flex flex-1 gap-4 min-h-0">
          <div className="flex-1 rounded-lg border border-border overflow-hidden">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={(_, node) => setSelectedNode((node.data as any).obj)}
              fitView
              minZoom={0.1}
              colorMode="dark"
            >
              <Background color="#1e293b" gap={20} />
              <Controls className="!bg-card !border-border" />
              <MiniMap
                nodeColor={(n) => TYPE_COLORS[(n.data as any)?.type] ?? "#475569"}
                maskColor="rgba(0,0,0,0.6)"
                className="!bg-card !border-border"
              />
            </ReactFlow>
          </div>

          {selectedNode && (
            <div className="w-64 flex-shrink-0 rounded-lg border border-border bg-card p-4 overflow-y-auto space-y-3">
              <div>
                <p className="text-xs text-muted-foreground">{selectedNode.type}</p>
                <p className="text-sm font-medium break-all">{selectedNode.name}</p>
              </div>
              <div className="text-xs space-y-1">
                {Object.entries(selectedNode.metadata ?? {}).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span className="text-muted-foreground truncate">{k}</span>
                    <span className="text-foreground truncate max-w-32">
                      {typeof v === "object" ? JSON.stringify(v).slice(0, 40) : String(v)}
                    </span>
                  </div>
                ))}
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Source</p>
                <p className="text-xs break-all">{selectedNode.source}</p>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-xs text-muted-foreground hover:text-foreground"
              >
                Dismiss
              </button>
            </div>
          )}
        </div>
      )}

      <div className="flex-shrink-0 flex flex-wrap gap-3 text-xs text-muted-foreground">
        {Object.entries(TYPE_COLORS)
          .filter(([k]) => !["image", "iac_resource", "runtime_call"].includes(k))
          .map(([type, color]) => (
            <span key={type} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ background: color }} />
              {type.replace(/_/g, " ")}
            </span>
          ))}
      </div>
    </div>
  );
}
