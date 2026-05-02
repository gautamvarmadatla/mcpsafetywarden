const BASE = "";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function del<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const api = {
  overview: () => get("/api/overview"),
  health: () => get("/api/health"),

  servers: (params?: Record<string, string>) =>
    get(`/api/servers${params ? "?" + new URLSearchParams(params) : ""}`),
  server: (id: string) => get(`/api/servers/${id}`),
  serverTools: (id: string, params?: Record<string, string>) =>
    get(`/api/servers/${id}/tools${params ? "?" + new URLSearchParams(params) : ""}`),
  serverScan: (id: string) => get(`/api/servers/${id}/scan`),
  serverScans: (id: string) => get(`/api/servers/${id}/scans`),
  serverSnapshots: (id: string) => get(`/api/servers/${id}/snapshots`),

  tools: (params?: Record<string, string>) =>
    get(`/api/tools${params ? "?" + new URLSearchParams(params) : ""}`),
  tool: (serverId: string, toolName: string) =>
    get(`/api/tools/${encodeURIComponent(serverId)}/${encodeURIComponent(toolName)}`),

  findings: (params?: Record<string, string>) =>
    get(`/api/findings${params ? "?" + new URLSearchParams(params) : ""}`),

  runs: (params?: Record<string, string>) =>
    get(`/api/runs${params ? "?" + new URLSearchParams(params) : ""}`),
  runsStats: (hours = 24) => get(`/api/runs/stats?hours=${hours}`),

  graph: (serverId?: string) =>
    get(`/api/graph${serverId ? `?server_id=${encodeURIComponent(serverId)}` : ""}`),
  rebuildGraph: (serverId?: string) =>
    post(`/api/graph/rebuild${serverId ? `?server_id=${encodeURIComponent(serverId)}` : ""}`),

  policies: () => get("/api/policies"),
  setPolicy: (serverId: string, toolName: string, policy: string) =>
    post("/api/policies", { server_id: serverId, tool_name: toolName, policy }),
  deletePolicy: (serverId: string, toolName: string) =>
    del(`/api/policies/${encodeURIComponent(serverId)}/${encodeURIComponent(toolName)}`),
  bulkBlockHigh: () => post("/api/policies/bulk-block-high"),

  discovered: () => get("/api/discovered"),
};
