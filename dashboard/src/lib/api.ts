import type {
  Activity,
  Discovered,
  FindingsResponse,
  GraphData,
  Overview,
  Paged,
  PolicyRow,
  RegisterInput,
  RunStats,
  RunsResponse,
  Scan,
  ScanStatus,
  ServerDetail,
  ServerRow,
  Snapshot,
  Tool,
  ToolDetail,
  Policy,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type Params = Record<string, string | number | boolean | null | undefined>;

function qs(params?: Params): string {
  if (!params) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" ? { "X-Warden-Client": "dashboard" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (typeof data?.detail === "string") message = data.detail;
      else if (Array.isArray(data?.detail)) message = data.detail.map((d: { msg?: string }) => d.msg).join(", ");
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, message);
  }
  return res.json() as Promise<T>;
}

const get = <T>(path: string, params?: Params) => request<T>("GET", path + qs(params));
const enc = encodeURIComponent;

export const api = {
  health: () => get<{ ok: boolean; db_path?: string; server_count?: number; error?: string }>("/api/health"),
  overview: () => get<Overview>("/api/overview"),

  servers: () => get<ServerRow[]>("/api/servers"),
  server: (id: string) => get<ServerDetail>(`/api/servers/${enc(id)}`),
  serverScan: (id: string) => get<Scan>(`/api/servers/${enc(id)}/scan`),
  serverSnapshots: (id: string) => get<Snapshot[]>(`/api/servers/${enc(id)}/snapshots`),

  tools: (params?: Params) => get<Paged<Tool>>("/api/tools", params),
  tool: (serverId: string, toolName: string) => get<ToolDetail>(`/api/tools/${enc(serverId)}/${enc(toolName)}`),
  activity: (days = 7) => get<Activity>("/api/tools/activity", { days }),

  findings: (params?: Params) => get<FindingsResponse>("/api/findings", { limit: 500, ...params }),

  runs: (params?: Params) => get<RunsResponse>("/api/runs", params),
  runStats: (hours = 24) => get<RunStats>("/api/runs/stats", { hours }),

  graph: () => get<GraphData>("/api/graph"),
  rebuildGraph: () => request<{ rebuilt: boolean; error?: string }>("POST", "/api/graph/rebuild"),

  policies: () => get<PolicyRow[]>("/api/policies"),
  setPolicy: (server_id: string, tool_name: string, policy: Policy) =>
    request<{ ok: boolean }>("POST", "/api/policies", { server_id, tool_name, policy }),
  deletePolicy: (serverId: string, toolName: string) =>
    request<{ ok: boolean }>("DELETE", `/api/policies/${enc(serverId)}/${enc(toolName)}`),

  scanStatus: () => get<ScanStatus>("/api/scans/status"),
  scanServer: (id: string) =>
    request<ScanStatus & { queued: string[] }>("POST", `/api/servers/${enc(id)}/scan`, { confirm_authorized: true }),
  scanServers: (ids?: string[]) =>
    request<ScanStatus & { queued: string[] }>("POST", "/api/scans", { confirm_authorized: true, server_ids: ids ?? null }),
  cancelQueuedScans: () => request<ScanStatus & { cleared: number }>("DELETE", "/api/scans/queue"),

  discovered: () => get<Discovered[]>("/api/discovered"),
  discover: () => request<{ count: number }>("POST", "/api/discover"),
  onboardDiscovered: (ids: string[]) =>
    request<{ registered?: number; results?: { status: string; server_id?: string; error?: string }[] }>(
      "POST",
      "/api/discovered/onboard",
      { discovery_ids: ids }
    ),
  register: (input: RegisterInput) =>
    request<{ server_id: string; tools_discovered?: number; inspect_error?: string }>("POST", "/api/servers", input),
};

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
