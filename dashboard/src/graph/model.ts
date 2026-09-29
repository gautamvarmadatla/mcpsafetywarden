import type { GraphData, Policy } from "@/lib/types";
import { normLevel, RANK, type Level } from "@/components/ui/Severity";

export type GType = "client" | "server" | "tool" | "package" | "credential" | "finding" | "cve" | "technique";

export interface GNode {
  id: string;
  type: GType;
  label: string;
  sub: string;
  name?: string;
  sev?: Level;
  server?: string;
  parent?: string;
  blocked?: boolean;
  meta: Record<string, unknown>;
  idx: number;
}

export interface GEdge {
  s: string;
  t: string;
  rel: string;
  meta: Record<string, unknown>;
}

export interface AttackPath {
  id: string;
  sev: Level;
  title: string;
  note: string;
  nodes: string[];
  mitigated: boolean;
}

export interface Graph {
  N: Record<string, GNode>;
  L: GNode[];
  E: GEdge[];
  out: Record<string, GEdge[]>;
  inn: Record<string, GEdge[]>;
  paths: AttackPath[];
}

const TYPE_MAP: Record<string, GType> = {
  agent_client: "client",
  mcp_server: "server",
  tool: "tool",
  finding: "finding",
  mitre_technique: "technique",
  credential_surface: "credential",
  package: "package",
  package_provenance: "package",
  image: "package",
  iac_resource: "package",
  cve: "cve",
  cve_blast_radius: "cve",
};

const SUBTYPE: Record<string, string> = {
  package: "Package",
  package_provenance: "Provenance",
  image: "Container image",
  iac_resource: "Infrastructure",
  cve: "Advisory",
  cve_blast_radius: "Advisory blast radius",
  credential_surface: "Secret",
};

export const TECHNIQUE_NAMES: Record<string, string> = {
  T1005: "Data from Local System",
  T1036: "Masquerading",
  T1041: "Exfiltration Over C2 Channel",
  T1059: "Command and Scripting Interpreter",
  T1068: "Exploitation for Privilege Escalation",
  T1078: "Valid Accounts",
  T1190: "Exploit Public-Facing Application",
  T1195: "Supply Chain Compromise",
  T1485: "Data Destruction",
  T1499: "Endpoint Denial of Service",
  T1552: "Unsecured Credentials",
  "T1552.005": "Cloud Instance Metadata API",
  T1565: "Data Manipulation",
  T1567: "Exfiltration Over Web Service",
  T1570: "Lateral Tool Transfer",
};

export const RISK_REL = new Set(["can_exfiltrate", "cross_server_exfil"]);
const SKIP_REL = new Set(["invoked"]);

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export function maxLevel(a?: Level, b?: Level): Level | undefined {
  if (!a) return b;
  if (!b) return a;
  return RANK[a] >= RANK[b] ? a : b;
}

export function buildGraph(data: GraphData, policies: Map<string, Policy>): Graph {
  const N: Record<string, GNode> = {};
  const configs = new Set<string>();
  let idx = 0;

  for (const o of data.objects) {
    if (o.type === "mcp_config") {
      configs.add(o.id);
      continue;
    }
    const type = TYPE_MAP[o.type];
    if (!type) continue;
    const meta = o.metadata ?? {};
    const n: GNode = { id: o.id, type, label: o.name || o.id, sub: SUBTYPE[o.type] ?? "", meta, idx: idx++ };
    if (type === "technique") {
      const tid = str(meta.technique_id) || o.name.split(" ")[0];
      n.label = tid;
      n.name = o.name.slice(tid.length).trim() || TECHNIQUE_NAMES[tid] || TECHNIQUE_NAMES[tid.split(".")[0]] || "ATT&CK technique";
      n.sub = "ATT&CK technique";
    }
    if (type === "finding" || type === "cve") {
      const lvl = normLevel(meta.risk_level ?? meta.severity);
      if (lvl !== "NONE") n.sev = lvl;
    }
    if (type === "server") {
      n.server = o.id;
      const lvl = normLevel(meta.overall_risk_level);
      if (lvl !== "NONE") n.sev = lvl;
      n.sub = str(meta.transport).replace(/_/g, " ");
    }
    if (type === "tool") {
      n.server = str(meta.server_id) || o.id.split("::")[0];
      n.sub = str(meta.effect_class).replace(/_/g, " ") || "tool";
    }
    N[o.id] = n;
  }

  for (const n of Object.values(N)) {
    if (n.type !== "tool" || !n.server || N[n.server]) continue;
    N[n.server] = { id: n.server, type: "server", label: n.server, sub: "not in graph yet", server: n.server, meta: {}, idx: idx++ };
  }

  const E: GEdge[] = [];
  const seen = new Set<string>();
  const add = (s: string, t: string, rel: string, meta: Record<string, unknown> = {}) => {
    const k = `${s}|${t}|${rel}`;
    if (seen.has(k) || s === t) return;
    seen.add(k);
    E.push({ s, t, rel, meta });
  };
  const configIn: Record<string, string[]> = {};
  const configOut: Record<string, string[]> = {};

  for (const r of data.relations) {
    if (SKIP_REL.has(r.relation)) continue;
    if (configs.has(r.target) && N[r.source]) (configIn[r.target] ??= []).push(r.source);
    else if (configs.has(r.source) && N[r.target]) (configOut[r.source] ??= []).push(r.target);
    else if (N[r.source] && N[r.target]) add(r.source, r.target, r.relation, r.metadata ?? {});
  }
  for (const c of configs) for (const cl of configIn[c] ?? []) for (const sv of configOut[c] ?? []) add(cl, sv, "declares");
  for (const n of Object.values(N)) if (n.type === "tool" && n.server && N[n.server]?.sub === "not in graph yet") add(n.server, n.id, "exposes");

  for (const e of E) {
    const a = N[e.s];
    const b = N[e.t];
    if (e.rel === "exposes" && a.type === "server" && b.type === "tool") {
      b.parent = a.id;
      b.server = a.id;
    }
    if ((e.rel === "uses_credential" || e.rel === "depends_on" || e.rel === "has_provenance") && a.type === "server") b.server ??= a.id;
  }
  for (const e of E) {
    const a = N[e.s];
    const b = N[e.t];
    if (e.rel === "affected_by" && a.type === "tool" && b.type === "finding") {
      b.parent = a.id;
      b.server = a.server;
      b.sub = a.label;
      a.sev = maxLevel(a.sev, b.sev);
    }
  }
  for (const n of Object.values(N)) {
    if (n.type === "tool") {
      n.blocked = policies.get(`${n.server}::${n.label}`) === "block";
      if (n.server && N[n.server] && !N[n.server].meta.overall_risk_level) N[n.server].sev = maxLevel(N[n.server].sev, n.sev);
    }
  }

  const out: Record<string, GEdge[]> = {};
  const inn: Record<string, GEdge[]> = {};
  for (const e of E) {
    (out[e.s] ??= []).push(e);
    (inn[e.t] ??= []).push(e);
  }
  for (const n of Object.values(N)) {
    if (n.type === "client") {
      const count = (out[n.id] ?? []).filter((e) => e.rel === "declares").length;
      n.sub = `${count} server${count === 1 ? "" : "s"}`;
    }
    if (n.type === "credential") n.sub = n.server ? `Secret, ${n.server}` : "Secret";
    if (n.type === "package" && n.server) n.sub = `${n.sub}, ${n.server}`;
  }

  const L = Object.values(N).sort((a, b) => a.idx - b.idx);
  const g: Graph = { N, L, E, out, inn, paths: [] };
  g.paths = attackPaths(g);
  return g;
}

function worstFinding(g: Graph, toolId: string): GNode | undefined {
  return (g.out[toolId] ?? [])
    .map((e) => g.N[e.t])
    .filter((n) => n.type === "finding")
    .sort((a, b) => RANK[b.sev ?? "NONE"] - RANK[a.sev ?? "NONE"])[0];
}

function technique(g: Graph, findingId?: string): GNode | undefined {
  if (!findingId) return undefined;
  return (g.out[findingId] ?? []).map((e) => g.N[e.t]).find((n) => n.type === "technique");
}

function clientOf(g: Graph, serverId?: string): string | undefined {
  if (!serverId) return undefined;
  return (g.inn[serverId] ?? []).find((e) => g.N[e.s].type === "client")?.s;
}

function attackPaths(g: Graph): AttackPath[] {
  const paths: AttackPath[] = [];
  for (const e of g.E) {
    if (!RISK_REL.has(e.rel)) continue;
    const a = g.N[e.s];
    const b = g.N[e.t];
    if (a.type !== "tool" || b.type !== "tool") continue;
    const f = worstFinding(g, b.id) ?? worstFinding(g, a.id);
    const tech = technique(g, f?.id);
    const nodes = [clientOf(g, a.server), a.server, a.id, b.id, f?.id, tech?.id].filter((x): x is string => !!x && !!g.N[x]);
    const cross = a.server !== b.server;
    paths.push({
      id: `rel:${e.s}>${e.t}`,
      sev: maxLevel(maxLevel(f?.sev, normLevel(e.meta.risk_level) === "NONE" ? undefined : normLevel(e.meta.risk_level)), "HIGH") ?? "HIGH",
      title: cross ? `${a.server}.${a.label} can send data to ${b.server}.${b.label}` : `${a.label} output can steer ${b.label}`,
      note: str(e.meta.reason) || (cross ? "Content read by one server can flow into an outbound action on another." : "One tool's output can drive a write on the same server."),
      nodes,
      mitigated: !!(a.blocked || b.blocked),
    });
  }
  for (const f of g.L) {
    if (f.type !== "finding" || RANK[f.sev ?? "NONE"] < 3 || !f.parent) continue;
    const tool = g.N[f.parent];
    if (paths.some((p) => p.nodes.includes(f.id))) continue;
    const tech = technique(g, f.id);
    const nodes = [clientOf(g, tool.server), tool.server, tool.id, f.id, tech?.id].filter((x): x is string => !!x && !!g.N[x]);
    paths.push({
      id: `finding:${f.id}`,
      sev: f.sev!,
      title: f.label,
      note: str(f.meta.exploitation_scenario) || str(f.meta.remediation) || `${tool.server}.${tool.label}`,
      nodes,
      mitigated: !!tool.blocked,
    });
  }
  return paths
    .sort((x, y) => Number(x.mitigated) - Number(y.mitigated) || RANK[y.sev] - RANK[x.sev])
    .slice(0, 10);
}
