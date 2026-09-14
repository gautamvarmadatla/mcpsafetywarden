import { RANK } from "@/components/ui/Severity";
import { RISK_REL, type GEdge, type GNode, type GType, type Graph } from "./model";

export type FilterKey = "client" | "tool" | "package" | "credential" | "finding" | "technique";

export interface ViewState {
  collapsed: Record<string, boolean>;
  scope: string[];
  path: string | null;
  filters: Record<FilterKey, boolean>;
  serverScope: "risk" | "all";
  sel: string | null;
  hover: string | null;
}

export interface VEdge {
  s: string;
  t: string;
  rel: string;
  n: number;
  agg: boolean;
}

export interface Model {
  nodes: GNode[];
  edges: VEdge[];
  vis: Set<string>;
  rep: (id: string) => string | null;
  exp: (serverId: string) => boolean;
  scope: string | null;
  limited: boolean;
}

export interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

export const COL: Record<GType, number> = { client: 0, server: 1, tool: 2, package: 2, credential: 2, finding: 3, cve: 3, technique: 4 };
export const HEADS = ["Clients", "Servers", "Tools, packages and secrets", "Findings", "ATT&CK techniques"];
const FTYPE: Record<GType, FilterKey | null> = {
  client: "client",
  server: null,
  tool: "tool",
  package: "package",
  credential: "credential",
  finding: "finding",
  cve: "finding",
  technique: "technique",
};
const TYPE_ORDER: Partial<Record<GType, number>> = { tool: 0, package: 1, credential: 2 };
const PRUNE: GType[] = ["client", "technique", "cve", "package", "credential"];

export function scopeSet(g: Graph, id: string): Set<string> {
  const seen = new Set([id]);
  let st = [id];
  while (st.length) {
    const c = st.pop()!;
    for (const e of g.out[c] ?? []) if (!seen.has(e.t)) seen.add(e.t), st.push(e.t);
  }
  st = [id];
  while (st.length) {
    const c = st.pop()!;
    for (const e of g.inn[c] ?? []) if (!seen.has(e.s)) seen.add(e.s), st.push(e.s);
  }
  for (const k of [...seen]) {
    let n: GNode | undefined = g.N[k];
    while (n?.parent) {
      seen.add(n.parent);
      n = g.N[n.parent];
    }
  }
  return seen;
}

export function riskyServers(g: Graph): Set<string> {
  const out = new Set<string>();
  for (const n of g.L) {
    if (n.type === "server" && n.sev && RANK[n.sev] >= 1) out.add(n.id);
    if (n.type === "tool" && n.server && (n.sev || n.blocked)) out.add(n.server);
  }
  for (const e of g.E) {
    if (!RISK_REL.has(e.rel)) continue;
    const a = g.N[e.s];
    const b = g.N[e.t];
    if (a.server) out.add(a.server);
    if (b.server) out.add(b.server);
  }
  return out;
}

export const FOCUS_LIMIT = 40;

export function focusServers(g: Graph): { ids: Set<string>; kind: "risk" | "largest"; total: number } | null {
  const risky = riskyServers(g);
  if (risky.size) {
    if (risky.size <= FOCUS_LIMIT) return { ids: risky, kind: "risk", total: risky.size };
    const score = new Map<string, number>();
    for (const id of risky) score.set(id, RANK[g.N[id]?.sev ?? "NONE"] * 1000);
    for (const n of g.L) if (n.type === "tool" && n.server && n.sev) score.set(n.server, (score.get(n.server) ?? 0) + RANK[n.sev] * 50);
    for (const e of g.E) {
      if (!RISK_REL.has(e.rel)) continue;
      for (const id of [g.N[e.s]?.server, g.N[e.t]?.server]) if (id && score.has(id)) score.set(id, score.get(id)! + 1);
    }
    const top = [...risky].sort((a, b) => (score.get(b) ?? 0) - (score.get(a) ?? 0) || a.localeCompare(b)).slice(0, FOCUS_LIMIT);
    return { ids: new Set(top), kind: "risk", total: risky.size };
  }
  const servers = g.L.filter((n) => n.type === "server");
  if (servers.length <= FOCUS_LIMIT) return null;
  const tools = new Map<string, number>();
  for (const n of g.L) if (n.type === "tool" && n.server) tools.set(n.server, (tools.get(n.server) ?? 0) + 1);
  const top = [...servers].sort((a, b) => (tools.get(b.id) ?? 0) - (tools.get(a.id) ?? 0) || a.label.localeCompare(b.label)).slice(0, FOCUS_LIMIT);
  return { ids: new Set(top.map((n) => n.id)), kind: "largest", total: servers.length };
}

export function buildModel(g: Graph, st: ViewState): Model {
  const sc = st.scope.length ? st.scope[st.scope.length - 1] : null;
  const inS = sc ? scopeSet(g, sc) : null;
  const path = st.path ? g.paths.find((p) => p.id === st.path) : undefined;
  const pexp = new Set<string>();
  for (const id of path?.nodes ?? []) {
    const n = g.N[id];
    if (n?.type === "tool" && n.parent) pexp.add(n.parent);
    if (n?.type === "finding" && n.parent && g.N[n.parent]?.parent) pexp.add(g.N[n.parent].parent!);
  }
  const focus = focusServers(g);
  const risky = focus?.ids ?? new Set<string>();
  const limited = st.serverScope === "risk" && !sc && !path && !!focus && focus.ids.size < g.L.filter((n) => n.type === "server").length;
  const exp = (sid: string) => !!sc || pexp.has(sid) || st.collapsed[sid] === false;

  const memo = new Map<string, string | null>();
  const rep = (id: string): string | null => {
    if (memo.has(id)) return memo.get(id)!;
    const n = g.N[id];
    let r: string | null;
    if (!n) r = null;
    else if (inS && !inS.has(id)) r = null;
    else if (limited && n.type === "server" && !risky.has(n.id)) r = null;
    else if (limited && n.server && !risky.has(n.server)) r = null;
    else {
      const f = FTYPE[n.type];
      if (f && !st.filters[f]) r = n.parent ? rep(n.parent) : null;
      else if (n.type === "tool" && n.parent && !exp(n.parent)) r = rep(n.parent);
      else if (n.type === "finding" && n.parent && g.N[n.parent]?.parent && !exp(g.N[n.parent].parent!)) r = rep(n.parent);
      else r = id;
    }
    memo.set(id, r);
    return r;
  };

  const em = new Map<string, VEdge>();
  for (const e of g.E) {
    const a = rep(e.s);
    const b = rep(e.t);
    if (!a || !b || a === b) continue;
    const k = `${a}|${b}|${e.rel}`;
    const agg = a !== e.s || b !== e.t;
    const cur = em.get(k);
    if (cur) {
      cur.n++;
      if (!agg) cur.agg = false;
    } else em.set(k, { s: a, t: b, rel: e.rel, n: 1, agg });
  }
  let edges = [...em.values()];
  const touched = new Set<string>();
  for (const e of edges) touched.add(e.s), touched.add(e.t);
  const nodes = g.L.filter((n) => rep(n.id) === n.id && (!PRUNE.includes(n.type) || touched.has(n.id) || n.id === sc));
  const vis = new Set(nodes.map((n) => n.id));
  edges = edges.filter((e) => vis.has(e.s) && vis.has(e.t));
  return { nodes, edges, vis, rep, exp, scope: sc, limited };
}

export function layout(m: Model): Record<string, Box> {
  const W = 208;
  const CW = 276;
  const GAP = 12;
  const GG = 24;
  const P: Record<string, Box> = {};
  const cols: GNode[][] = [[], [], [], [], []];
  const H = (n: GNode) => (n.type === "server" ? 60 : 54);
  for (const n of m.nodes) cols[COL[n.type]].push(n);

  const servers = [...cols[1]].sort((a, b) => RANK[b.sev ?? "NONE"] - RANK[a.sev ?? "NONE"] || a.label.localeCompare(b.label));
  const so = new Map(servers.map((s, i) => [s.id, i]));
  const sOrd = (n: GNode) => (n.server && so.has(n.server) ? so.get(n.server)! : 1e6);
  cols[2].sort((a, b) => sOrd(a) - sOrd(b) || (TYPE_ORDER[a.type] ?? 9) - (TYPE_ORDER[b.type] ?? 9) || a.idx - b.idx);

  let y = 0;
  cols[2].forEach((n, i) => {
    if (i) y += GAP + (cols[2][i - 1].server !== n.server ? GG : 0);
    P[n.id] = { x: 2 * CW, y, w: W, h: H(n) };
    y += H(n);
  });

  const center = (id: string) => (P[id] ? P[id].y + P[id].h / 2 : null);
  const mean = (a: (number | null)[]) => {
    const v = a.filter((x): x is number => x != null);
    return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null;
  };
  const succ = (id: string) => m.edges.filter((e) => e.s === id).map((e) => center(e.t));
  const pred = (id: string) => m.edges.filter((e) => e.t === id).map((e) => center(e.s));

  const place = (c: number, list: GNode[], des: (n: GNode) => number | null, sortByDesire: boolean) => {
    const d = new Map(list.map((n) => [n.id, des(n)]));
    const ordered = sortByDesire
      ? [...list].sort((a, b) => (d.get(a.id) ?? 1e9) - (d.get(b.id) ?? 1e9) || a.idx - b.idx)
      : list;
    let prev = -1e9;
    let last = 0;
    for (const n of ordered) {
      let want = d.get(n.id);
      if (want == null) want = last;
      const yy = Math.max(want - H(n) / 2, prev + GAP);
      P[n.id] = { x: c * CW, y: yy, w: W, h: H(n) };
      prev = yy + H(n);
      last = prev + GAP + H(n) / 2;
    }
  };

  place(1, servers, (n) => mean(succ(n.id)), false);
  place(0, cols[0], (n) => mean(succ(n.id)), true);
  place(3, cols[3], (n) => mean(pred(n.id)), true);
  place(4, cols[4], (n) => mean(pred(n.id)), true);
  return P;
}

export interface Highlight {
  any: boolean;
  nodes: Set<string>;
  edges: Set<number>;
  flow: Set<number>;
  labels: Set<number>;
}

export function highlight(g: Graph, m: Model, st: ViewState): Highlight {
  const nodes = new Set<string>();
  const edges = new Set<number>();
  const flow = new Set<number>();
  const labels = new Set<number>();
  const sel = st.sel && m.vis.has(st.sel) ? st.sel : null;
  const path = st.path ? g.paths.find((p) => p.id === st.path) : undefined;

  if (sel) {
    nodes.add(sel);
    for (const [from, to] of [
      ["s", "t"],
      ["t", "s"],
    ] as const) {
      const seen = new Set([sel]);
      const stack = [sel];
      while (stack.length) {
        const c = stack.pop()!;
        m.edges.forEach((e, i) => {
          if (e[from] !== c) return;
          edges.add(i);
          if (!seen.has(e[to])) {
            seen.add(e[to]);
            nodes.add(e[to]);
            stack.push(e[to]);
          }
        });
      }
    }
  } else if (path) {
    const r = path.nodes.map((id) => m.rep(id));
    r.forEach((id) => id && nodes.add(id));
    for (let i = 0; i < r.length - 1; i++)
      m.edges.forEach((e, j) => {
        if (e.s === r[i] && e.t === r[i + 1]) {
          edges.add(j);
          flow.add(j);
        }
      });
  } else if (st.hover && m.vis.has(st.hover)) {
    nodes.add(st.hover);
    m.edges.forEach((e, i) => {
      if (e.s === st.hover || e.t === st.hover) {
        edges.add(i);
        nodes.add(e.s);
        nodes.add(e.t);
      }
    });
  }
  m.edges.forEach((e, i) => {
    if (edges.has(i) && (RISK_REL.has(e.rel) || (st.hover && (e.s === st.hover || e.t === st.hover)))) labels.add(i);
  });
  return { any: nodes.size > 0, nodes, edges, flow, labels };
}

const UP_ORDER = ["exposes", "affected_by", "declares", "depends_on", "uses_credential", "has_provenance", "cross_server_exfil", "can_exfiltrate", "maps_to"];

export type ChainStep = { id: string; rel: string | null };

export function chainFor(g: Graph, id: string): ChainStep[] {
  const up: GEdge[] = [];
  let cur = id;
  const seen = new Set([id]);
  for (;;) {
    const ins = (g.inn[cur] ?? []).filter((e) => !seen.has(e.s)).sort((a, b) => UP_ORDER.indexOf(a.rel) - UP_ORDER.indexOf(b.rel));
    if (!ins.length) break;
    up.unshift(ins[0]);
    seen.add(ins[0].s);
    cur = ins[0].s;
  }
  const score = new Map<string, number>();
  const scoreOf = (n: string, depth = 0): number => {
    if (score.has(n)) return score.get(n)!;
    if (depth > 12) return 0;
    score.set(n, 0);
    const node = g.N[n];
    let s = node.sev && node.type !== "server" ? RANK[node.sev] * 10 : 0;
    for (const e of g.out[n] ?? []) s = Math.max(s, scoreOf(e.t, depth + 1) + (RISK_REL.has(e.rel) ? 5 : 0));
    score.set(n, s);
    return s;
  };
  const down: GEdge[] = [];
  cur = id;
  while (down.length < 8) {
    const outs = (g.out[cur] ?? []).filter((e) => !seen.has(e.t));
    if (!outs.length) break;
    outs.sort((a, b) => scoreOf(b.t) + (RISK_REL.has(b.rel) ? 5 : 0) - scoreOf(a.t) - (RISK_REL.has(a.rel) ? 5 : 0));
    down.push(outs[0]);
    seen.add(outs[0].t);
    cur = outs[0].t;
  }
  const steps: ChainStep[] = [];
  if (up.length) steps.push({ id: up[0].s, rel: null });
  up.forEach((e) => steps.push({ id: e.t, rel: e.rel }));
  if (!up.length) steps.push({ id, rel: null });
  down.forEach((e) => steps.push({ id: e.t, rel: e.rel }));
  return steps;
}

export function pathSteps(g: Graph, nodes: string[]): ChainStep[] {
  return nodes.map((id, i) => {
    if (!i) return { id, rel: null };
    const e = (g.out[nodes[i - 1]] ?? []).find((x) => x.t === id);
    return { id, rel: e?.rel ?? null };
  });
}
