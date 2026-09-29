import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import useSWR from "swr";
import { api, errorMessage } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { buildGraph, RISK_REL, type Graph as G, type GNode } from "@/graph/model";
import { buildModel, chainFor, focusServers, highlight, layout, pathSteps, scopeSet, type ChainStep, type FilterKey, type ViewState } from "@/graph/layout";
import { GraphEngine, REL_LABEL, glyph } from "@/graph/engine";
import Severity from "@/components/ui/Severity";
import Button from "@/components/ui/Button";
import Seg from "@/components/ui/Seg";
import { useToast } from "@/components/ui/Toast";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";
import { isTyping } from "@/components/Shell";

const TNAME: Record<string, string> = {
  client: "MCP client",
  server: "Server",
  tool: "Tool",
  package: "Package",
  credential: "Secret",
  finding: "Finding",
  cve: "Advisory",
  technique: "ATT&CK technique",
};
const FILTERS: [FilterKey, string][] = [
  ["client", "Clients"],
  ["tool", "Tools"],
  ["package", "Packages"],
  ["credential", "Secrets"],
  ["finding", "Findings"],
  ["technique", "Techniques"],
];
const INVERSE: Record<string, string> = {
  declares: "declared by",
  exposes: "exposed by",
  affected_by: "affects",
  maps_to: "mapped from",
  depends_on: "used by",
  uses_credential: "used by",
  can_exfiltrate: "fed by",
  cross_server_exfil: "receives data from",
};
const sansTypes = new Set(["finding", "client", "cve"]);

function Glyph({ n }: { n: Pick<GNode, "type" | "sev"> }) {
  return <span dangerouslySetInnerHTML={{ __html: glyph(n) }} style={{ display: "inline-flex" }} />;
}

function Stepper({ g, steps, current, onPick }: { g: G; steps: ChainStep[]; current?: string | null; onPick: (id: string) => void }) {
  return (
    <ol className="chain">
      {steps.map((s, i) => {
        const n = g.N[s.id];
        if (!n) return null;
        const sub = n.type === "technique" ? n.name : n.type === "finding" ? `${n.server}.${n.sub}` : `${TNAME[n.type]}${n.server && n.type !== "server" ? `, ${n.server}` : ""}`;
        return (
          <li key={`${s.id}-${i}`} style={{ display: "contents" }}>
            {i > 0 && s.rel && <div className={`rel${RISK_REL.has(s.rel) ? " risk" : ""}`}>{REL_LABEL[s.rel] ?? s.rel}</div>}
            <button type="button" className={`step${s.id === current ? " cur" : ""}`} onClick={() => onPick(s.id)}>
              <Glyph n={n} />
              <span>
                <b className={sansTypes.has(n.type) ? "" : "mono"}>{n.label}</b>
                <small>{sub}</small>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export default function Graph() {
  const navigate = useNavigate();
  const toast = useToast();
  const { data, error, isLoading, mutate } = useSWR("graph", api.graph);
  const { data: policies } = useSWR("policies", api.policies);
  const [st, setSt] = useState<ViewState>({
    collapsed: {},
    scope: [],
    path: null,
    filters: { client: true, tool: true, package: true, credential: true, finding: true, technique: true },
    serverScope: "risk",
    sel: null,
    hover: null,
  });
  const [q, setQ] = useState("");
  const [zoom, setZoom] = useState(100);
  const [rebuilding, setRebuilding] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);
  const engine = useRef<GraphEngine | null>(null);
  const pending = useRef<{ fit?: boolean; ids?: string[]; anchor?: string; focus?: string; instant?: boolean }>({ fit: true, instant: true });
  const stRef = useRef(st);
  stRef.current = st;

  const policyMap = useMemo(() => new Map<string, Policy>((policies ?? []).map((p) => [`${p.server_id}::${p.tool_name}`, p.policy])), [policies]);
  const graph = useMemo(() => (data ? buildGraph(data, policyMap) : null), [data, policyMap]);
  const focus = useMemo(() => (graph ? focusServers(graph) : null), [graph]);
  const risky = useMemo(() => focus?.ids ?? new Set<string>(), [focus]);
  const focusLabel = focus?.kind === "largest" ? `Largest ${risky.size}` : focus && focus.total > risky.size ? `Top ${risky.size} at risk` : "With risk";
  const serverCount = useMemo(() => graph?.L.filter((n) => n.type === "server").length ?? 0, [graph]);
  const model = useMemo(
    () => (graph ? buildModel(graph, { ...st, sel: null, hover: null }) : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [graph, st.collapsed, st.scope, st.path, st.filters, st.serverScope]
  );
  const boxes = useMemo(() => (model ? layout(model) : null), [model]);
  const hl = useMemo(() => (graph && model ? highlight(graph, model, st) : null), [graph, model, st]);
  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const out = new Set<string>();
    if (needle.length < 2 || !model) return out;
    for (const n of model.nodes) if (`${n.label} ${n.name ?? ""} ${n.server ?? ""}`.toLowerCase().includes(needle)) out.add(n.id);
    return out;
  }, [q, model]);

  const hasGraph = !!graph && graph.L.length > 0;

  useEffect(() => {
    if (!hasGraph || !canvasRef.current) return;
    const eng = new GraphEngine(canvasRef.current, {
      select: (id) => setSt((s) => ({ ...s, sel: id, path: null })),
      drill: (id) => {
        pending.current = { fit: true };
        setSt((s) => ({ ...s, scope: s.scope[s.scope.length - 1] === id ? s.scope : [...s.scope, id], sel: id, path: null }));
      },
      toggle: (id) => {
        pending.current = { anchor: id };
        setSt((s) => ({ ...s, collapsed: { ...s.collapsed, [id]: s.collapsed[id] === false } }));
      },
      background: () => {
        const s = stRef.current;
        if (s.sel || s.path) setSt({ ...s, sel: null, path: null });
      },
      hover: (id) => {
        if (stRef.current.hover !== id) setSt((s) => ({ ...s, hover: id }));
      },
      zoom: (k) => setZoom((z) => (Math.round(k * 100) === z ? z : Math.round(k * 100))),
    });
    engine.current = eng;
    pending.current = { fit: true, instant: true };
    return () => {
      eng.destroy();
      engine.current = null;
    };
  }, [hasGraph]);

  useEffect(() => {
    if (!engine.current || !graph || !model || !boxes || !hl) return;
    engine.current.update(graph, model, boxes, hl, pending.current);
    pending.current = {};
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, model, boxes, hasGraph]);

  useEffect(() => {
    if (hl) engine.current?.setHighlight(hl);
  }, [hl]);

  useEffect(() => {
    engine.current?.mark(st.sel, st.hover, matches);
  }, [st.sel, st.hover, matches, model]);

  const reveal = useCallback(
    (id: string, center = true) => {
      if (!graph) return;
      const n = graph.N[id];
      if (!n) return;
      setSt((s) => {
        const next: ViewState = { ...s, sel: id, path: null, collapsed: { ...s.collapsed }, filters: { ...s.filters } };
        let changed = false;
        const scope = s.scope[s.scope.length - 1];
        if (scope && !scopeSet(graph, scope).has(id)) {
          next.scope = [];
          changed = true;
        }
        if (s.serverScope === "risk" && ((n.type === "server" && !risky.has(n.id)) || (n.server && !risky.has(n.server)))) {
          next.serverScope = "all";
          changed = true;
        }
        const f = ({ client: "client", tool: "tool", package: "package", credential: "credential", finding: "finding", cve: "finding", technique: "technique" } as Record<string, FilterKey>)[n.type];
        if (f && !next.filters[f]) {
          next.filters[f] = true;
          changed = true;
        }
        const srv = n.type === "tool" ? n.parent : n.type === "finding" && n.parent ? graph.N[n.parent]?.parent : undefined;
        if (n.type === "finding" && !next.filters.tool) next.filters.tool = true;
        if (srv && next.collapsed[srv] !== false) {
          next.collapsed[srv] = false;
          changed = true;
        }
        if (s.path) changed = true;
        pending.current = changed || center ? { focus: id } : {};
        return next;
      });
    },
    [graph, risky]
  );

  const drill = (id: string) => {
    pending.current = { fit: true };
    setSt((s) => ({ ...s, scope: s.scope[s.scope.length - 1] === id ? s.scope : [...s.scope, id], sel: id, path: null }));
  };

  const pickPath = (id: string) => {
    if (!graph) return;
    const p = graph.paths.find((x) => x.id === id);
    if (!p) return;
    if (st.path === id) {
      pending.current = { fit: true };
      setSt((s) => ({ ...s, path: null }));
      return;
    }
    const nextState = { ...st, path: id, sel: null, scope: [], serverScope: "all" as const };
    const m = buildModel(graph, nextState);
    pending.current = { fit: true, ids: p.nodes.map((n) => m.rep(n)).filter((x): x is string => !!x) };
    setSt(nextState);
  };

  const allExpanded = !!graph && graph.L.filter((n) => n.type === "server").every((n) => st.collapsed[n.id] === false);
  const toggleAll = () => {
    if (!graph) return;
    const collapsed: Record<string, boolean> = {};
    for (const n of graph.L) if (n.type === "server") collapsed[n.id] = allExpanded;
    pending.current = { fit: true };
    setSt((s) => ({ ...s, collapsed }));
  };

  const rebuild = async () => {
    setRebuilding(true);
    try {
      const res = await api.rebuildGraph();
      if (!res.rebuilt) throw new Error(res.error ?? "rebuild failed");
      pending.current = { fit: true };
      await mutate();
      toast("Graph rebuilt from the latest inventory and scans.");
    } catch (e) {
      toast(`Could not rebuild the graph: ${errorMessage(e)}`);
    } finally {
      setRebuilding(false);
    }
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || document.querySelector(".pal-wrap.on, .dialog-wrap")) return;
      const typing = isTyping();
      if (e.key === "Escape") {
        if (typing) {
          (document.activeElement as HTMLElement).blur();
          return;
        }
        const s = stRef.current;
        if (s.sel) setSt({ ...s, sel: null });
        else if (s.path) {
          pending.current = { fit: true };
          setSt({ ...s, path: null });
        } else if (s.scope.length) {
          pending.current = { fit: true };
          const scope = s.scope.slice(0, -1);
          setSt({ ...s, scope, sel: scope[scope.length - 1] ?? null });
        }
        return;
      }
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "f" || e.key === "F") engine.current?.fit();
      else if (e.key === "+" || e.key === "=") engine.current?.zoomBy(1.25);
      else if (e.key === "-" || e.key === "_") engine.current?.zoomBy(0.8);
      else if (e.key === "Enter" && stRef.current.sel) drill(stRef.current.sel);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const onSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== "Enter" || !graph) return;
    e.preventDefault();
    e.stopPropagation();
    const needle = q.trim().toLowerCase();
    if (!needle) return;
    const order = ["server", "tool", "finding", "client", "technique", "package", "credential", "cve"];
    const hit = graph.L.filter((n) => `${n.label} ${n.name ?? ""}`.toLowerCase().includes(needle)).sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type))[0];
    if (hit) {
      reveal(hit.id);
      e.currentTarget.blur();
    } else toast(`Nothing in the graph matches “${q}”.`);
  };

  if (error) return <ErrorBanner error={error} onRetry={() => mutate()} />;

  const selNode = st.sel && graph ? graph.N[st.sel] : null;
  const path = st.path && graph ? graph.paths.find((p) => p.id === st.path) : null;

  const inspector = (() => {
    if (!graph || !model) return null;
    if (selNode) {
      const n = selNode;
      const kv: [string, React.ReactNode][] = [];
      if (n.type === "server") kv.push(["Transport", n.sub || "unknown"], ["Risk", n.sev ? <Severity level={n.sev} /> : "Not scanned"]);
      if (n.type === "tool") {
        kv.push(["Server", <span className="mono">{n.server}</span>], ["Effect", n.sub]);
        if (n.sev) kv.push(["Risk", <Severity level={n.sev} />]);
        kv.push(["Policy", n.blocked ? <span className="pol-block">Blocked</span> : "Default or allowed"]);
      }
      if (n.type === "finding") kv.push(["Severity", <Severity level={n.sev} />], ["Tool", <span className="mono">{`${n.server}.${n.sub}`}</span>]);
      if (n.type === "technique") kv.push(["Name", n.name ?? ""], ["Tactic", String(n.meta.tactic ?? "") || "ATT&CK"]);
      if (["package", "credential", "cve", "client"].includes(n.type)) kv.push(["Detail", n.sub || TNAME[n.type]]);
      const conn = new Map<string, string[]>();
      for (const e of graph.out[n.id] ?? []) conn.set(REL_LABEL[e.rel] ?? e.rel, [...(conn.get(REL_LABEL[e.rel] ?? e.rel) ?? []), e.t]);
      for (const e of graph.inn[n.id] ?? []) {
        const k = INVERSE[e.rel] ?? e.rel;
        conn.set(k, [...(conn.get(k) ?? []), e.s]);
      }
      return (
        <>
          <div className="gi-type">
            <Glyph n={n} />
            {TNAME[n.type]}
          </div>
          <h2 className={sansTypes.has(n.type) ? "" : "mono"}>{n.type === "technique" ? `${n.label} ${n.name}` : n.label}</h2>
          <dl className="gi-kv">
            {kv.map(([k, v]) => (
              <div key={k} style={{ display: "contents" }}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
          <div className="gi-acts">
            <Button variant="primary" size="sm" onClick={() => drill(n.id)}>
              Drill into chain
            </Button>
            {n.type === "server" && !st.scope.length && (
              <Button size="sm" onClick={() => {
                pending.current = { anchor: n.id };
                setSt((s) => ({ ...s, collapsed: { ...s.collapsed, [n.id]: s.collapsed[n.id] === false } }));
              }}>
                {model.exp(n.id) ? "Hide tools" : "Show tools"}
              </Button>
            )}
            {n.type === "server" && (
              <Button size="sm" variant="quiet" onClick={() => navigate(`/servers/${encodeURIComponent(n.id)}`)}>
                Open server
              </Button>
            )}
            {n.type === "tool" && (
              <Button size="sm" variant="quiet" onClick={() => navigate(`/tools?open=${encodeURIComponent(`${n.server}::${n.label}`)}`)}>
                Open tool
              </Button>
            )}
            {n.type === "finding" && n.parent && (
              <Button size="sm" onClick={() => navigate(`/findings?open=${encodeURIComponent(`${n.server}::${graph.N[n.parent!]?.label}`)}`)}>
                Open finding
              </Button>
            )}
          </div>
          <h3>Dependency chain</h3>
          <Stepper g={graph} steps={chainFor(graph, n.id)} current={n.id} onPick={(id) => reveal(id)} />
          <h3>Connections</h3>
          <div className="gconn">
            {[...conn.entries()].map(([k, ids]) => (
              <div key={k}>
                <div className="grp2">
                  {k[0].toUpperCase() + k.slice(1)} <span>{ids.length}</span>
                </div>
                {ids.slice(0, 6).map((id) => {
                  const m = graph.N[id];
                  return (
                    <button key={id} type="button" onClick={() => reveal(id)}>
                      <Glyph n={m} />
                      <span className={sansTypes.has(m.type) ? "" : "mono"}>{m.type === "technique" ? `${m.label} ${m.name}` : m.label}</span>
                    </button>
                  );
                })}
                {ids.length > 6 && <div className="more">and {ids.length - 6} more</div>}
              </div>
            ))}
          </div>
        </>
      );
    }
    if (path) {
      return (
        <>
          <div className="gi-type">
            <Severity level={path.sev} />
            <span>Attack path</span>
            {path.mitigated && <span className="gpaths mit" style={{ color: "var(--safe)", fontWeight: 500 }}>Mitigated</span>}
          </div>
          <h2>{path.title}</h2>
          <p className="gi-note">{path.note}</p>
          {path.mitigated && <p className="gi-note">A tool on this path is blocked by policy, so the chain is broken.</p>}
          <div className="gi-acts">
            <Button size="sm" onClick={() => pickPath(path.id)}>
              Show all paths
            </Button>
          </div>
          <h3>Steps</h3>
          <Stepper g={graph} steps={pathSteps(graph, path.nodes)} onPick={(id) => reveal(id)} />
        </>
      );
    }
    return (
      <>
        <h3 style={{ marginTop: 0 }}>
          Attack paths <span className="muted">{graph.paths.length}</span>
        </h3>
        {graph.paths.length === 0 ? (
          <p className="gi-note">No attack paths yet. Paths appear when a scan flags risky tools or finds data flowing between them.</p>
        ) : (
          <>
            <p className="gi-note">Chains where untrusted input can reach a risky action. Select one to trace it.</p>
            <ul className="gpaths">
              {graph.paths.map((p) => (
                <li key={p.id}>
                  <button type="button" onClick={() => pickPath(p.id)}>
                    <span className="row1">
                      <Severity level={p.sev} />
                      {p.mitigated && <span className="mit">Mitigated</span>}
                    </span>
                    <span className="t">{p.title}</span>
                    <span className="r mono">
                      {p.nodes
                        .map((id) => graph.N[id])
                        .filter((x) => x.type === "tool")
                        .map((x) => `${x.server}.${x.label}`)
                        .join(" → ")}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
        <h3>Reading the graph</h3>
        <div className="glegend">
          {(["client", "server", "tool", "package", "credential", "technique"] as const).map((t) => (
            <div key={t}>
              <Glyph n={{ type: t }} />
              {TNAME[t]}
            </div>
          ))}
          <div>
            <Glyph n={{ type: "finding", sev: "HIGH" }} />
            Finding, coloured by severity
          </div>
          <div>
            <svg width="22" height="8">
              <line x1="0" y1="4" x2="22" y2="4" stroke="var(--edge)" strokeWidth="1.5" />
            </svg>
            Structure
          </div>
          <div>
            <svg width="22" height="8">
              <line x1="0" y1="4" x2="22" y2="4" stroke="var(--crit)" strokeWidth="1.5" />
            </svg>
            Data can flow to a risky tool
          </div>
          <div>
            <svg width="22" height="8">
              <line x1="0" y1="4" x2="22" y2="4" stroke="var(--edge)" strokeWidth="1.5" strokeDasharray="3 3" />
            </svg>
            Finding or mapping
          </div>
        </div>
        <p className="gi-foot">
          {model.nodes.length} nodes, {model.edges.length} relations shown
          {model.limited ? `. Showing ${risky.size} of ${serverCount} servers.` : ""}
        </p>
      </>
    );
  })();

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Risk graph</h1>
          <div className="sub">How clients, servers, tools and findings connect. Select a node to trace its dependency chain.</div>
        </div>
        <Button loading={rebuilding} onClick={rebuild}>
          Rebuild graph
        </Button>
      </div>

      {isLoading && !data ? (
        <SkeletonRows />
      ) : !hasGraph ? (
        <Empty title="The risk graph is empty" action={<Button variant="primary" loading={rebuilding} onClick={rebuild}>Rebuild graph</Button>}>
          The graph is built from registered servers, their tools and scan results. Register a server or rebuild it from the current inventory.
        </Empty>
      ) : (
        <>
          <div className="gtool">
            <nav className="gcrumb" aria-label="Scope">
              <button
                type="button"
                className={st.scope.length ? "" : "on"}
                onClick={() => {
                  pending.current = { fit: true };
                  setSt((s) => ({ ...s, scope: [], sel: null, path: null }));
                }}
              >
                {model?.limited ? (focus?.kind === "largest" ? `Largest ${risky.size} servers` : focus && focus.total > risky.size ? `Top ${risky.size} servers at risk` : "Servers with risk") : "All servers"}
              </button>
              {st.scope.map((id, i) => {
                const n = graph!.N[id];
                return (
                  <span key={id} style={{ display: "contents" }}>
                    <span className="sep">/</span>
                    <button
                      type="button"
                      className={`${i === st.scope.length - 1 ? "on " : ""}${n && sansTypes.has(n.type) ? "" : "mono"}`}
                      onClick={() => {
                        pending.current = { fit: true };
                        setSt((s) => ({ ...s, scope: s.scope.slice(0, i + 1), sel: id, path: null }));
                      }}
                    >
                      {n?.label ?? id}
                    </button>
                  </span>
                );
              })}
            </nav>
            <span className="sp" />
            <div className="gsearch">
              <input className="input" data-search placeholder="Find a node" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onSearchKey} autoComplete="off" />
              <span className="kbd">/</span>
            </div>
            {risky.size > 0 && risky.size < serverCount && !st.scope.length && (
              <Seg
                label="Servers"
                options={[
                  { value: "risk", label: focusLabel },
                  { value: "all", label: "All", count: serverCount },
                ]}
                value={st.serverScope}
                onChange={(v) => {
                  pending.current = { fit: true };
                  setSt((s) => ({ ...s, serverScope: v, sel: null, path: null }));
                }}
              />
            )}
            <div className="seg" role="group" aria-label="Show">
              {FILTERS.map(([k, label]) => (
                <button
                  key={k}
                  type="button"
                  aria-pressed={st.filters[k]}
                  onClick={() => {
                    pending.current = { fit: true };
                    setSt((s) => ({ ...s, filters: { ...s.filters, [k]: !s.filters[k] } }));
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
            {!st.scope.length && (
              <Button size="sm" onClick={toggleAll}>
                {allExpanded ? "Collapse servers" : "Expand servers"}
              </Button>
            )}
          </div>
          <div className="gx">
            <div className="gx-canvas">
              <div className="gx-stage" ref={canvasRef} />
              <div className="gctl">
                <button type="button" title="Zoom in (+)" aria-label="Zoom in" onClick={() => engine.current?.zoomBy(1.25)}>
                  +
                </button>
                <button type="button" title="Zoom out (-)" aria-label="Zoom out" onClick={() => engine.current?.zoomBy(0.8)}>
                  −
                </button>
                <button type="button" title="Fit to screen (F)" aria-label="Fit to screen" onClick={() => engine.current?.fit()}>
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
                    <path d="M1.5 5V1.5H5M9 1.5h3.5V5M12.5 9v3.5H9M5 12.5H1.5V9" />
                  </svg>
                </button>
                <span>{zoom}%</span>
              </div>
              <div className="ghint">
                Drag to pan, scroll to zoom, double-click to drill in <span className="kbd">F</span> fit <span className="kbd">Esc</span> back
              </div>
            </div>
            <aside className="gins">{inspector}</aside>
          </div>
        </>
      )}
    </div>
  );
}
