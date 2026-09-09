import { RISK_REL, type GNode, type Graph } from "./model";
import { COL, HEADS, type Box, type Highlight, type Model } from "./layout";

const SVGNS = "http://www.w3.org/2000/svg";
const LABEL: Record<string, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
export const REL_LABEL: Record<string, string> = {
  declares: "declares",
  exposes: "exposes",
  affected_by: "affected by",
  affected_by_cve: "affected by",
  maps_to: "maps to",
  depends_on: "depends on",
  uses_credential: "uses secret",
  has_provenance: "has provenance",
  can_exfiltrate: "can feed",
  cross_server_exfil: "can exfiltrate to",
  can_read: "can read",
  can_write: "can write",
  can_execute: "can execute",
  blocked_by: "blocked by",
};

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");

export function glyph(n: Pick<GNode, "type" | "sev">): string {
  if (n.type === "finding" || n.type === "cve") return `<i class="gg dot s-${n.sev ?? "NONE"}"></i>`;
  return `<i class="gg ${n.type}"></i>`;
}

function card(n: GNode, expanded: boolean, scoped: boolean): string {
  let l1 = "";
  let l2 = "";
  if (n.type === "server") {
    l1 = `${glyph(n)}<span class="nm mono">${esc(n.label)}</span>${
      scoped
        ? ""
        : `<button class="gtog${expanded ? " on" : ""}" data-gtog="${esc(n.id)}" title="${expanded ? "Hide" : "Show"} tools" aria-label="${expanded ? "Hide" : "Show"} tools"><svg width="12" height="12" viewBox="0 0 12 12"><path d="M4.5 3l3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>`
    }`;
    l2 = `${n.sev ? `<span class="s-${n.sev}">${LABEL[n.sev]}</span>` : ""}<span>${esc(n.sub)}</span>`;
  } else if (n.type === "tool") {
    l1 = `${glyph(n)}<span class="nm mono">${esc(n.label)}</span>${n.sev ? `<i class="gg dot s-${n.sev} end"></i>` : ""}`;
    l2 = `<span class="${n.sub === "destructive" ? "eff-destructive" : ""}">${esc(n.sub)}</span>${n.blocked ? '<span class="pol-block">Blocked</span>' : ""}`;
  } else if (n.type === "technique") {
    l1 = `<span class="mono tid">${esc(n.label)}</span><span class="nm">${esc(n.name ?? "")}</span>`;
    l2 = esc(n.sub);
  } else if (n.type === "finding") {
    l1 = `${glyph(n)}<span class="nm">${esc(n.label)}</span>`;
    l2 = `<span class="mono">${esc(`${n.server ?? ""}.${n.sub}`)}</span>`;
  } else {
    l1 = `${glyph(n)}<span class="nm${n.type === "client" || n.type === "cve" ? "" : " mono"}">${esc(n.label)}</span>`;
    l2 = esc(n.sub);
  }
  return `<div class="gcard t-${n.type}"><div class="l1">${l1}</div><div class="l2">${l2}</div></div>`;
}

export interface EngineEvents {
  select: (id: string) => void;
  drill: (id: string) => void;
  toggle: (id: string) => void;
  background: () => void;
  hover: (id: string | null) => void;
  zoom: (k: number) => void;
}

type View = { x: number; y: number; k: number };
type UpdateOpts = { fit?: boolean; ids?: string[]; anchor?: string; focus?: string; instant?: boolean };

export class GraphEngine {
  private root: HTMLElement;
  private ev: EngineEvents;
  private world: SVGGElement;
  private heads: SVGGElement;
  private edgesG: SVGGElement;
  private labelsG: SVGGElement;
  private nodesG: SVGGElement;
  private miniNodes: SVGGElement;
  private miniView: SVGRectElement;
  private mini = { k: 1, ox: 0, oy: 0 };
  private nodeEls = new Map<string, SVGGElement>();
  private edgeEls: SVGPathElement[] = [];
  private cur: Record<string, Box> = {};
  private target: Record<string, Box> = {};
  private model: Model | null = null;
  private hl: Highlight | null = null;
  private view: View = { x: 0, y: 0, k: 1 };
  private raf = 0;
  private reduce = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  private cleanup: (() => void)[] = [];

  constructor(root: HTMLElement, ev: EngineEvents) {
    this.root = root;
    this.ev = ev;
    root.innerHTML = `
      <svg class="gsvg"><defs>
        <marker id="ga" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0.8 L7 4 L0 7.2 z" style="fill:var(--edge)"/></marker>
        <marker id="gar" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0.8 L7 4 L0 7.2 z" style="fill:var(--crit)"/></marker>
      </defs><g class="gw"><g class="gh"></g><g class="ge-g"></g><g class="gl"></g><g class="gn"></g></g></svg>
      <div class="gmini" title="Click to move the view"><svg width="188" height="116"><g class="gmn"></g><rect id="gminiview" rx="2"></rect></svg></div>`;
    this.world = root.querySelector(".gw")!;
    this.heads = root.querySelector(".gh")!;
    this.edgesG = root.querySelector(".ge-g")!;
    this.labelsG = root.querySelector(".gl")!;
    this.nodesG = root.querySelector(".gn")!;
    this.miniNodes = root.querySelector(".gmn")!;
    this.miniView = root.querySelector("#gminiview")!;
    this.bind();
  }

  destroy() {
    cancelAnimationFrame(this.raf);
    this.cleanup.forEach((f) => f());
    this.root.innerHTML = "";
  }

  private on<K extends keyof HTMLElementEventMap>(el: HTMLElement, type: K, fn: (e: HTMLElementEventMap[K]) => void, opts?: AddEventListenerOptions) {
    el.addEventListener(type, fn as EventListener, opts);
    this.cleanup.push(() => el.removeEventListener(type, fn as EventListener, opts));
  }

  private bind() {
    const cv = this.root;
    let drag: { x: number; y: number; vx: number; vy: number; moved: number } | null = null;
    this.on(cv, "wheel", (e) => {
      e.preventDefault();
      const r = cv.getBoundingClientRect();
      this.zoomAt(Math.exp(-e.deltaY * 0.0016), e.clientX - r.left, e.clientY - r.top);
    }, { passive: false });
    this.on(cv, "pointerdown", (e) => {
      const t = e.target as Element;
      if (e.button !== 0 || t.closest(".gnode, .gmini")) return;
      drag = { x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y, moved: 0 };
      cv.setPointerCapture(e.pointerId);
      cv.classList.add("dragging");
    });
    this.on(cv, "pointermove", (e) => {
      if (drag) {
        const dx = e.clientX - drag.x;
        const dy = e.clientY - drag.y;
        drag.moved = Math.max(drag.moved, Math.abs(dx) + Math.abs(dy));
        this.view = { x: drag.vx + dx, y: drag.vy + dy, k: this.view.k };
        this.applyView();
        return;
      }
      const n = (e.target as Element).closest(".gnode") as SVGGElement | null;
      this.ev.hover(n?.dataset.id ?? null);
    });
    this.on(cv, "pointerleave", () => this.ev.hover(null));
    this.on(cv, "pointerup", () => {
      if (!drag) return;
      const moved = drag.moved;
      drag = null;
      cv.classList.remove("dragging");
      if (moved < 4) this.ev.background();
    });
    this.on(cv, "click", (e) => {
      const t = e.target as Element;
      const tog = t.closest("[data-gtog]") as HTMLElement | null;
      if (tog) {
        e.stopPropagation();
        this.ev.toggle(tog.dataset.gtog!);
        return;
      }
      const mini = t.closest(".gmini");
      if (mini) {
        const r = mini.getBoundingClientRect();
        const wx = (e.clientX - r.left - this.mini.ox) / this.mini.k;
        const wy = (e.clientY - r.top - this.mini.oy) / this.mini.k;
        const v = this.view;
        this.animate(this.cur, this.target, v, { k: v.k, x: cv.clientWidth / 2 - wx * v.k, y: cv.clientHeight / 2 - wy * v.k }, false);
        return;
      }
      const n = t.closest(".gnode") as SVGGElement | null;
      if (n) this.ev.select(n.dataset.id!);
    });
    this.on(cv, "dblclick", (e) => {
      const n = (e.target as Element).closest(".gnode") as SVGGElement | null;
      if (n && !(e.target as Element).closest("[data-gtog]")) this.ev.drill(n.dataset.id!);
    });
    const ro = new ResizeObserver(() => this.applyView());
    ro.observe(cv);
    this.cleanup.push(() => ro.disconnect());
  }

  update(g: Graph, m: Model, P: Record<string, Box>, hl: Highlight, opts: UpdateOpts = {}) {
    const prev = this.cur;
    const from: Record<string, Box> = {};
    for (const n of m.nodes) {
      if (prev[n.id]) {
        from[n.id] = prev[n.id];
        continue;
      }
      let p = n.parent;
      let q: Box | undefined;
      while (p) {
        if (prev[p]) {
          q = prev[p];
          break;
        }
        p = g.N[p]?.parent;
      }
      if (!q && n.server && prev[n.server]) q = prev[n.server];
      from[n.id] = q ? { ...q, w: P[n.id].w, h: P[n.id].h } : P[n.id];
    }

    const v0 = { ...this.view };
    let v1 = v0;
    if (opts.fit || !Object.keys(prev).length) v1 = this.fitView(P, opts.ids);
    else if (opts.anchor && prev[opts.anchor] && P[opts.anchor])
      v1 = { k: v0.k, x: v0.x + v0.k * (prev[opts.anchor].x - P[opts.anchor].x), y: v0.y + v0.k * (prev[opts.anchor].y - P[opts.anchor].y) };
    else if (opts.focus && P[opts.focus]) {
      const p = P[opts.focus];
      const k = Math.max(v0.k, 0.85);
      v1 = { k, x: this.root.clientWidth / 2 - (p.x + p.w / 2) * k, y: this.root.clientHeight / 2 - (p.y + p.h / 2) * k };
    }

    this.model = m;
    this.target = P;
    this.nodesG.innerHTML = m.nodes
      .map((n) => {
        const p = P[n.id];
        return `<g class="gnode${prev[n.id] ? "" : " enter"}" data-id="${esc(n.id)}" tabindex="-1"><foreignObject width="${p.w}" height="${p.h}">${card(n, m.exp(n.id), !!m.scope)}</foreignObject></g>`;
      })
      .join("");
    this.edgesG.innerHTML = m.edges
      .map((e, i) => {
        const risk = RISK_REL.has(e.rel);
        const soft = e.rel === "maps_to" || e.rel === "affected_by";
        return `<path class="ge${risk ? " risk" : ""}${soft ? " soft" : ""}${e.agg ? " agg" : ""}" data-i="${i}" marker-end="url(#${risk ? "gar" : "ga"})"/>`;
      })
      .join("");
    this.labelsG.innerHTML = "";
    this.nodeEls.clear();
    this.nodesG.querySelectorAll<SVGGElement>(".gnode").forEach((el) => this.nodeEls.set(el.dataset.id!, el));
    this.edgeEls = [...this.edgesG.querySelectorAll<SVGPathElement>(".ge")];

    const tops: Record<number, { x: number; y: number }> = {};
    for (const n of m.nodes) {
      const c = COL[n.type];
      const p = P[n.id];
      if (!tops[c] || p.y < tops[c].y) tops[c] = { x: p.x, y: p.y };
    }
    const top = Math.min(0, ...Object.values(tops).map((t) => t.y));
    this.heads.innerHTML = Object.entries(tops)
      .map(([c, t]) => `<text class="gch" x="${t.x}" y="${top - 22}">${HEADS[Number(c)]}</text>`)
      .join("");

    this.buildMini();
    requestAnimationFrame(() => this.nodesG.querySelectorAll(".gnode.enter").forEach((el) => el.classList.remove("enter")));
    this.setHighlight(hl, false);
    this.animate(from, P, v0, v1, !!opts.instant, () => this.setHighlight(this.hl ?? hl, true));
  }

  setHighlight(hl: Highlight, withLabels = true) {
    this.hl = hl;
    for (const [id, el] of this.nodeEls) {
      el.classList.toggle("dim", hl.any && !hl.nodes.has(id));
    }
    this.edgeEls.forEach((el, i) => {
      el.classList.toggle("dim", hl.any && !hl.edges.has(i));
      el.classList.toggle("hl", hl.edges.has(i));
      el.classList.toggle("flow", hl.flow.has(i));
    });
    this.labelsG.innerHTML = withLabels && this.model ? this.labelMarkup(hl) : "";
  }

  mark(sel: string | null, hover: string | null, matches: Set<string>) {
    for (const [id, el] of this.nodeEls) {
      el.classList.toggle("sel", id === sel);
      el.classList.toggle("hov", id === hover);
      el.classList.toggle("match", matches.has(id));
    }
  }

  private labelMarkup(hl: Highlight): string {
    if (!this.model) return "";
    return this.model.edges
      .map((e, i) => {
        if (!hl.labels.has(i)) return "";
        const g = this.geom(e.s, e.t);
        if (!g) return "";
        const text = (REL_LABEL[e.rel] ?? e.rel.replace(/_/g, " ")) + (e.n > 1 ? ` (${e.n})` : "");
        return `<text class="gel${RISK_REL.has(e.rel) ? " risk" : ""}" x="${g.m[0].toFixed(1)}" y="${(g.m[1] - 6).toFixed(1)}" text-anchor="middle">${esc(text)}</text>`;
      })
      .join("");
  }

  private geom(s: string, t: string) {
    const A = this.cur[s];
    const B = this.cur[t];
    if (!A || !B) return null;
    let p0: number[], p1: number[], p2: number[], p3: number[];
    if (Math.abs(A.x - B.x) < 1) {
      const x = A.x + A.w;
      const y1 = A.y + A.h / 2;
      const y2 = B.y + B.h / 2;
      const bx = x + Math.max(56, Math.abs(y2 - y1) * 0.4);
      p0 = [x, y1];
      p1 = [bx, y1];
      p2 = [bx, y2];
      p3 = [x + 3, y2];
    } else if (A.x < B.x) {
      const sx = A.x + A.w;
      const sy = A.y + A.h / 2;
      const tx = B.x;
      const ty = B.y + B.h / 2;
      const dx = Math.max(40, (tx - sx) * 0.5);
      p0 = [sx, sy];
      p1 = [sx + dx, sy];
      p2 = [tx - dx, ty];
      p3 = [tx - 3, ty];
    } else {
      const sx = A.x;
      const sy = A.y + A.h / 2;
      const tx = B.x + B.w;
      const ty = B.y + B.h / 2;
      const dx = Math.max(40, (sx - tx) * 0.5);
      p0 = [sx, sy];
      p1 = [sx - dx, sy];
      p2 = [tx + dx, ty];
      p3 = [tx + 3, ty];
    }
    const m = [(p0[0] + 3 * p1[0] + 3 * p2[0] + p3[0]) / 8, (p0[1] + 3 * p1[1] + 3 * p2[1] + p3[1]) / 8];
    return { d: `M${p0.join(" ")} C${p1.join(" ")} ${p2.join(" ")} ${p3.join(" ")}`, m };
  }

  private animate(from: Record<string, Box>, to: Record<string, Box>, v0: View, v1: View, instant: boolean, done?: () => void) {
    cancelAnimationFrame(this.raf);
    const t0 = performance.now();
    const D = instant || this.reduce ? 0 : 320;
    const frame = (now: number) => {
      const t = D ? Math.min(1, (now - t0) / D) : 1;
      const e = 1 - Math.pow(1 - t, 3);
      const cur: Record<string, Box> = {};
      for (const id in to) {
        const a = from[id] ?? to[id];
        const b = to[id];
        cur[id] = { x: a.x + (b.x - a.x) * e, y: a.y + (b.y - a.y) * e, w: b.w, h: b.h };
      }
      this.cur = cur;
      this.view = { x: v0.x + (v1.x - v0.x) * e, y: v0.y + (v1.y - v0.y) * e, k: v0.k + (v1.k - v0.k) * e };
      this.paint();
      if (t < 1) this.raf = requestAnimationFrame(frame);
      else done?.();
    };
    if (!D) frame(performance.now());
    else this.raf = requestAnimationFrame(frame);
  }

  private paint() {
    for (const [id, el] of this.nodeEls) {
      const p = this.cur[id];
      if (p) el.setAttribute("transform", `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
    }
    this.model?.edges.forEach((e, i) => {
      const g = this.geom(e.s, e.t);
      if (g) this.edgeEls[i]?.setAttribute("d", g.d);
    });
    this.applyView();
  }

  private applyView() {
    const v = this.view;
    this.world.setAttribute("transform", `translate(${v.x.toFixed(1)},${v.y.toFixed(1)}) scale(${v.k.toFixed(4)})`);
    const m = this.mini;
    const cw = this.root.clientWidth;
    const ch = this.root.clientHeight;
    this.miniView.setAttribute("x", ((-v.x / v.k) * m.k + m.ox).toFixed(1));
    this.miniView.setAttribute("y", ((-v.y / v.k) * m.k + m.oy).toFixed(1));
    this.miniView.setAttribute("width", Math.max(4, (cw / v.k) * m.k).toFixed(1));
    this.miniView.setAttribute("height", Math.max(4, (ch / v.k) * m.k).toFixed(1));
    this.ev.zoom(v.k);
  }

  private bounds(P: Record<string, Box>, ids?: string[]) {
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const id of ids ?? Object.keys(P)) {
      const p = P[id];
      if (!p) continue;
      x0 = Math.min(x0, p.x);
      y0 = Math.min(y0, p.y);
      x1 = Math.max(x1, p.x + p.w);
      y1 = Math.max(y1, p.y + p.h);
    }
    if (!Number.isFinite(x0)) return { x: 0, y: 0, w: 1, h: 1 };
    if (!ids) y0 -= 40;
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  }

  private fitView(P: Record<string, Box>, ids?: string[]): View {
    const b = this.bounds(P, ids);
    const cw = this.root.clientWidth || 800;
    const ch = this.root.clientHeight || 600;
    const pd = 40;
    const k = Math.max(0.25, Math.min((cw - pd * 2) / b.w, (ch - pd * 2) / b.h, 1.15));
    return { k, x: (cw - b.w * k) / 2 - b.x * k, y: (ch - b.h * k) / 2 - b.y * k };
  }

  private buildMini() {
    if (!this.model) return;
    const b = this.bounds(this.target);
    const W = 188;
    const H = 116;
    const pd = 8;
    const k = Math.min((W - pd * 2) / b.w, (H - pd * 2) / b.h);
    this.mini = { k, ox: (W - b.w * k) / 2 - b.x * k, oy: (H - b.h * k) / 2 - b.y * k };
    const m = this.mini;
    this.miniNodes.innerHTML = this.model.nodes
      .map((n) => {
        const p = this.target[n.id];
        const hot = n.sev === "CRITICAL" || n.sev === "HIGH";
        return `<rect x="${(m.ox + p.x * k).toFixed(1)}" y="${(m.oy + p.y * k).toFixed(1)}" width="${Math.max(2, p.w * k).toFixed(1)}" height="${Math.max(2, p.h * k).toFixed(1)}" rx="1" class="${hot ? "r" : ""}"/>`;
      })
      .join("");
  }

  fit(ids?: string[]) {
    this.animate(this.cur, this.target, this.view, this.fitView(this.target, ids), false);
  }

  zoomBy(f: number) {
    this.zoomAt(f, this.root.clientWidth / 2, this.root.clientHeight / 2);
  }

  private zoomAt(f: number, cx: number, cy: number) {
    const v = this.view;
    const k = Math.min(2.2, Math.max(0.25, v.k * f));
    const wx = (cx - v.x) / v.k;
    const wy = (cy - v.y) / v.k;
    this.view = { k, x: cx - wx * k, y: cy - wy * k };
    this.applyView();
  }
}
