import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate, Link } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import { useTheme, setTheme, type Theme } from "@/lib/theme";
import { useScans } from "@/lib/scans";
import { relativeTime } from "@/lib/format";
import Seg from "./ui/Seg";
import Button from "./ui/Button";
import CommandPalette, { type Command } from "./CommandPalette";

type NavItem = { to: string; label: string; end?: boolean; count?: "findings" | "servers" | "tools" };

const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: "Monitor",
    items: [
      { to: "/", label: "Overview", end: true },
      { to: "/findings", label: "Findings", count: "findings" },
      { to: "/history", label: "History" },
    ],
  },
  {
    group: "Inventory",
    items: [
      { to: "/servers", label: "Servers", count: "servers" },
      { to: "/tools", label: "Tools", count: "tools" },
      { to: "/graph", label: "Risk graph" },
    ],
  },
  { group: "Control", items: [{ to: "/policies", label: "Policies" }] },
];

const TITLES: Record<string, string> = {
  "/": "Overview",
  "/findings": "Findings",
  "/history": "History",
  "/servers": "Servers",
  "/tools": "Tools",
  "/graph": "Risk graph",
  "/policies": "Policies",
};

function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
      <rect width="20" height="20" rx="5" fill="var(--ink)" />
      <path d="M10 4.6l4.4 1.7v3.5c0 2.8-1.8 4.8-4.4 5.6-2.6-.8-4.4-2.8-4.4-5.6V6.3z" fill="none" stroke="var(--ink-fg)" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}

export function isTyping() {
  const el = document.activeElement as HTMLElement | null;
  return !!el && (/INPUT|TEXTAREA|SELECT/.test(el.tagName) || el.isContentEditable);
}

export default function Shell({ children }: { children: ReactNode }) {
  const loc = useLocation();
  const navigate = useNavigate();
  const [theme] = useTheme();
  const scans = useScans();
  const [palOpen, setPalOpen] = useState(false);

  const { data: overview } = useSWR("overview", api.overview, { refreshInterval: 30000 });
  const { data: health, error: healthError } = useSWR("health", api.health, { refreshInterval: 30000 });
  const { data: servers } = useSWR(palOpen ? "servers" : null, api.servers);
  const { data: findings } = useSWR(palOpen ? ["findings", ""] : null, () => api.findings());

  const findingTotal = overview ? Object.values(overview.finding_counts).reduce((a, b) => a + b, 0) : undefined;
  const alertFindings = overview ? (overview.finding_counts.CRITICAL ?? 0) + (overview.finding_counts.HIGH ?? 0) > 0 : false;
  const counts = { findings: findingTotal, servers: overview?.server_count, tools: overview?.tool_count };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalOpen((o) => !o);
        return;
      }
      if (e.key === "/" && !isTyping() && !e.metaKey && !e.ctrlKey) {
        const target = document.querySelector<HTMLInputElement>("[data-search]");
        if (target) {
          e.preventDefault();
          target.focus();
          target.select();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const go = useCallback((to: string) => navigate(to), [navigate]);

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [];
    Object.entries(TITLES).forEach(([to, label]) => list.push({ group: "Go to", label, run: () => go(to) }));
    list.push({ group: "Action", label: "Scan all servers…", run: () => scans.requestScan("all") });
    list.push({ group: "Action", label: "Add server…", run: () => go("/servers?add=1") });
    (["light", "dark", "system"] as Theme[]).forEach((t) =>
      list.push({ group: "Theme", label: `Switch to ${t} theme`, run: () => setTheme(t) })
    );
    servers?.forEach((s) => list.push({ group: "Server", label: s.server_id, mono: true, run: () => go(`/servers/${encodeURIComponent(s.server_id)}`) }));
    findings?.items.forEach((f) =>
      list.push({
        group: "Finding",
        label: `${f.server_id}.${f.name}  ${f.finding ?? ""}`,
        run: () => go(`/findings?open=${encodeURIComponent(`${f.server_id}::${f.name}`)}`),
      })
    );
    return list;
  }, [servers, findings, go, scans]);

  const serverMatch = loc.pathname.match(/^\/servers\/(.+)$/);
  const crumb = serverMatch ? (
    <>
      <Link className="link" to="/servers">
        Servers
      </Link>
      <span>/</span>
      <b className="mono">{decodeURIComponent(serverMatch[1])}</b>
    </>
  ) : (
    <b>{TITLES[loc.pathname] ?? "Safety Warden"}</b>
  );

  const st = scans.status;
  const connected = !!health?.ok && !healthError;

  return (
    <div className="app">
      <aside className="side">
        <div className="ws">
          <Mark />
          <b>Safety Warden</b>
        </div>
        <button type="button" className="search-btn" onClick={() => setPalOpen(true)}>
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
            <circle cx="7" cy="7" r="4.5" />
            <path d="M10.5 10.5L14 14" strokeLinecap="round" />
          </svg>
          Search or jump to<span className="kbd">Ctrl K</span>
        </button>
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="grp">{g.group}</div>
            {g.items.map((it) => {
              const n = it.count ? counts[it.count] : undefined;
              const active = it.end ? loc.pathname === it.to : loc.pathname.startsWith(it.to);
              return (
                <NavLink key={it.to} to={it.to} end={it.end} className={`nav${active ? " on" : ""}`}>
                  {it.label}
                  {n != null && <span className={`n${it.count === "findings" && alertFindings ? " alert" : ""}`}>{n.toLocaleString()}</span>}
                </NavLink>
              );
            })}
          </div>
        ))}
        <div className="side-foot">
          <Seg
            label="Theme"
            options={[
              { value: "light", label: "Light" },
              { value: "dark", label: "Dark" },
              { value: "system", label: "System" },
            ]}
            value={theme}
            onChange={(t) => setTheme(t as Theme)}
          />
          <div className="status" title={health?.db_path}>
            <i style={connected ? undefined : { background: "var(--crit)" }} />
            {connected ? "Connected" : "API unreachable"}
            <span className="tnum" style={{ marginLeft: "auto" }}>
              :{window.location.port || "80"}
            </span>
          </div>
        </div>
      </aside>
      <div className="main">
        <div className="top">
          <div className="crumb">{crumb}</div>
          <div className="right">
            {st?.current ? (
              <>
                <span className="scanning">
                  <i />
                  Scanning <span className="mono">{st.current}</span>
                  {st.queue.length > 0 && <span className="muted">and {st.queue.length} more</span>}
                </span>
                {st.queue.length > 0 && (
                  <Button size="sm" variant="quiet" onClick={() => scans.cancelQueue()}>
                    Cancel queued
                  </Button>
                )}
              </>
            ) : (
              <span>{overview?.last_scan_at ? `Last scan ${relativeTime(overview.last_scan_at)}` : overview ? "No scans yet" : ""}</span>
            )}
          </div>
        </div>
        <div className={`content${loc.pathname === "/graph" ? " flush" : ""}`}>{children}</div>
      </div>
      <CommandPalette open={palOpen} onClose={() => setPalOpen(false)} commands={commands} />
    </div>
  );
}
