import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Server,
  Wrench,
  ShieldAlert,
  History,
  GitGraph,
  Lock,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, exact: true },
  { to: "/servers", label: "Servers", icon: Server },
  { to: "/tools", label: "Tools", icon: Wrench },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/history", label: "History", icon: History },
  { to: "/graph", label: "Risk Graph", icon: GitGraph },
  { to: "/policies", label: "Policies", icon: Lock },
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const loc = useLocation();
  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <aside className="w-56 flex-shrink-0 flex flex-col border-r border-border bg-card">
        <div className="flex items-center gap-2.5 px-4 py-5 border-b border-border">
          <Shield className="h-5 w-5 text-primary" />
          <span className="text-sm font-semibold tracking-tight text-foreground">
            Safety Warden
          </span>
        </div>
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {NAV.map((item) => {
            const active = item.exact ? loc.pathname === item.to : loc.pathname.startsWith(item.to);
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={cn(
                  "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors",
                  active
                    ? "bg-accent text-foreground font-medium"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
              >
                <item.icon className="h-4 w-4 flex-shrink-0" />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
        <div className="px-4 py-3 border-t border-border">
          <p className="text-xs text-muted-foreground">mcpsafetywarden</p>
        </div>
      </aside>
      <main className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto p-6">{children}</div>
      </main>
    </div>
  );
}
