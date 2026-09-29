export function relativeTime(iso?: string | null): string {
  if (!iso) return "never";
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return "unknown";
  const diff = Date.now() - ts;
  if (diff < 45_000) return "just now";
  if (diff < 3_600_000) return `${Math.max(1, Math.floor(diff / 60_000))}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 30 * 86_400_000) return `${Math.floor(diff / 86_400_000)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function absoluteTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export function clockTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? ""
    : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const y = new Date();
  y.setDate(today.getDate() - 1);
  const same = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  const date = d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  if (same(d, today)) return `Today, ${date}`;
  if (same(d, y)) return `Yesterday, ${date}`;
  return d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short" });
}

export function fmtLatency(ms?: number | null): string {
  if (ms == null) return "-";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function fmtBytes(b?: number | null): string {
  if (b == null) return "-";
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

export function fmtNum(n?: number | null): string {
  return n == null ? "-" : n.toLocaleString("en-US");
}

export function fmtPct(rate?: number | null): string {
  return rate == null ? "-" : `${(rate * 100).toFixed(1)}%`;
}

export function humanize(s?: string | null): string {
  return (s ?? "unknown").replace(/_/g, " ");
}
