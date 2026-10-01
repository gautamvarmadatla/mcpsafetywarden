import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-400/10 border-red-400/20",
  HIGH: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  MEDIUM: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  LOW: "text-green-400 bg-green-400/10 border-green-400/20",
  NONE: "text-slate-400 bg-slate-400/10 border-slate-400/20",
  unknown: "text-slate-400 bg-slate-400/10 border-slate-400/20",
};

export const RISK_DOT: Record<string, string> = {
  CRITICAL: "bg-red-400",
  HIGH: "bg-orange-400",
  MEDIUM: "bg-yellow-400",
  LOW: "bg-green-400",
  NONE: "bg-slate-600",
};

export const EFFECT_COLORS: Record<string, string> = {
  read_only: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  additive_write: "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
  mutating_write: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  external_action: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  destructive: "text-red-400 bg-red-400/10 border-red-400/20",
  unknown: "text-slate-400 bg-slate-400/10 border-slate-400/20",
};

export const TRANSPORT_COLORS: Record<string, string> = {
  stdio: "text-purple-400 bg-purple-400/10 border-purple-400/20",
  sse: "text-teal-400 bg-teal-400/10 border-teal-400/20",
  streamable_http: "text-indigo-400 bg-indigo-400/10 border-indigo-400/20",
};

export function relativeTime(iso: string): string {
  const now = Date.now();
  const ts = new Date(iso).getTime();
  const diff = now - ts;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function fmtLatency(ms: number | null | undefined): string {
  if (ms == null) return "-";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function fmtBytes(b: number | null | undefined): string {
  if (b == null) return "-";
  if (b < 1024) return `${b}B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)}KB`;
  return `${(b / 1024 / 1024).toFixed(1)}MB`;
}

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, " ");
}
