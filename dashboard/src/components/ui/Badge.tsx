import { cn, RISK_COLORS, EFFECT_COLORS, TRANSPORT_COLORS } from "@/lib/utils";

interface BadgeProps {
  children: React.ReactNode;
  className?: string;
  variant?: "risk" | "effect" | "transport" | "default";
  value?: string;
}

export function Badge({ children, className, variant, value }: BadgeProps) {
  let colorClass = "text-slate-400 bg-slate-400/10 border-slate-400/20";
  if (variant === "risk" && value) colorClass = RISK_COLORS[value] ?? colorClass;
  if (variant === "effect" && value) colorClass = EFFECT_COLORS[value] ?? colorClass;
  if (variant === "transport" && value) colorClass = TRANSPORT_COLORS[value] ?? colorClass;

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        colorClass,
        className
      )}
    >
      {children}
    </span>
  );
}

export function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return <Badge>-</Badge>;
  return (
    <Badge variant="risk" value={level}>
      {level}
    </Badge>
  );
}

export function EffectBadge({ cls }: { cls: string | null | undefined }) {
  if (!cls) return <Badge>-</Badge>;
  return (
    <Badge variant="effect" value={cls}>
      {cls?.replace(/_/g, " ")}
    </Badge>
  );
}

export function TransportBadge({ transport }: { transport: string }) {
  return (
    <Badge variant="transport" value={transport}>
      {transport}
    </Badge>
  );
}

export function PolicyBadge({ policy }: { policy: string | null | undefined }) {
  if (!policy) return null;
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        policy === "block"
          ? "text-red-400 bg-red-400/10 border-red-400/20"
          : "text-green-400 bg-green-400/10 border-green-400/20"
      )}
    >
      {policy}
    </span>
  );
}
