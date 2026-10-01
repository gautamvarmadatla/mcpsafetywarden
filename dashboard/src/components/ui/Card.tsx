import { cn } from "@/lib/utils";

export function Card({ className, children, onClick }: { className?: string; children?: React.ReactNode; onClick?: () => void }) {
  return (
    <div className={cn("rounded-lg border border-border bg-card p-4", className)} onClick={onClick}>{children}</div>
  );
}

export function CardHeader({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("mb-3", className)}>{children}</div>;
}

export function CardTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h3 className={cn("text-sm font-medium text-muted-foreground", className)}>{children}</h3>;
}

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon?: React.ElementType;
  color?: string;
}) {
  return (
    <Card>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className={cn("text-2xl font-bold tabular-nums", color ?? "text-foreground")}>{value}</p>
          {sub && <p className="text-xs text-muted-foreground mt-1">{sub}</p>}
        </div>
        {Icon && (
          <div className="p-2 rounded-md bg-accent">
            <Icon className="h-4 w-4 text-muted-foreground" />
          </div>
        )}
      </div>
    </Card>
  );
}
