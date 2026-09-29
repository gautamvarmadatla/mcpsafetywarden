import type { ReactNode } from "react";

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <b>{title}</b>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function SkeletonRows({ rows = 6, cols = [180, 120, 90, 60] }: { rows?: number; cols?: number[] }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div className="skel-row" key={i}>
          {cols.map((w, j) => (
            <span className="skel" key={j} style={{ width: w, height: 12, opacity: 1 - i * 0.1 }} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="banner" role="alert">
      <span>Could not load data: {msg}</span>
      {onRetry && (
        <button type="button" className="btn sm" style={{ marginLeft: "auto" }} onClick={onRetry}>
          <span className="spin" />
          Retry
        </button>
      )}
    </div>
  );
}
