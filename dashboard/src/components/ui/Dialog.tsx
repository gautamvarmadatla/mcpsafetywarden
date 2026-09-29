import { useEffect, useRef, type ReactNode } from "react";

export default function Dialog({
  open,
  onClose,
  title,
  description,
  footer,
  wide,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  children?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, select, textarea, button.primary");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      prev?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="dialog-wrap" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} className={`dialog${wide ? " wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="dialog-h">
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        <div className="dialog-b">{children}</div>
        {footer && <div className="dialog-f">{footer}</div>}
      </div>
    </div>
  );
}
