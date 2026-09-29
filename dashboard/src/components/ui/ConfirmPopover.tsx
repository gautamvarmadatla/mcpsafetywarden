import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import Button from "./Button";

export default function ConfirmPopover({
  anchor,
  open,
  onClose,
  title,
  children,
  confirmLabel,
  onConfirm,
  busy,
}: {
  anchor: RefObject<HTMLElement>;
  open: boolean;
  onClose: () => void;
  title: string;
  children?: ReactNode;
  confirmLabel: string;
  onConfirm: () => void;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState({ top: 0, right: 0 });

  useLayoutEffect(() => {
    if (!open || !anchor.current) return;
    const app = anchor.current.closest(".app") as HTMLElement | null;
    const ar = app?.getBoundingClientRect() ?? { top: 0, right: window.innerWidth };
    const br = anchor.current.getBoundingClientRect();
    setPos({ top: br.bottom - ar.top + 8, right: ar.right - br.right });
  }, [open, anchor]);

  useEffect(() => {
    if (!open) return;
    confirmRef.current?.focus();
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || anchor.current?.contains(t)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey, true);
    };
  }, [open, onClose, anchor]);

  return (
    <div ref={ref} className={`pop${open ? " on" : ""}`} role="dialog" aria-hidden={!open} style={{ top: pos.top, right: pos.right }}>
      <b>{title}</b>
      {children}
      <div className="acts">
        <Button variant="quiet" size="sm" onClick={onClose}>
          Cancel
        </Button>
        <Button ref={confirmRef} variant="primary" size="sm" loading={busy} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </div>
  );
}
