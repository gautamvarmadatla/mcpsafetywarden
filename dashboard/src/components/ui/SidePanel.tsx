import { useEffect, type ReactNode } from "react";
import Button from "./Button";

export default function SidePanel({
  open,
  onClose,
  header,
  footer,
  children,
}: {
  open: boolean;
  onClose: () => void;
  header?: ReactNode;
  footer?: ReactNode;
  children?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector(".pal-wrap.on, .dialog-wrap, .pop.on")) {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  return (
    <>
      <div className={`scrim${open ? " on" : ""}`} onClick={onClose} />
      <aside className={`panel${open ? " on" : ""}`} aria-hidden={!open}>
        {open && (
          <>
            <div className="panel-h">
              {header}
              <Button variant="quiet" size="sm" className="x" onClick={onClose}>
                Close <span className="kbd">Esc</span>
              </Button>
            </div>
            <div className="panel-b">{children}</div>
            {footer && <div className="panel-f">{footer}</div>}
          </>
        )}
      </aside>
    </>
  );
}
