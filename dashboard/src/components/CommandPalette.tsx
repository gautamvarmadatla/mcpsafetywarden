import { useEffect, useMemo, useRef, useState } from "react";

export type Command = { group: string; label: string; mono?: boolean; hint?: string; run: () => void };

export default function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      requestAnimationFrame(() => input.current?.focus());
    }
  }, [open]);

  const items = useMemo(() => {
    const s = q.trim().toLowerCase();
    const hits = s ? commands.filter((c) => `${c.group} ${c.label}`.toLowerCase().includes(s)) : commands;
    return hits.slice(0, 40);
  }, [q, commands]);

  useEffect(() => {
    list.current?.querySelector<HTMLElement>("li.sel")?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  if (!open) return null;

  const run = (c?: Command) => {
    if (!c) return;
    onClose();
    c.run();
  };

  return (
    <div className="pal-wrap on" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="pal" role="dialog" aria-label="Command palette">
        <input
          ref={input}
          value={q}
          placeholder="Type a command or search"
          autoComplete="off"
          onChange={(e) => {
            setQ(e.target.value);
            setSel(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setSel((s) => Math.min(s + 1, items.length - 1));
            } else if (e.key === "ArrowUp") {
              e.preventDefault();
              setSel((s) => Math.max(s - 1, 0));
            } else if (e.key === "Enter") {
              e.preventDefault();
              run(items[sel]);
            } else if (e.key === "Escape") {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }
          }}
        />
        <ul ref={list}>
          {items.length === 0 && <li className="muted">No results</li>}
          {items.map((c, i) => (
            <li key={`${c.group}:${c.label}`} className={i === sel ? "sel" : ""} onMouseMove={() => i !== sel && setSel(i)} onClick={() => run(c)}>
              <span className="k">{c.group}</span>
              <span className={c.mono ? "mono" : ""} style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                {c.label}
              </span>
              {i === sel && <span className="kbd">Enter</span>}
            </li>
          ))}
        </ul>
        <div className="pal-foot">
          <span>
            <span className="kbd">↑↓</span>Navigate
          </span>
          <span>
            <span className="kbd">Enter</span>Open
          </span>
          <span>
            <span className="kbd">Esc</span>Close
          </span>
        </div>
      </div>
    </div>
  );
}
