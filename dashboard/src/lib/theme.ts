import { useSyncExternalStore } from "react";

export type Theme = "light" | "dark" | "system";

const KEY = "mcpsw-theme";
const listeners = new Set<() => void>();

function read(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === "dark" || v === "system" ? v : "light";
  } catch {
    return "light";
  }
}

let current: Theme = read();

export function setTheme(t: Theme) {
  const root = document.documentElement;
  root.classList.add("no-tx");
  if (t === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", t);
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* storage unavailable */
  }
  current = t;
  listeners.forEach((l) => l());
  requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("no-tx")));
}

export function useTheme(): [Theme, (t: Theme) => void] {
  const t = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => current
  );
  return [t, setTheme];
}
