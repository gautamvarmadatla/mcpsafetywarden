import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

type ToastOpts = { undo?: () => void; duration?: number };
type ToastFn = (message: string, opts?: ToastOpts) => void;

const ToastCtx = createContext<ToastFn>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [item, setItem] = useState<{ message: string; undo?: () => void } | null>(null);
  const [on, setOn] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();

  const show = useCallback<ToastFn>((message, opts) => {
    setItem({ message, undo: opts?.undo });
    setOn(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setOn(false), opts?.duration ?? (opts?.undo ? 6000 : 4000));
  }, []);

  return (
    <ToastCtx.Provider value={show}>
      {children}
      <div className={`toast${on ? " on" : ""}`} role="status" aria-live="polite">
        {item && (
          <>
            <span>{item.message}</span>
            {item.undo && (
              <button
                type="button"
                onClick={() => {
                  setOn(false);
                  item.undo?.();
                }}
              >
                Undo
              </button>
            )}
          </>
        )}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast(): ToastFn {
  return useContext(ToastCtx);
}
