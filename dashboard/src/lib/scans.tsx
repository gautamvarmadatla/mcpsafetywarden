import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import useSWR, { useSWRConfig } from "swr";
import { api, errorMessage } from "./api";
import type { ScanStatus } from "./types";
import { useToast } from "@/components/ui/Toast";
import Dialog from "@/components/ui/Dialog";
import Button from "@/components/ui/Button";
import { levelLabel } from "@/components/ui/Severity";

type ScansCtx = {
  status: ScanStatus | undefined;
  isBusy: (serverId?: string) => boolean;
  requestScan: (serverIds: string[] | "all") => void;
  cancelQueue: () => Promise<void>;
};

const Ctx = createContext<ScansCtx>({
  status: undefined,
  isBusy: () => false,
  requestScan: () => {},
  cancelQueue: async () => {},
});

export function refreshAfterScan(mutate: ReturnType<typeof useSWRConfig>["mutate"]) {
  return mutate(
    (key) => {
      const k = Array.isArray(key) ? key[0] : key;
      return typeof k === "string" && ["overview", "servers", "server-scan", "findings", "graph", "snapshots"].includes(k);
    },
    undefined,
    { revalidate: true }
  );
}

export function ScansProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [pending, setPending] = useState<string[] | "all" | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const seen = useRef<Record<string, string>>({});
  const primed = useRef(false);

  const { data: status, mutate: mutateStatus } = useSWR("scan-status", api.scanStatus, {
    refreshInterval: (d) => (d && (d.current || d.queue.length) ? 2000 : 15000),
  });

  useEffect(() => {
    if (!status) return;
    const finished: string[] = [];
    for (const [id, r] of Object.entries(status.results)) {
      if (seen.current[id] !== r.finished_at) {
        if (primed.current) finished.push(id);
        seen.current[id] = r.finished_at;
      }
    }
    primed.current = true;
    if (!finished.length) return;
    refreshAfterScan(mutate);
    const last = finished[finished.length - 1];
    const r = status.results[last];
    if (finished.length > 1) toast(`${finished.length} scans finished.`);
    else if (r.status === "failed") toast(`Scan of ${last} failed: ${r.error ?? "unknown error"}`);
    else toast(`Scanned ${last}. Overall risk: ${levelLabel(r.overall_risk_level)}.`);
  }, [status, mutate, toast]);

  const isBusy = useCallback(
    (serverId?: string) => {
      if (!status) return false;
      if (!serverId) return !!status.current || status.queue.length > 0;
      return status.current === serverId || status.queue.includes(serverId);
    },
    [status]
  );

  const requestScan = useCallback((ids: string[] | "all") => {
    setAuthorized(false);
    setStartError(null);
    setPending(ids);
  }, []);

  const start = async () => {
    if (!pending) return;
    setStarting(true);
    setStartError(null);
    try {
      const res = pending === "all" ? await api.scanServers() : await api.scanServers(pending);
      await mutateStatus(res, { revalidate: false });
      const n = res.queued.length;
      toast(n ? `Queued ${n} scan${n > 1 ? "s" : ""}. Results appear as each one finishes.` : "Those servers are already queued.");
      setPending(null);
    } catch (e) {
      setStartError(errorMessage(e));
    } finally {
      setStarting(false);
    }
  };

  const cancelQueue = useCallback(async () => {
    try {
      const res = await api.cancelQueuedScans();
      await mutateStatus(res, { revalidate: false });
      toast(res.cleared ? `Cancelled ${res.cleared} queued scan${res.cleared > 1 ? "s" : ""}.` : "Nothing was queued.");
    } catch (e) {
      toast(errorMessage(e));
    }
  }, [mutateStatus, toast]);

  const target = pending === "all" ? "every registered server" : pending?.length === 1 ? pending[0] : `${pending?.length ?? 0} servers`;

  return (
    <Ctx.Provider value={{ status, isBusy, requestScan, cancelQueue }}>
      {children}
      <Dialog
        open={pending !== null}
        onClose={() => setPending(null)}
        title={pending === "all" ? "Scan all servers?" : `Scan ${target}?`}
        description={
          <>
            The scan sends active security probes to <b>{target}</b> and runs one server at a time. It can take a few minutes per server.
          </>
        }
        footer={
          <>
            <Button variant="quiet" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button variant="primary" loading={starting} onClick={() => (authorized ? start() : setStartError("Confirm the authorization first."))}>
              {pending === "all" ? "Scan all servers" : `Scan ${target}`}
            </Button>
          </>
        }
      >
        {startError && <div className="form-error">{startError}</div>}
        <label className="check">
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I own {pending === "all" ? "these servers" : "this server"} or am authorized to test {pending === "all" ? "them" : "it"}.</span>
        </label>
      </Dialog>
    </Ctx.Provider>
  );
}

export function useScans() {
  return useContext(Ctx);
}
