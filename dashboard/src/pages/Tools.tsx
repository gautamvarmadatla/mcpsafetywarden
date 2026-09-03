import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api } from "@/lib/api";
import Seg from "@/components/ui/Seg";
import Button from "@/components/ui/Button";
import ToolsTable from "@/components/ToolsTable";
import ToolPanel from "@/components/ToolPanel";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

const LIMIT = 50;
const EFFECTS = ["read_only", "additive_write", "mutating_write", "external_action", "destructive", "unknown"];

export default function Tools() {
  const [params, setParams] = useSearchParams();
  const policy = params.get("policy") ?? "all";
  const effect = params.get("effect") ?? "";
  const page = Math.max(1, Number(params.get("page") ?? 1));
  const open = params.get("open");
  const [q, setQ] = useState(params.get("q") ?? "");
  const [debounced, setDebounced] = useState(q);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 250);
    return () => clearTimeout(t);
  }, [q]);

  const update = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
    }
    setParams(next, { replace: true });
  };

  useEffect(() => {
    if ((params.get("q") ?? "") !== debounced) update({ q: debounced || null, page: null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);

  const apiPolicy = policy === "all" ? null : policy;
  const { data, error, isLoading, mutate } = useSWR(["tools", debounced, apiPolicy, effect, page], () =>
    api.tools({ q: debounced, policy: apiPolicy, effect_class: effect || null, page, limit: LIMIT })
  );
  const { data: activity } = useSWR(["activity", 7], () => api.activity(7));

  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / LIMIT));
  const from = total ? (page - 1) * LIMIT + 1 : 0;
  const to = Math.min(page * LIMIT, total);
  const filtered = !!(debounced || apiPolicy || effect);

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Tools</h1>
          <div className="sub">Behaviour profiles built from observed calls.</div>
        </div>
      </div>

      <div className="toolbar">
        <input className="input" data-search placeholder="Search tools or servers" value={q} onChange={(e) => setQ(e.target.value)} />
        <Seg
          label="Policy"
          options={[
            { value: "all", label: "All" },
            { value: "allow", label: "Allowed" },
            { value: "block", label: "Blocked" },
            { value: "none", label: "Default" },
          ]}
          value={policy}
          onChange={(v) => update({ policy: v === "all" ? null : v, page: null })}
        />
        <select className="input" style={{ minWidth: 170, width: 170 }} value={effect} onChange={(e) => update({ effect: e.target.value || null, page: null })} aria-label="Effect">
          <option value="">All effects</option>
          {EFFECTS.map((e) => (
            <option key={e} value={e}>
              {e.replace(/_/g, " ")}
            </option>
          ))}
        </select>
        <span className="sp" />
        <span className="kbd">/</span>
      </div>

      {error && <ErrorBanner error={error} onRetry={() => mutate()} />}

      {isLoading && !data ? (
        <SkeletonRows />
      ) : total === 0 ? (
        <Empty title={filtered ? "No tools match these filters" : "No tools yet"}>
          {filtered ? "Try a different search or clear the filters." : "Tools appear after a server is registered and inspected."}
        </Empty>
      ) : (
        <>
          <ToolsTable tools={data?.items ?? []} activity={activity?.tools} onOpen={(k) => update({ open: k })} />
          <div className="pager">
            <span>
              {from.toLocaleString()} to {to.toLocaleString()} of {total.toLocaleString()} tools
            </span>
            <span className="sp" />
            <Button size="sm" disabled={page <= 1} onClick={() => update({ page: page - 1 > 1 ? String(page - 1) : null })}>
              Previous
            </Button>
            <span className="tnum">
              Page {page} of {pages}
            </span>
            <Button size="sm" disabled={page >= pages} onClick={() => update({ page: String(page + 1) })}>
              Next
            </Button>
          </div>
        </>
      )}

      <ToolPanel toolKey={open} onClose={() => update({ open: null })} />
    </div>
  );
}
