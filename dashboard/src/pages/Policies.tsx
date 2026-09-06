import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import useSWR from "swr";
import { api, errorMessage } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { usePolicyActions } from "@/lib/policies";
import { absoluteTime, relativeTime } from "@/lib/format";
import Seg from "@/components/ui/Seg";
import Button from "@/components/ui/Button";
import Dialog from "@/components/ui/Dialog";
import ConfirmPopover from "@/components/ui/ConfirmPopover";
import ToolPanel from "@/components/ToolPanel";
import Severity, { normLevel, RANK } from "@/components/ui/Severity";
import { useToast } from "@/components/ui/Toast";
import { Empty, ErrorBanner, SkeletonRows } from "@/components/ui/States";

type Filter = "all" | Policy;

function AddRuleDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { change } = usePolicyActions();
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [picked, setPicked] = useState<string | null>(null);
  const [policy, setPolicy] = useState<Policy>("block");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 200);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    if (open) {
      setQ("");
      setPicked(null);
      setErr(null);
      setPolicy("block");
    }
  }, [open]);

  const { data } = useSWR(open ? ["tools", "rule-search", debounced] : null, () => api.tools({ q: debounced, limit: 8 }));
  const pickedTool = data?.items.find((t) => `${t.server_id}::${t.tool_name}` === picked);

  const save = async () => {
    if (!picked) return setErr("Pick a tool first.");
    const [sid, name] = picked.split("::");
    setSaving(true);
    const ok = await change(sid, name, policy, pickedTool?.policy ?? null);
    setSaving(false);
    if (ok) onClose();
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Add rule"
      description="Rules override risk gating for one tool. Blocked tools are refused; allowed tools skip the preflight check."
      footer={
        <>
          <Button variant="quiet" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={saving} onClick={save}>
            {picked ? `${policy === "block" ? "Block" : "Allow"} ${picked.split("::")[1]}` : "Save rule"}
          </Button>
        </>
      }
    >
      {err && <div className="form-error">{err}</div>}
      <div className="field">
        <label htmlFor="rule-q">Tool</label>
        <input id="rule-q" className="input" placeholder="Search tools or servers" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div style={{ marginBottom: 16, minHeight: 60 }}>
        {(data?.items ?? []).map((t) => {
          const key = `${t.server_id}::${t.tool_name}`;
          return (
            <button
              key={key}
              type="button"
              className={`nav${picked === key ? " on" : ""}`}
              style={{ height: 36 }}
              onClick={() => {
                setPicked(key);
                setErr(null);
              }}
            >
              <span className="mono">{t.tool_name}</span>
              <span className="mono muted" style={{ marginLeft: 10 }}>
                {t.server_id}
              </span>
              <span className="n">{t.policy ?? "no rule"}</span>
            </button>
          );
        })}
        {data && data.items.length === 0 && <p className="muted">No tools match.</p>}
      </div>
      <div className="field" style={{ marginBottom: 0 }}>
        <label>Policy</label>
        <Seg
          label="Policy"
          options={[
            { value: "block", label: "Block" },
            { value: "allow", label: "Allow" },
          ]}
          value={policy}
          onChange={setPolicy}
        />
      </div>
    </Dialog>
  );
}

export default function Policies() {
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const open = params.get("open");
  const [filter, setFilter] = useState<Filter>("all");
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const bulkRef = useRef<HTMLButtonElement>(null);
  const { change, refresh, write } = usePolicyActions();

  const { data, error, isLoading, mutate } = useSWR("policies", api.policies);
  const { data: findings } = useSWR(["findings", ""], () => api.findings());

  const current = useMemo(() => new Map((data ?? []).map((p) => [`${p.server_id}::${p.tool_name}`, p.policy])), [data]);
  const highRisk = useMemo(() => {
    const seen = new Map<string, string>();
    for (const f of findings?.items ?? []) {
      if (RANK[normLevel(f.risk_level)] < 3) continue;
      const k = `${f.server_id}::${f.name}`;
      if (current.get(k) === "block") continue;
      if (!seen.has(k) || RANK[normLevel(f.risk_level)] > RANK[normLevel(seen.get(k))]) seen.set(k, f.risk_level);
    }
    return [...seen.entries()];
  }, [findings, current]);

  const rows = (data ?? []).filter((p) => filter === "all" || p.policy === filter);
  const setOpen = (k: string | null) => {
    const next = new URLSearchParams(params);
    if (k) next.set("open", k);
    else next.delete("open");
    setParams(next, { replace: true });
  };

  const bulkBlock = async () => {
    const prev = highRisk.map(([k]) => [k, current.get(k) ?? null] as const);
    setBulkBusy(true);
    try {
      await api.bulkBlockHigh();
      await refresh();
      setBulkOpen(false);
      toast(`Blocked ${prev.length} high-risk tool${prev.length === 1 ? "" : "s"}.`, {
        undo: async () => {
          try {
            for (const [k, p] of prev) {
              const [sid, name] = k.split("::");
              await write(sid, name, p);
            }
            await refresh();
          } catch (e) {
            toast(`Undo failed: ${errorMessage(e)}`);
          }
        },
      });
    } catch (e) {
      toast(`Could not block tools: ${errorMessage(e)}`);
    } finally {
      setBulkBusy(false);
    }
  };

  const setRow = async (sid: string, name: string, next: Policy | null, prev: Policy | null) => {
    setRowBusy(`${sid}::${name}`);
    await change(sid, name, next, prev);
    await mutate();
    setRowBusy(null);
  };

  return (
    <div className="wrap">
      <div className="ph">
        <div>
          <h1>Policies</h1>
          <div className="sub">Explicit allow and block rules. Tools without a rule fall back to risk gating.</div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Button
            ref={bulkRef}
            onClick={() => (highRisk.length ? setBulkOpen((o) => !o) : toast("Every tool with a critical or high finding is already blocked."))}
          >
            Block high-risk tools…
          </Button>
          <Button variant="primary" onClick={() => setAddOpen(true)}>
            Add rule…
          </Button>
        </div>
      </div>

      <ConfirmPopover
        anchor={bulkRef}
        open={bulkOpen}
        onClose={() => setBulkOpen(false)}
        title={`Block ${highRisk.length} high-risk tool${highRisk.length === 1 ? "" : "s"}?`}
        confirmLabel={`Block ${highRisk.length} tool${highRisk.length === 1 ? "" : "s"}`}
        onConfirm={bulkBlock}
        busy={bulkBusy}
      >
        <p>Calls to {highRisk.length === 1 ? "this tool" : "these tools"} will be refused until you change the rule.</p>
        <ul>
          {highRisk.map(([k, lvl]) => (
            <li key={k} style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
              <span className="mono">{k.replace("::", ".")}</span>
              <Severity level={lvl} />
            </li>
          ))}
        </ul>
      </ConfirmPopover>

      {error && <ErrorBanner error={error} onRetry={() => mutate()} />}

      {isLoading && !data ? (
        <SkeletonRows />
      ) : (data ?? []).length === 0 ? (
        <Empty title="No rules yet" action={<Button variant="primary" onClick={() => setAddOpen(true)}>Add rule…</Button>}>
          Every tool currently falls back to risk gating. Block a tool to refuse its calls, or allow it to skip the preflight check.
        </Empty>
      ) : (
        <>
          <div className="toolbar">
            <Seg
              label="Filter"
              options={[
                { value: "all", label: "All", count: data?.length },
                { value: "block", label: "Blocked", count: data?.filter((p) => p.policy === "block").length },
                { value: "allow", label: "Allowed", count: data?.filter((p) => p.policy === "allow").length },
              ]}
              value={filter}
              onChange={setFilter}
            />
          </div>
          <table className="t">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Server</th>
                <th>Description</th>
                <th>Policy</th>
                <th className="r">Set</th>
                <th className="r" />
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => {
                const k = `${p.server_id}::${p.tool_name}`;
                return (
                  <tr key={k}>
                    <td>
                      <button type="button" className="link mono" style={{ border: 0, background: "none", cursor: "pointer", fontSize: 13.5 }} onClick={() => setOpen(k)}>
                        {p.tool_name}
                      </button>
                    </td>
                    <td className="mono muted">{p.server_id}</td>
                    <td className="muted trunc" style={{ maxWidth: 360 }}>
                      {p.description}
                    </td>
                    <td>
                      <Seg
                        label={`Policy for ${p.tool_name}`}
                        options={[
                          { value: "allow", label: "Allow" },
                          { value: "block", label: "Block" },
                        ]}
                        value={p.policy}
                        onChange={(v) => v !== p.policy && setRow(p.server_id, p.tool_name, v, p.policy)}
                      />
                    </td>
                    <td className="r muted" title={absoluteTime(p.set_at)}>
                      {relativeTime(p.set_at)}
                    </td>
                    <td className="r">
                      <Button size="sm" variant="quiet" loading={rowBusy === k} onClick={() => setRow(p.server_id, p.tool_name, null, p.policy)}>
                        Remove
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="foot-note">
            {rows.length} rule{rows.length === 1 ? "" : "s"}
          </div>
        </>
      )}

      <AddRuleDialog open={addOpen} onClose={() => setAddOpen(false)} />
      <ToolPanel toolKey={open} onClose={() => setOpen(null)} />
    </div>
  );
}
