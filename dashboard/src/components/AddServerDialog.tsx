import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import useSWR, { useSWRConfig } from "swr";
import { api, errorMessage } from "@/lib/api";
import type { RegisterInput } from "@/lib/types";
import Dialog from "./ui/Dialog";
import Button from "./ui/Button";
import Seg from "./ui/Seg";
import { useToast } from "./ui/Toast";

type Tab = "discovered" | "manual";

function parsePairs(text: string, sep: "=" | ":"): Record<string, string> | string {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const i = line.indexOf(sep);
    if (i <= 0) return `Could not read "${line}". Use one ${sep === "=" ? "KEY=value" : "Header: value"} per line.`;
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

function refreshInventory(mutate: ReturnType<typeof useSWRConfig>["mutate"]) {
  return mutate(
    (key) => {
      const k = Array.isArray(key) ? key[0] : key;
      return typeof k === "string" && ["servers", "overview", "discovered", "tools", "graph"].includes(k);
    },
    undefined,
    { revalidate: true }
  );
}

export default function AddServerDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const { data: discovered, mutate: mutateDiscovered, isLoading } = useSWR(open ? "discovered" : null, api.discovered);
  const [tab, setTab] = useState<Tab>("discovered");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [form, setForm] = useState({ server_id: "", transport: "stdio", command: "", args: "", url: "", env: "", headers: "", github_url: "" });

  useEffect(() => {
    if (open) {
      setFormError(null);
      setTab("discovered");
    }
  }, [open]);

  useEffect(() => {
    if (open && discovered && discovered.length === 0) setTab("manual");
  }, [open, discovered]);

  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const searchAgain = async () => {
    setSearching(true);
    try {
      const res = await api.discover();
      await mutateDiscovered();
      toast(`Found ${res.count} server${res.count === 1 ? "" : "s"} across your MCP client configs.`);
    } catch (e) {
      toast(`Search failed: ${errorMessage(e)}`);
    } finally {
      setSearching(false);
    }
  };

  const onboard = async (ids: string[], label: string) => {
    setBusyId(ids.length > 1 ? "all" : ids[0]);
    try {
      const res = await api.onboardDiscovered(ids);
      const results = res.results ?? [];
      const ok = results.filter((r) => r.status === "registered" || r.status === "already_registered");
      const failed = results.filter((r) => r.status === "failed");
      await refreshInventory(mutate);
      await mutateDiscovered();
      if (failed.length && !ok.length) toast(`Could not register ${label}: ${failed[0].error ?? "unknown error"}`);
      else toast(`Registered ${ok.length} server${ok.length === 1 ? "" : "s"}${failed.length ? `, ${failed.length} failed` : ""}.`);
    } catch (e) {
      toast(`Could not register ${label}: ${errorMessage(e)}`);
    } finally {
      setBusyId(null);
    }
  };

  const submit = async () => {
    setFormError(null);
    const id = form.server_id.trim();
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(id)) return setFormError("Use letters, numbers, dots, dashes or underscores for the server ID.");
    const input: RegisterInput = { server_id: id, transport: form.transport };
    if (form.transport === "stdio") {
      if (!form.command.trim()) return setFormError("Enter the command that starts the server.");
      input.command = form.command.trim();
      const args = form.args.split(/\r?\n/).map((a) => a.trim()).filter(Boolean);
      if (args.length) input.args = args;
      const env = parsePairs(form.env, "=");
      if (typeof env === "string") return setFormError(env);
      if (Object.keys(env).length) input.env = env;
    } else {
      if (!/^https?:\/\//.test(form.url.trim())) return setFormError("Enter the server URL, starting with http:// or https://.");
      input.url = form.url.trim();
      const headers = parsePairs(form.headers, ":");
      if (typeof headers === "string") return setFormError(headers);
      if (Object.keys(headers).length) input.headers = headers;
    }
    if (form.github_url.trim()) input.github_url = form.github_url.trim();

    setSubmitting(true);
    try {
      const res = await api.register(input);
      await refreshInventory(mutate);
      toast(
        res.inspect_error
          ? `Registered ${id}, but listing its tools failed: ${res.inspect_error}`
          : `Registered ${id} with ${res.tools_discovered ?? 0} tool${res.tools_discovered === 1 ? "" : "s"}.`
      );
      onClose();
      setForm({ server_id: "", transport: "stdio", command: "", args: "", url: "", env: "", headers: "", github_url: "" });
      navigate(`/servers/${encodeURIComponent(id)}`);
    } catch (e) {
      setFormError(errorMessage(e));
    } finally {
      setSubmitting(false);
    }
  };

  const list = discovered ?? [];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      wide
      title="Add server"
      description="Registering connects to the server and lists its tools. For stdio servers the command runs on this machine."
      footer={
        tab === "manual" ? (
          <>
            <Button variant="quiet" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" loading={submitting} onClick={submit}>
              Register server
            </Button>
          </>
        ) : (
          <>
            <span className="note">{list.length ? `${list.length} not yet registered` : ""}</span>
            <Button variant="quiet" onClick={onClose}>
              Close
            </Button>
            {list.length > 1 && (
              <Button variant="primary" loading={busyId === "all"} onClick={() => onboard(list.map((d) => d.discovery_id), `${list.length} servers`)}>
                Register all {list.length}
              </Button>
            )}
          </>
        )
      }
    >
      <div style={{ marginBottom: 16 }}>
        <Seg
          label="Source"
          options={[
            { value: "discovered", label: "From your MCP clients", count: list.length },
            { value: "manual", label: "Manual" },
          ]}
          value={tab}
          onChange={setTab}
        />
      </div>

      {tab === "discovered" ? (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
            <span className="muted" style={{ fontSize: 13.5, flex: 1 }}>
              Servers found in Claude Desktop, Cursor, VS Code and other client configs.
            </span>
            <Button size="sm" loading={searching} onClick={searchAgain}>
              Search configs again
            </Button>
          </div>
          {isLoading ? (
            <p className="muted" style={{ padding: "16px 0" }}>
              Loading…
            </p>
          ) : list.length === 0 ? (
            <p className="muted" style={{ padding: "16px 0" }}>
              Every server found in your client configs is already registered.
            </p>
          ) : (
            list.map((d) => {
              let args: string[] = [];
              try {
                args = JSON.parse(d.args_json ?? "[]");
              } catch {
                args = [];
              }
              return (
                <div key={d.discovery_id} className="disc-row">
                  <div style={{ minWidth: 0 }}>
                    <div className="n mono">{d.server_name}</div>
                    <div className="m">
                      {d.client_name} · {d.transport} · <span className="mono">{d.url || [d.command, ...args].filter(Boolean).join(" ")}</span>
                    </div>
                  </div>
                  <Button size="sm" loading={busyId === d.discovery_id} onClick={() => onboard([d.discovery_id], d.server_name)}>
                    Register
                  </Button>
                </div>
              );
            })
          )}
        </>
      ) : (
        <>
          {formError && <div className="form-error">{formError}</div>}
          <div className="field-row">
            <div className="field">
              <label htmlFor="as-id">Server ID</label>
              <input id="as-id" className="input" value={form.server_id} onChange={set("server_id")} placeholder="github" />
            </div>
            <div className="field">
              <label htmlFor="as-transport">Transport</label>
              <select id="as-transport" value={form.transport} onChange={set("transport")}>
                <option value="stdio">stdio (local process)</option>
                <option value="streamable_http">Streamable HTTP</option>
                <option value="sse">SSE</option>
              </select>
            </div>
          </div>
          {form.transport === "stdio" ? (
            <>
              <div className="field">
                <label htmlFor="as-cmd">Command</label>
                <input id="as-cmd" className="input mono" value={form.command} onChange={set("command")} placeholder="npx" />
              </div>
              <div className="field">
                <label htmlFor="as-args">Arguments</label>
                <textarea id="as-args" value={form.args} onChange={set("args")} placeholder={"-y\n@modelcontextprotocol/server-filesystem\n~/projects"} />
                <span className="hint">One argument per line.</span>
              </div>
              <div className="field">
                <label htmlFor="as-env">Environment variables</label>
                <textarea id="as-env" value={form.env} onChange={set("env")} placeholder="GITHUB_PERSONAL_ACCESS_TOKEN=..." />
                <span className="hint">One KEY=value per line. Secrets are replaced with opaque references before they are stored.</span>
              </div>
            </>
          ) : (
            <>
              <div className="field">
                <label htmlFor="as-url">URL</label>
                <input id="as-url" className="input mono" value={form.url} onChange={set("url")} placeholder="https://example.com/mcp" />
              </div>
              <div className="field">
                <label htmlFor="as-headers">Headers</label>
                <textarea id="as-headers" value={form.headers} onChange={set("headers")} placeholder="Authorization: Bearer ..." />
                <span className="hint">One Header: value per line. Tokens are replaced with opaque references before they are stored.</span>
              </div>
            </>
          )}
          <div className="field" style={{ marginBottom: 0 }}>
            <label htmlFor="as-gh">GitHub repository (optional)</label>
            <input id="as-gh" className="input mono" value={form.github_url} onChange={set("github_url")} placeholder="https://github.com/owner/repo" />
            <span className="hint">Enables source code analysis during security scans.</span>
          </div>
        </>
      )}
    </Dialog>
  );
}
