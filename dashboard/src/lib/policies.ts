import { useCallback } from "react";
import { useSWRConfig } from "swr";
import { api, errorMessage } from "./api";
import type { Policy } from "./types";
import { useToast } from "@/components/ui/Toast";

const KEYS = ["overview", "tools", "tool", "policies", "graph"];

export function usePolicyActions() {
  const { mutate } = useSWRConfig();
  const toast = useToast();

  const refresh = useCallback(
    () =>
      mutate(
        (key) => {
          const k = Array.isArray(key) ? key[0] : key;
          return typeof k === "string" && KEYS.includes(k);
        },
        undefined,
        { revalidate: true }
      ),
    [mutate]
  );

  const write = useCallback(async (serverId: string, toolName: string, policy: Policy | null) => {
    if (policy) await api.setPolicy(serverId, toolName, policy);
    else await api.deletePolicy(serverId, toolName);
  }, []);

  const change = useCallback(
    async (serverId: string, toolName: string, next: Policy | null, prev: Policy | null) => {
      const id = `${serverId}.${toolName}`;
      try {
        await write(serverId, toolName, next);
        await refresh();
        const msg =
          next === "block" ? `Blocked ${id}. Calls will be refused.` : next === "allow" ? `Allowed ${id} without preflight.` : `Removed the rule for ${id}.`;
        toast(msg, {
          undo: async () => {
            try {
              await write(serverId, toolName, prev);
              await refresh();
            } catch (e) {
              toast(`Undo failed: ${errorMessage(e)}`);
            }
          },
        });
        return true;
      } catch (e) {
        toast(`Could not update ${id}: ${errorMessage(e)}`);
        return false;
      }
    },
    [write, refresh, toast]
  );

  return { change, refresh, write };
}
