export type Level = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

const LABEL: Record<Level, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  NONE: "None",
};

export const RANK: Record<Level, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };

export function normLevel(v: unknown): Level {
  const s = String(v ?? "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH" || s === "MEDIUM" || s === "LOW") return s;
  return "NONE";
}

export function levelLabel(v: unknown): string {
  return LABEL[normLevel(v)];
}

export default function Severity({ level, chip, label }: { level: unknown; chip?: boolean; label?: string }) {
  const l = normLevel(level);
  return (
    <span className={`sev s-${l}${chip ? " chip" : ""}`}>
      <i />
      {label ?? LABEL[l]}
    </span>
  );
}
