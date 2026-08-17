type Option<T extends string> = { value: T; label: string; count?: number };

export default function Seg<T extends string>({
  options,
  value,
  onChange,
  className = "",
  label,
}: {
  options: Option<T>[];
  value: T;
  onChange: (v: T) => void;
  className?: string;
  label?: string;
}) {
  return (
    <div className={`seg ${className}`} role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
          {o.count != null && <span className="c">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}
