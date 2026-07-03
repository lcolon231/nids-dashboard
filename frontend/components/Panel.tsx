import { ReactNode } from "react";

export function Panel({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section
      className="rounded-xl p-5 flex flex-col gap-4"
      style={{ background: "var(--surface-1)", border: "1px solid var(--border)" }}
    >
      <header className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
            {title}
          </h2>
          {subtitle && (
            <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
              {subtitle}
            </p>
          )}
        </div>
        {actions}
      </header>
      {children}
    </section>
  );
}

export function Toggle<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
}) {
  return (
    <div
      className="flex rounded-lg p-0.5 text-xs"
      style={{ border: "1px solid var(--border)" }}
      role="tablist"
    >
      {options.map((o) => (
        <button
          key={o}
          role="tab"
          aria-selected={o === value}
          onClick={() => onChange(o)}
          className="px-2.5 py-1 rounded-md cursor-pointer"
          style={
            o === value
              ? { background: "var(--gridline)", color: "var(--text-primary)", fontWeight: 600 }
              : { color: "var(--text-muted)" }
          }
        >
          {o}
        </button>
      ))}
    </div>
  );
}

export function LoadState({ error }: { error?: string }) {
  return (
    <p className="text-xs py-6 text-center" style={{ color: "var(--text-muted)" }}>
      {error ? `⚠ ${error} — is the API running on :8000?` : "Loading…"}
    </p>
  );
}
