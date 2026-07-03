"use client";

import { useEffect, useState } from "react";
import { DatasetSummary, fetchSummary, Split } from "@/lib/api";
import { LoadState, Panel, Toggle } from "./Panel";

const CLASS_ORDER = ["normal", "dos", "probe", "r2l", "u2r"];

export default function DatasetPanel() {
  const [split, setSplit] = useState<Split>("train");
  const [data, setData] = useState<DatasetSummary | null>(null);
  const [error, setError] = useState<string>();

  useEffect(() => {
    setData(null);
    setError(undefined);
    fetchSummary(split).then(setData).catch((e) => setError(String(e.message ?? e)));
  }, [split]);

  const total = data ? data.rows : 0;
  const max = data ? Math.max(...Object.values(data.class_distribution)) : 1;

  return (
    <Panel
      title="Dataset summary"
      subtitle={data ? `NSL-KDD ${split} — ${data.rows.toLocaleString()} rows × ${data.cols} cols` : "NSL-KDD"}
      actions={<Toggle value={split} options={["train", "test"] as const} onChange={setSplit} />}
    >
      {!data ? (
        <LoadState error={error} />
      ) : (
        <div className="flex flex-col gap-2">
          {CLASS_ORDER.filter((c) => c in data.class_distribution).map((cls) => {
            const n = data.class_distribution[cls];
            return (
              <div
                key={cls}
                className="flex items-center gap-2"
                title={`${cls}: ${n.toLocaleString()} rows (${((n / total) * 100).toFixed(1)}%)`}
              >
                <span className="text-xs w-14" style={{ color: "var(--text-secondary)" }}>
                  {cls}
                </span>
                <div className="flex-1 h-5">
                  <div
                    className="h-5 rounded-r"
                    style={{
                      width: `${Math.max((n / max) * 100, 0.8)}%`,
                      background: "var(--series-1)",
                      borderLeft: "2px solid var(--baseline)",
                    }}
                  />
                </div>
                <span
                  className="text-xs w-24 text-right"
                  style={{ color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}
                >
                  {n.toLocaleString()}{" "}
                  <span style={{ color: "var(--text-muted)" }}>
                    ({((n / total) * 100).toFixed(1)}%)
                  </span>
                </span>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}
