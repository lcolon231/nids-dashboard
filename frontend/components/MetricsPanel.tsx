"use client";

import { useEffect, useState } from "react";
import { fetchMetrics, MetricsResponse, Phase } from "@/lib/api";
import { LoadState, Panel, Toggle } from "./Panel";

const METRIC_KEYS = ["accuracy", "precision", "recall", "f1"] as const;
const SERIES = [
  { key: "dt", name: "Decision Tree", color: "var(--series-1)" },
  { key: "nb", name: "Naive Bayes", color: "var(--series-2)" },
  { key: "rf", name: "Random Forest", color: "var(--series-3)" },
  { key: "xgb", name: "XGBoost", color: "var(--series-4)" },
] as const;

export default function MetricsPanel() {
  const [phase, setPhase] = useState<Phase>("binary");
  const [data, setData] = useState<MetricsResponse | null>(null);
  const [error, setError] = useState<string>();

  useEffect(() => {
    setData(null);
    setError(undefined);
    fetchMetrics(phase).then(setData).catch((e) => setError(String(e.message ?? e)));
  }, [phase]);

  return (
    <Panel
      title="Model performance"
      subtitle="Evaluated on KDDTest+"
      actions={<Toggle value={phase} options={["binary", "multiclass"] as const} onChange={setPhase} />}
    >
      {!data ? (
        <LoadState error={error} />
      ) : (
        <div className="flex flex-col gap-3">
          {/* legend */}
          <div className="flex gap-4 text-xs" style={{ color: "var(--text-secondary)" }}>
            {SERIES.map((s) => (
              <span key={s.key} className="flex items-center gap-1.5">
                <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: s.color }} />
                {s.name}
              </span>
            ))}
          </div>
          {METRIC_KEYS.map((metric) => (
            <div key={metric}>
              <div className="text-xs mb-1 capitalize" style={{ color: "var(--text-secondary)" }}>
                {metric}
              </div>
              <div className="flex flex-col gap-0.5">
                {SERIES.map((s) => {
                  const v = data.metrics[s.key][metric];
                  return (
                    <div
                      key={s.key}
                      className="flex items-center gap-2"
                      title={`${s.name} ${metric}: ${v.toFixed(4)}`}
                    >
                      <div className="flex-1 h-4 relative" style={{ background: "transparent" }}>
                        <div
                          className="h-4 rounded-r"
                          style={{
                            width: `${Math.max(v * 100, 1)}%`,
                            background: s.color,
                            borderLeft: "2px solid var(--baseline)",
                          }}
                        />
                      </div>
                      <span
                        className="text-xs w-12 text-right"
                        style={{ color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}
                      >
                        {(v * 100).toFixed(1)}%
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
