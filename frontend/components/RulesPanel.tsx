"use client";

import { useEffect, useState } from "react";
import { fetchRules, Rule } from "@/lib/api";
import { LoadState, Panel } from "./Panel";

export default function RulesPanel() {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [error, setError] = useState<string>();

  useEffect(() => {
    fetchRules()
      .then((r) => setRules(r.rules))
      .catch((e) => setError(String(e.message ?? e)));
  }, []);

  const maxLift = rules ? Math.max(...rules.map((r) => r.lift)) : 1;

  return (
    <Panel title="Association rules" subtitle="Top patterns by lift (Apriori on KDDTrain+)">
      {!rules ? (
        <LoadState error={error} />
      ) : (
        <div className="overflow-x-auto -mx-1">
          <table className="w-full text-xs" style={{ color: "var(--text-secondary)" }}>
            <thead>
              <tr style={{ color: "var(--text-muted)" }}>
                <th className="text-left font-medium py-1 px-1">Pattern</th>
                <th className="text-left font-medium py-1 px-1">Class</th>
                <th className="text-right font-medium py-1 px-1">Conf</th>
                <th className="text-right font-medium py-1 px-1">Lift</th>
                <th className="w-20 px-1" aria-hidden />
              </tr>
            </thead>
            <tbody style={{ fontVariantNumeric: "tabular-nums" }}>
              {rules.slice(0, 10).map((r, i) => {
                const cls = r.consequents.replace("label=", "");
                return (
                  <tr
                    key={i}
                    style={{ borderTop: "1px solid var(--gridline)" }}
                    title={`${r.antecedents} → ${cls} · support ${r.support.toFixed(3)} · confidence ${r.confidence.toFixed(3)} · lift ${r.lift.toFixed(2)}`}
                  >
                    <td className="py-1.5 px-1" style={{ color: "var(--text-primary)" }}>
                      {r.antecedents}
                    </td>
                    <td className="py-1.5 px-1 font-semibold">{cls}</td>
                    <td className="py-1.5 px-1 text-right">{(r.confidence * 100).toFixed(0)}%</td>
                    <td className="py-1.5 px-1 text-right" style={{ color: "var(--text-primary)" }}>
                      {r.lift.toFixed(2)}
                    </td>
                    <td className="py-1.5 px-1">
                      <div
                        className="h-2.5 rounded-r"
                        style={{
                          width: `${(r.lift / maxLift) * 100}%`,
                          background: "var(--series-1)",
                          borderLeft: "2px solid var(--baseline)",
                        }}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
