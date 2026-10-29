"use client";

import { BarList } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { fmt, useStats } from "@/lib/api";

interface Tech { technique: string; name: string; tactic: string; hits: number; ips: number }

// ATT&CK kill-chain order for the tactics we map.
const TACTICS = ["initial-access", "execution", "persistence", "defense-evasion", "credential-access", "discovery", "command-and-control", "impact"];
const STEPS = ["var(--q1)", "var(--q2)", "var(--q3)", "var(--q4)", "var(--q5)", "var(--q6)"];

export default function TtpPage() {
  const { data } = useStats<{ techniques: Tech[]; commands: { command: string; n: number; ips: number }[] }>("/stats/techniques", 20000);
  const techs = data?.techniques ?? [];
  const max = Math.max(1, ...techs.map((t) => t.hits));
  // Sequential one-hue scale on log magnitude: hits span several orders of magnitude.
  const stepIdx = (n: number) => Math.min(STEPS.length - 1, Math.floor((Math.log1p(n) / Math.log1p(max)) * (STEPS.length - 1)));

  return (
    <>
      <PageHead eyebrow="Behaviour" title="MITRE ATT&CK coverage" desc="What attackers do after they get a (fake) shell. Every command is mapped to ATT&CK techniques; cell shade = how often the technique was observed." />
      <div className="grid">
        <section className="card span-12">
          <div className="card-head">
            <h2>Technique heatmap</h2>
            <span className="row sub" aria-label="Color scale: fewer to more observations">
              fewer {STEPS.map((c) => <span key={c} style={{ width: 14, height: 8, background: c, borderRadius: 2, display: "inline-block" }} />)} more
            </span>
          </div>
          <div className="matrix">
            {TACTICS.map((tac) => (
              <div className="tactic" key={tac}>
                <h3>{tac.replace(/-/g, " ")}</h3>
                {techs.filter((t) => t.tactic === tac).sort((a, b) => b.hits - a.hits).map((t) => (
                  <a key={t.technique} href={`https://attack.mitre.org/techniques/${t.technique.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                     className={`tech ${t.hits ? "" : "zero"}`}
                     style={t.hits ? { background: STEPS[stepIdx(t.hits)], borderColor: "transparent", color: `var(--qi${stepIdx(t.hits) + 1})` } : undefined}
                     title={`${t.technique} ${t.name}: ${t.hits.toLocaleString()} events from ${t.ips.toLocaleString()} IPs`}>
                    <span className="n">{t.hits ? fmt(t.hits) : ""}</span>
                    <span className="id">{t.technique}</span>
                    <div>{t.name}</div>
                  </a>
                ))}
              </div>
            ))}
          </div>
        </section>
        <section className="card span-12">
          <div className="card-head"><h2>Most common commands</h2><span className="sub">executions (defanged)</span></div>
          <BarList items={(data?.commands ?? []).map((c, i) => ({
            key: `${i}`, value: c.n, title: c.command, label: <span className="mono">$ {c.command}</span>,
          }))} empty="No shell commands in this window yet" />
        </section>
      </div>
    </>
  );
}
