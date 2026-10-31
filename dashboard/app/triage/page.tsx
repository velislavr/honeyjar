"use client";

import Link from "next/link";
import { useState } from "react";
import { BarList, LineChart, Tile } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { ACTOR_LABEL, INTENT_LABEL, SOURCE_LABEL, SeverityBadge, type Verdict } from "@/components/Verdict";
import { ago, fmt, useStats } from "@/lib/api";

interface Count { label: string; n: number }
interface TriageStats {
  totals: { sessions: number; escalated: number; jev: number; cached: number; rules: number; tokens: number };
  actors: Count[]; intents: Count[]; severities: Count[];
  timeline: { t: string; low: number; medium: number; high: number; critical: number }[];
}

const pct = (a: number, b: number) => (b ? `${Math.round((a / b) * 100)}%` : "–");

export default function TriagePage() {
  const [all, setAll] = useState(false);
  const { data: st } = useStats<TriageStats>("/stats/triage", 20000);
  const { data: q } = useStats<{ sessions: Verdict[] }>(`/triage/queue?limit=100${all ? "&all=true" : ""}`, 20000);
  const t = st?.totals;
  const timeline = (st?.timeline ?? []).map((p) => ({ ...p, serious: p.high + p.critical }));

  return (
    <>
      <PageHead eyebrow="Triage" title="Session verdicts"
        desc={<>Every attack session gets a verdict: who is behind it, what they want and how severe it is. Interesting sessions go to
          the <a className="link" href="https://jevapi.io/jev-api/" target="_blank" rel="noreferrer">Jev</a> decision model, routine noise
          is labelled by rules, and repeated bot scripts reuse a cached verdict.</>} />
      <div className="tiles">
        <Tile label="Sessions judged" value={fmt(t?.sessions)} note={`${fmt(t?.escalated)} flagged for review`} />
        <Tile label="Judged by Jev" value={fmt(t?.jev)} note={`${fmt(t?.tokens)} tokens used`} />
        <Tile label="Cache hits" value={fmt(t?.cached)} note={`${pct(t?.cached ?? 0, (t?.jev ?? 0) + (t?.cached ?? 0))} of model-worthy sessions`} />
        <Tile label="Rules only" value={fmt(t?.rules)} note="scans and password guessing" />
      </div>
      <div className="grid">
        <section className="card span-4">
          <div className="card-head"><h2>Who</h2><span className="sub">sessions by actor</span></div>
          <BarList items={(st?.actors ?? []).map((c) => ({ key: c.label, value: c.n, label: ACTOR_LABEL[c.label] ?? c.label }))} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Why</h2><span className="sub">sessions by intent</span></div>
          <BarList items={(st?.intents ?? []).map((c) => ({ key: c.label, value: c.n, label: INTENT_LABEL[c.label] ?? c.label }))} />
        </section>
        <section className="card span-4">
          <LineChart data={timeline} field="serious" label="High + critical sessions" color="var(--serious)" />
        </section>

        <section className="card span-12">
          <div className="card-head">
            <h2>{all ? "All sessions" : "Review queue"}</h2>
            <span className="sub">
              <button className="linkbtn" onClick={() => setAll((a) => !a)} aria-pressed={all}>
                {all ? "show review queue only" : "show all sessions"}
              </button>
            </span>
          </div>
          {!q?.sessions.length ? <div className="empty">{all ? "No sessions judged in this window yet" : "Nothing needs review in this window"}</div> : (
            <div className="scroll-x">
              <table className="data">
                <thead><tr><th>Severity</th><th>Actor</th><th>Intent</th><th>Source IP</th><th>Sensor</th><th>Judged by</th><th className="num">Confidence</th><th>Ended</th></tr></thead>
                <tbody>
                  {q.sessions.map((v) => (
                    <tr key={v.session_id}>
                      <td><SeverityBadge v={v} /></td>
                      <td>{ACTOR_LABEL[v.actor] ?? v.actor}</td>
                      <td className="ink2">{INTENT_LABEL[v.intent] ?? v.intent}</td>
                      <td><Link className="link mono" href={`/ip/${v.src_ip}`}>{v.src_ip}</Link></td>
                      <td className="muted">{v.sensor_id}</td>
                      <td className="muted">{SOURCE_LABEL[v.source]}</td>
                      <td className="num">{v.confidence == null ? "–" : `${Math.round(v.confidence * 100)}%`}</td>
                      <td className="muted" style={{ whiteSpace: "nowrap" }}>{ago(v.ended_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
