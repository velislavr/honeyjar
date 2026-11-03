"use client";

import Link from "next/link";
import { useState } from "react";
import { BarList, LineChart, Tile } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { ACTOR_LABEL, INTENT_LABEL, SeverityBadge, type Verdict } from "@/components/Verdict";
import { ago, fmt, useStats } from "@/lib/api";

interface Count { label: string; n: number }
interface TriageStats {
  totals: { sessions: number };
  actors: Count[]; intents: Count[]; severities: Count[];
  timeline: { t: string; low: number; medium: number; high: number; critical: number }[];
}

export default function TriagePage() {
  const [all, setAll] = useState(false);
  const { data: st } = useStats<TriageStats>("/stats/triage", 20000);
  const { data: q } = useStats<{ sessions: (Verdict & { sessions: number; ips: number })[] }>(`/triage/queue?limit=100${all ? "&all=true" : ""}`, 20000);
  const t = st?.totals;
  const sev = (...names: string[]) => (st?.severities ?? []).filter((c) => names.includes(c.label)).reduce((n, c) => n + c.n, 0);
  const timeline = (st?.timeline ?? []).map((p) => ({ ...p, serious: p.high + p.critical }));

  return (
    <>
      <PageHead eyebrow="Triage" title="Session verdicts"
        desc="Every attack session gets a verdict: who is behind it, what they want and how severe it is, judged by rules over its logins, commands, exploits and downloads. Bots replaying the same script are grouped into one row." />
      <div className="tiles">
        <Tile label="Sessions judged" value={fmt(t?.sessions)} />
        <Tile label="High severity" value={fmt(sev("high", "critical"))} note="malware installs, exploits, persistence" />
        <Tile label="Medium" value={fmt(sev("medium"))} note="post-login recon, injection probes" />
        <Tile label="Low" value={fmt(sev("low"))} note="scans and password guessing" />
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
            <h2>{all ? "All behaviours" : "Review queue"}</h2>
            <span className="sub">
              identical sessions grouped ·{" "}
              <button className="linkbtn" onClick={() => setAll((a) => !a)} aria-pressed={all}>
                {all ? "show review queue only" : "show all sessions"}
              </button>
            </span>
          </div>
          {!q?.sessions.length ? <div className="empty">{all ? "No sessions judged in this window yet" : "Nothing needs review in this window"}</div> : (
            <div className="scroll-x">
              <table className="data">
                <thead><tr><th>Severity</th><th>Actor</th><th>Intent</th><th className="num">Sessions</th><th className="num">IPs</th><th>Latest IP</th><th>Sensor</th><th>Last seen</th></tr></thead>
                <tbody>
                  {q.sessions.map((v) => (
                    <tr key={v.session_id}>
                      <td><SeverityBadge v={v} /></td>
                      <td>{ACTOR_LABEL[v.actor] ?? v.actor}</td>
                      <td className="ink2">{INTENT_LABEL[v.intent] ?? v.intent}</td>
                      <td className="num">{fmt(v.sessions)}</td>
                      <td className="num">{fmt(v.ips)}</td>
                      <td><Link className="link mono" href={`/ip/${v.src_ip}`}>{v.src_ip}</Link></td>
                      <td className="muted">{v.sensor_id}</td>
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
