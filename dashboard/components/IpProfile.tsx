"use client";

import { useParams } from "next/navigation";
import { useState } from "react";
import { Tile } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import Icon, { CountryCode } from "@/components/Icon";
import { ago, fmt, useApi } from "@/lib/api";

interface Profile {
  ip: string;
  summary: {
    events: number; first_seen: string; last_seen: string; country_code: string | null; country: string | null;
    city: string | null; asn: number | null; as_org: string | null; logins: number; login_successes: number;
    commands: number; sessions: number; ports: number[] | null; honeypots: string[];
  };
  cves: string[];
  techniques: string[];
  intel: { abuse_score: number | null; total_reports: number | null; usage_type: string | null; isp: string | null; is_tor: boolean | null } | null;
  sessions: { session_id: string; start: string; end: string; proto: string | null; logins: number; commands: number; logged_in: boolean | null }[];
  events: { ts: string; honeypot: string; event_type: string; dst_port: number | null; username: string | null; password: string | null;
    command: string | null; http_method: string | null; http_path: string | null; cves: string[]; techniques: string[]; tags: string[] }[];
}
interface SessionEv { ts: string; event_type: string; username: string | null; password: string | null; login_success: boolean | null; command: string | null; download_url: string | null; extra: Record<string, unknown> }

export default function IpProfile() {
  const { ip } = useParams<{ ip: string }>();
  const { data, error } = useApi<Profile>(`/attackers/${encodeURIComponent(ip)}`, 30000);
  const [session, setSession] = useState<string | null>(null);

  if (error) return <><PageHead title={ip} picker={false} /><div className="card empty">No recorded activity from this IP.</div></>;
  if (!data) return <PageHead title={ip} picker={false} />;
  const s = data.summary;

  return (
    <>
      <PageHead
        title={ip}
        picker={false}
        desc={<><CountryCode cc={s.country_code} /> {[s.city, s.country].filter(Boolean).join(", ") || "Unknown location"} · {s.asn ? `AS${s.asn} ` : ""}{s.as_org ?? ""}</>}
      />
      <div className="tiles">
        <Tile label="Events" value={fmt(s.events)} note={`first seen ${ago(s.first_seen)}`} />
        <Tile label="Login attempts" value={fmt(s.logins)} note={`${fmt(s.login_successes)} successful`} />
        <Tile label="Shell commands" value={fmt(s.commands)} note={`${fmt(s.sessions)} sessions`} />
        <Tile
          label="AbuseIPDB score"
          value={data.intel?.abuse_score != null ? `${data.intel.abuse_score}%` : "–"}
          note={data.intel ? `${fmt(data.intel.total_reports)} reports · ${data.intel.usage_type ?? ""}` : "not checked yet"}
        />
      </div>

      <div className="grid">
        <section className="card span-4">
          <div className="card-head"><h2>Fingerprint</h2></div>
          <table className="data">
            <tbody>
              <tr><td className="muted">Ports hit</td><td className="mono">{(s.ports ?? []).join(", ") || "–"}</td></tr>
              <tr><td className="muted">Honeypots</td><td><div className="row" style={{ gap: 4 }}>{s.honeypots.map((h) => <span key={h} className="tag">{h}</span>)}</div></td></tr>
              <tr><td className="muted">CVEs</td><td><div className="row" style={{ gap: 4 }}>{data.cves.length ? data.cves.map((c) => <span key={c} className="badge cve">{c}</span>) : "–"}</div></td></tr>
              <tr><td className="muted">Techniques</td><td><div className="row" style={{ gap: 4 }}>{data.techniques.length ? data.techniques.map((t) => <span key={t} className="tag">{t}</span>) : "–"}</div></td></tr>
              <tr><td className="muted">Last seen</td><td>{ago(s.last_seen)}</td></tr>
              {data.intel?.is_tor && <tr><td className="muted">Tor</td><td><span className="badge ransom"><Icon name="octagon" />Tor exit node</span></td></tr>}
            </tbody>
          </table>
          <p className="muted" style={{ fontSize: 12 }}>
            External: <a className="link" href={`https://www.abuseipdb.com/check/${ip}`} target="_blank" rel="noreferrer">AbuseIPDB</a> ·{" "}
            <a className="link" href={`https://viz.greynoise.io/ip/${ip}`} target="_blank" rel="noreferrer">GreyNoise</a> ·{" "}
            <a className="link" href={`https://www.shodan.io/host/${ip}`} target="_blank" rel="noreferrer">Shodan</a>
          </p>
        </section>

        <section className="card span-8">
          <div className="card-head"><h2>SSH / Telnet sessions</h2><span className="sub">click to replay</span></div>
          {!data.sessions.length ? <div className="empty">No interactive sessions</div> : (
            <div className="scroll-x" style={{ maxHeight: 320, overflowY: "auto" }}>
              <table className="data">
                <thead><tr><th>Session</th><th>Start</th><th>Proto</th><th className="num">Logins</th><th className="num">Commands</th><th>Shell</th></tr></thead>
                <tbody>
                  {data.sessions.map((x) => (
                    <tr key={x.session_id} onClick={() => setSession(x.session_id)} role="button" tabIndex={0} aria-pressed={session === x.session_id}
                        aria-label={`Replay session ${x.session_id}`}
                        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSession(x.session_id); } }}
                        style={{ background: session === x.session_id ? "var(--hover)" : undefined }}>
                      <td className="mono">{x.session_id}</td>
                      <td className="muted">{new Date(x.start).toLocaleString()}</td>
                      <td>{x.proto ?? "–"}</td>
                      <td className="num">{x.logins}</td>
                      <td className="num">{x.commands}</td>
                      <td>{x.logged_in ? <span className="badge"><Icon name="terminal" />got shell</span> : <span className="muted">–</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {session && <SessionReplay id={session} />}

        <section className="card span-12">
          <div className="card-head"><h2>Recent activity</h2><span className="sub">last 200 events</span></div>
          <div className="scroll-x" style={{ maxHeight: 480, overflowY: "auto" }}>
            <table className="data">
              <thead><tr><th>Time</th><th>Type</th><th>Port</th><th>Detail</th><th>Tags</th></tr></thead>
              <tbody>
                {data.events.map((e, i) => (
                  <tr key={i}>
                    <td className="muted mono" style={{ whiteSpace: "nowrap" }}>{new Date(e.ts).toLocaleString()}</td>
                    <td>{e.event_type}</td>
                    <td className="mono">{e.dst_port ?? ""}</td>
                    <td className="mono" style={{ maxWidth: 520, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {e.command ? `$ ${e.command}` : e.http_path ? `${e.http_method} ${e.http_path}` : e.username != null ? `${e.username} / ${e.password}` : ""}
                    </td>
                    <td><div className="row" style={{ gap: 4 }}>
                      {e.cves.map((c) => <span key={c} className="badge cve">{c}</span>)}
                      {e.techniques.map((t) => <span key={t} className="tag">{t}</span>)}
                      {e.tags.map((t) => <span key={t} className="tag">{t}</span>)}
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}

function SessionReplay({ id }: { id: string }) {
  const { data } = useApi<{ events: SessionEv[] }>(`/sessions/${encodeURIComponent(id)}`);
  const start = data?.events[0] ? new Date(data.events[0].ts).getTime() : 0;
  const rel = (ts: string) => `+${((new Date(ts).getTime() - start) / 1000).toFixed(1).padStart(5, " ")}s`;
  return (
    <section className="card span-12">
      <div className="card-head"><h2>Session replay <span className="mono muted">{id}</span></h2><span className="sub">reconstructed from logged events</span></div>
      <div className="term">
        {!data ? <div className="sys">loading…</div> : data.events.map((e, i) => (
          <div className="ln" key={i}>
            <span className="ts">{rel(e.ts)}</span>
            {e.event_type === "connect" && <span className="sys">connection opened</span>}
            {e.event_type === "client_info" && <span className="sys">client {String(e.extra?.client_version ?? e.extra?.hassh ?? "")}</span>}
            {e.event_type === "login_attempt" && (
              <span className={e.login_success ? "ps" : "bad"}>login {e.username} / {e.password} {e.login_success ? "→ accepted" : "→ denied"}</span>
            )}
            {e.event_type === "command" && <><span className="ps">root@web-prod-02:~# </span>{e.command}</>}
            {e.event_type === "download" && <span className="bad">fetched {e.download_url}</span>}
            {e.event_type === "session_closed" && <span className="sys">connection closed</span>}
          </div>
        ))}
      </div>
    </section>
  );
}
