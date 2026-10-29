"use client";

import Link from "next/link";
import { BarList } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { CountryCode } from "@/components/Icon";
import { ago, fmt, useStats } from "@/lib/api";

interface Attacker {
  ip: string; country_code: string | null; country: string | null; as_org: string | null; events: number;
  logins: number; commands: number; exploits: number; honeypots: string[]; first_seen: string; last_seen: string;
}
interface Geo {
  countries: { country_code: string; country: string; events: number; ips: number; exploits: number }[];
  asns: { asn: number; as_org: string; events: number; ips: number }[];
  ports: { dst_port: number; proto: string; events: number; ips: number }[];
}

export default function AttackersPage() {
  const { data } = useStats<{ attackers: Attacker[] }>("/attackers/top?limit=50", 20000);
  const { data: geo } = useStats<Geo>("/stats/geo", 30000);

  return (
    <>
      <PageHead eyebrow="Origins" title="Attackers & infrastructure" desc="Where attacks come from: source countries, the networks (ASNs) hosting them, the ports they probe, and the most active individual IPs." />
      <div className="grid">
        <section className="card span-4">
          <div className="card-head"><h2>Countries</h2><span className="sub">unique IPs</span></div>
          <BarList items={(geo?.countries ?? []).slice(0, 15).map((c) => ({
            key: c.country_code, value: c.ips, label: <><CountryCode cc={c.country_code} />{c.country}</>,
          }))} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Hosting networks (ASN)</h2><span className="sub">unique IPs</span></div>
          <BarList items={(geo?.asns ?? []).slice(0, 15).map((a) => ({
            key: String(a.asn), value: a.ips, title: `AS${a.asn} ${a.as_org}`,
            label: <><span className="mono muted">AS{a.asn}</span>{a.as_org}</>,
          }))} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Targeted ports</h2><span className="sub">events</span></div>
          <BarList items={(geo?.ports ?? []).slice(0, 15).map((p) => ({
            key: `${p.dst_port}-${p.proto}`, value: p.events,
            label: <><span className="mono">{p.dst_port}</span><span className="muted">{p.proto}</span></>,
          }))} />
        </section>

        <section className="card span-12">
          <div className="card-head"><h2>Most active IPs</h2><span className="sub">click for a full profile</span></div>
          {!data?.attackers.length ? <div className="empty">No attackers in this window yet</div> : (
            <div className="scroll-x">
              <table className="data">
                <thead>
                  <tr><th>IP</th><th>Origin</th><th>Network</th><th className="num">Events</th><th className="num">Logins</th>
                    <th className="num">Commands</th><th className="num">Exploits</th><th>Honeypots</th><th>Last seen</th></tr>
                </thead>
                <tbody>
                  {data.attackers.map((a) => (
                    <tr key={a.ip}>
                      <td><Link className="link mono" href={`/ip/${a.ip}`}>{a.ip}</Link></td>
                      <td style={{ whiteSpace: "nowrap" }}><span className="row" style={{ flexWrap: "nowrap" }}><CountryCode cc={a.country_code} />{a.country ?? "–"}</span></td>
                      <td className="ink2" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.as_org ?? "–"}</td>
                      <td className="num">{fmt(a.events)}</td>
                      <td className="num">{fmt(a.logins)}</td>
                      <td className="num">{fmt(a.commands)}</td>
                      <td className="num">{fmt(a.exploits)}</td>
                      <td><div className="row" style={{ gap: 4 }}>{a.honeypots.map((h) => <span key={h} className="tag">{h}</span>)}</div></td>
                      <td className="muted" style={{ whiteSpace: "nowrap" }}>{ago(a.last_seen)}</td>
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
