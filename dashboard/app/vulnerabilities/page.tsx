"use client";

import { Fragment, useState } from "react";
import { BarList, Meter, Sparkline, Tile } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import Icon from "@/components/Icon";
import { ago, fmt, useStats } from "@/lib/api";

interface Cve {
  cve: string; hits: number; ips: number; countries: number; first_seen: string; last_seen: string;
  name: string | null; description: string | null; vendor: string | null; product: string | null;
  cvss: number | null; kev: boolean; kev_date_added: string | null; kev_ransomware: boolean | null;
  epss: number | null; epss_percentile: number | null; trend: number[];
  sample: { method: string | null; path: string | null; body: string | null; command: string | null } | null;
}
interface Tag { tag: string; name: string | null; hits: number; ips: number }

export default function VulnerabilitiesPage() {
  const { data } = useStats<{ cves: Cve[] }>("/stats/cves?limit=60", 20000);
  const { data: tags } = useStats<{ tags: Tag[] }>("/stats/tags", 30000);
  const [open, setOpen] = useState<string | null>(null);
  const cves = data?.cves ?? [];
  const kevCount = cves.filter((c) => c.kev).length;

  return (
    <>
      <PageHead
        eyebrow="Exploitation" title="Exploited vulnerabilities"
        desc="Exploit attempts matched against our signature set, enriched with CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS exploit-probability score."
      />
      <div className="tiles">
        <Tile label="CVEs targeted" value={fmt(cves.length)} />
        <Tile label="On CISA KEV" value={fmt(kevCount)} note="confirmed exploited in the wild" />
        <Tile label="Exploit requests" value={fmt(cves.reduce((a, c) => a + c.hits, 0))} />
        <Tile label="Ransomware-linked" value={fmt(cves.filter((c) => c.kev_ransomware).length)} note="per KEV" />
      </div>

      <div className="grid">
        <section className="card span-12">
          <div className="card-head"><h2>CVE leaderboard</h2><span className="sub">click a row for the captured payload</span></div>
          {!cves.length ? <div className="empty">No exploit attempts in this window yet</div> : (
            <div className="scroll-x">
              <table className="data">
                <thead>
                  <tr>
                    <th>CVE</th><th>Vulnerability</th><th className="num">Attempts</th><th className="num">IPs</th>
                    <th>Trend</th><th>CVSS</th><th>EPSS</th><th>Status</th><th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {cves.map((c) => (
                    <Fragment key={c.cve}>
                      <tr onClick={() => setOpen(open === c.cve ? null : c.cve)} role="button" tabIndex={0} aria-expanded={open === c.cve}
                          aria-label={`${c.cve}: show captured payload`}
                          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen(open === c.cve ? null : c.cve); } }}>
                        <td className="mono" style={{ whiteSpace: "nowrap" }}>
                          <a className="link" href={`https://nvd.nist.gov/vuln/detail/${c.cve}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{c.cve}</a>
                        </td>
                        <td style={{ minWidth: 240 }}>
                          {c.name}
                          {c.vendor && <div className="muted" style={{ fontSize: 12 }}>{c.vendor} · {c.product}</div>}
                        </td>
                        <td className="num">{fmt(c.hits)}</td>
                        <td className="num">{fmt(c.ips)}</td>
                        <td><Sparkline values={c.trend} /></td>
                        <td className="num">{c.cvss?.toFixed(1) ?? "–"}</td>
                        <td><Meter value={c.epss} label={c.epss_percentile != null ? `${(c.epss_percentile * 100).toFixed(1)}th percentile` : undefined} /></td>
                        <td>
                          <div className="row" style={{ gap: 4 }}>
                            {c.kev ? <span className="badge kev" title={`Added to KEV ${c.kev_date_added ?? ""}`}><Icon name="alert" />KEV</span> : <span className="badge">not in KEV</span>}
                            {c.kev_ransomware && <span className="badge ransom"><Icon name="octagon" />ransomware</span>}
                          </div>
                        </td>
                        <td className="muted" style={{ whiteSpace: "nowrap" }}>{ago(c.last_seen)}</td>
                      </tr>
                      {open === c.cve && (
                        <tr>
                          <td colSpan={9} style={{ background: "var(--surface-2)" }}>
                            {c.description && <p className="ink2" style={{ marginTop: 0 }}>{c.description}</p>}
                            <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Most recent captured request (defanged):</div>
                            <pre className="term" style={{ margin: 0 }}>
                              {c.sample?.command
                                ? `$ ${c.sample.command}`
                                : `${c.sample?.method ?? ""} ${c.sample?.path ?? ""}${c.sample?.body ? `\n\n${c.sample.body}` : ""}`}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card span-12">
          <div className="card-head"><h2>Recon & generic attack classes</h2><span className="sub">requests</span></div>
          <BarList items={(tags?.tags ?? []).map((t) => ({
            key: t.tag, value: t.hits,
            label: <><span className="tag">{t.tag}</span><span className="muted">{t.name}</span></>,
          }))} />
        </section>
      </div>
    </>
  );
}
