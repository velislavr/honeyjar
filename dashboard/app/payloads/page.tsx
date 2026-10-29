"use client";

import { BarList } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { ago, fmt, useApi, useStats } from "@/lib/api";

interface Malware {
  sha256: string; first_seen: string; last_seen: string; hits: number; source_url: string | null; ips: number;
  family: string | null; file_type: string | null; intel_tags: string[] | null;
}
interface Http { paths: { method: string; path: string; n: number; ips: number }[]; user_agents: { ua: string | null; n: number; ips: number }[] }

export default function PayloadsPage() {
  const { data } = useApi<{ malware: Malware[] }>("/stats/malware", 30000);
  const { data: http } = useStats<Http>("/stats/http", 30000);

  return (
    <>
      <PageHead eyebrow="Captured" title="Payloads & web probes" desc="Files attackers tried to drop on the fake shell (hash only; samples are never redistributed), plus the most-requested web paths and client fingerprints." />
      <div className="grid">
        <section className="card span-12">
          <div className="card-head"><h2>Captured malware</h2><span className="sub">all time · family via MalwareBazaar</span></div>
          {!data?.malware.length ? <div className="empty">No payloads captured yet</div> : (
            <div className="scroll-x">
              <table className="data">
                <thead><tr><th>SHA-256</th><th>Family</th><th>Type</th><th>Source (defanged)</th><th className="num">Drops</th><th className="num">IPs</th><th>Last seen</th></tr></thead>
                <tbody>
                  {data.malware.map((m) => (
                    <tr key={m.sha256}>
                      <td className="mono"><a className="link" href={`https://bazaar.abuse.ch/sample/${m.sha256}/`} target="_blank" rel="noreferrer" title={m.sha256}>{m.sha256.slice(0, 16)}…</a></td>
                      <td>{m.family ? <span className="badge ransom">{m.family}</span> : <span className="muted">unknown</span>}</td>
                      <td className="ink2">{m.file_type ?? "–"}</td>
                      <td className="mono ink2" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.source_url ?? "–"}</td>
                      <td className="num">{fmt(m.hits)}</td>
                      <td className="num">{fmt(m.ips)}</td>
                      <td className="muted">{ago(m.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="card span-7">
          <div className="card-head"><h2>Most requested web paths</h2><span className="sub">requests</span></div>
          <BarList items={(http?.paths ?? []).map((p, i) => ({
            key: `${i}`, value: p.n, title: p.path,
            label: <span className="mono"><span className="muted">{p.method}</span> {p.path}</span>,
          }))} />
        </section>
        <section className="card span-5">
          <div className="card-head"><h2>User agents</h2><span className="sub">requests</span></div>
          <BarList items={(http?.user_agents ?? []).map((u, i) => ({
            key: `${i}`, value: u.n, title: u.ua ?? "",
            label: <span className="mono">{u.ua ?? <span className="muted">(none)</span>}</span>,
          }))} />
        </section>
      </div>
    </>
  );
}
