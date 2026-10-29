"use client";

import { BarList, Tile } from "@/components/charts";
import { PageHead } from "@/components/Shell";
import { fmt, useStats } from "@/lib/api";

interface Creds {
  totals: { attempts: number; successes: number; unique_usernames: number; unique_passwords: number; ips: number };
  usernames: { value: string; n: number }[];
  passwords: { value: string; n: number }[];
  pairs: { username: string | null; password: string | null; n: number }[];
  lengths: { len: number; n: number }[];
}

const show = (v: string | null) => (v == null ? <span className="muted">(none)</span> : v === "" ? <span className="muted">(empty)</span> : v);

export default function CredentialsPage() {
  const { data } = useStats<Creds>("/stats/creds", 20000);
  const t = data?.totals;
  const lenMax = Math.max(1, ...(data?.lengths ?? []).map((l) => l.n));

  return (
    <>
      <PageHead eyebrow="Brute force" title="Credential stuffing" desc="Usernames and passwords bots try against SSH, Telnet and fake web logins (WordPress, Tomcat, phpMyAdmin, VPN portals). These are the passwords that should never be in use." />
      <div className="tiles">
        <Tile label="Login attempts" value={fmt(t?.attempts)} />
        <Tile label="Unique usernames" value={fmt(t?.unique_usernames)} />
        <Tile label="Unique passwords" value={fmt(t?.unique_passwords)} />
        <Tile label="Brute-forcing IPs" value={fmt(t?.ips)} />
      </div>
      <div className="grid">
        <section className="card span-4">
          <div className="card-head"><h2>Top usernames</h2><span className="sub">attempts</span></div>
          <BarList items={(data?.usernames ?? []).map((u) => ({ key: u.value, value: u.n, label: <span className="mono">{show(u.value)}</span> }))} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Top passwords</h2><span className="sub">attempts</span></div>
          <BarList items={(data?.passwords ?? []).map((p) => ({ key: p.value, value: p.n, label: <span className="mono">{show(p.value)}</span> }))} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Top combinations</h2><span className="sub">attempts</span></div>
          <BarList items={(data?.pairs ?? []).map((p) => ({
            key: `${p.username}:${p.password}`, value: p.n,
            label: <span className="mono">{show(p.username)} <span className="muted">:</span> {show(p.password)}</span>,
          }))} />
        </section>
        <section className="card span-12">
          <div className="card-head"><h2>Password length distribution</h2><span className="sub">characters (20 = 20+)</span></div>
          {!data?.lengths.length ? <div className="empty">No data in this window yet</div> : (
            <svg viewBox="0 0 640 170" width="100%" height="170" role="img" aria-label="Password length histogram">
              {Array.from({ length: 21 }, (_, len) => {
                const n = data.lengths.find((l) => l.len === len)?.n ?? 0;
                const bw = 640 / 21;
                const h = (n / lenMax) * 130;
                return (
                  <g key={len}>
                    <title>{`${len}${len === 20 ? "+" : ""} chars: ${n.toLocaleString()} attempts`}</title>
                    <rect x={len * bw + 1} y={0} width={bw - 2} height={150} fill="transparent" />
                    {n > 0 && <path d={roundTop(len * bw + 1, 150 - h, bw - 2, h)} fill="var(--s-login)" />}
                    <text x={len * bw + bw / 2} y={165} textAnchor="middle" fontSize="11" fill="var(--muted)">{len}{len === 20 ? "+" : ""}</text>
                  </g>
                );
              })}
              <line x1="0" x2="640" y1="150" y2="150" stroke="var(--baseline)" />
            </svg>
          )}
        </section>
      </div>
    </>
  );
}

function roundTop(x: number, y: number, w: number, h: number) {
  const r = Math.min(4, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
