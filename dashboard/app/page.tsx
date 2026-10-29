"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { BarList, LineChart, Tile } from "@/components/charts";
import LiveFeed from "@/components/LiveFeed";
import { PageHead } from "@/components/Shell";
import Icon, { CountryCode } from "@/components/Icon";
import { ago, fmt, useApi, useLiveEvents, useNow, useStats } from "@/lib/api";

const AttackGlobe = dynamic(() => import("@/components/AttackGlobe"), {
  ssr: false,
  loading: () => <div className="globe-wrap" />,
});

interface Overview {
  totals: Record<string, number>;
  timeline: { t: string; attacks: number; exploits: number; logins: number }[];
  by_proto: { proto: string; n: number }[];
}
interface Geo { countries: { country_code: string; country: string; events: number; ips: number }[] }
interface Cves { cves: { cve: string; name: string | null; hits: number; ips: number; kev: boolean }[] }

export default function LivePage() {
  const { events, connected, paused, setPaused, pending, lastEventAt } = useLiveEvents();
  const now = useNow(1000);
  // Honest telemetry: call the stream stale if nothing arrived for 5 minutes.
  const stale = now > 0 && (!connected || (lastEventAt != null && now - lastEventAt > 5 * 60_000));
  const { data: ov } = useStats<Overview>("/stats/overview");
  const { data: geo } = useStats<Geo>("/stats/geo", 30000);
  const { data: cves } = useStats<Cves>("/stats/cves?limit=8", 30000);
  const { data: sensors } = useApi<{ sensors: { id: string; label: string; lat: number | null; lon: number | null }[] }>("/sensors", 60000);
  const t = ov?.totals;

  return (
    <>
      <PageHead
        eyebrow="Honeynet · live" title="Live attack map"
        desc="Every arc is a real connection hitting one of our honeypot sensors, colored by what the attacker tried to do."
      />
      <div className="tiles">
        <Tile label="Attack events" value={fmt(t?.attacks)} note="connections + HTTP requests" />
        <Tile label="Unique attacker IPs" value={fmt(t?.unique_ips)} note={`from ${fmt(t?.countries)} countries`} />
        <Tile label="Login attempts" value={fmt(t?.login_attempts)} note={`${fmt(t?.login_successes)} let into the fake shell`} />
        <Tile label="Exploit attempts" value={fmt(t?.exploit_attempts)} note={`${fmt(t?.distinct_cves)} distinct CVEs`} />
        <Tile label="Shell commands" value={fmt(t?.commands)} note={`${fmt(t?.downloads)} malware downloads`} />
      </div>

      <div className="grid">
        <section className="card span-8" style={{ padding: 8 }}>
          <AttackGlobe events={events} sensors={sensors?.sensors ?? []} paused={paused} />
        </section>
        <section className="card span-4">
          <div className="card-head"><h2>Live feed</h2></div>
          <div className="livebar">
            <span className={`state ${stale ? "stale" : ""}`} role="status" aria-atomic="true">
              {!connected ? <><Icon name="alert" />Connecting…</>
                : stale ? <><Icon name="alert" />No events for {ago(new Date(lastEventAt!).toISOString()).replace(" ago", "")}</>
                : paused ? <>Paused{pending > 0 && <> · <span className="newcount">{pending} new</span></>}</>
                : <>Live · last event {lastEventAt ? ago(new Date(lastEventAt).toISOString()) : "–"}</>}
            </span>
            <button className="btn" onClick={() => setPaused(!paused)} aria-pressed={paused}>
              <Icon name={paused ? "play" : "pause"} />{paused ? "Resume" : "Pause"}
            </button>
          </div>
          <LiveFeed events={events} />
        </section>

        <section className="card span-4">
          <LineChart data={ov?.timeline ?? []} field="attacks" label="Attack events" color="var(--ink-2)" />
        </section>
        <section className="card span-4">
          <LineChart data={ov?.timeline ?? []} field="logins" label="Login attempts" color="var(--s-login)" />
        </section>
        <section className="card span-4">
          <LineChart data={ov?.timeline ?? []} field="exploits" label="Exploit attempts" color="var(--s-exploit)" />
        </section>

        <section className="card span-6">
          <div className="card-head"><h2>Top source countries</h2><span className="sub">unique IPs</span></div>
          <BarList items={(geo?.countries ?? []).slice(0, 10).map((c) => ({
            key: c.country_code, value: c.ips,
            label: <><CountryCode cc={c.country_code} />{c.country}</>,
          }))} />
        </section>
        <section className="card span-6">
          <div className="card-head">
            <h2>Most exploited vulnerabilities</h2>
            <Link className="link sub" href="/vulnerabilities">All CVEs →</Link>
          </div>
          <BarList items={(cves?.cves ?? []).map((c) => ({
            key: c.cve, value: c.hits, href: "/vulnerabilities", title: c.name ?? c.cve,
            label: <><span className="mono">{c.cve}</span>{c.kev && <span className="badge kev"><Icon name="alert" />KEV</span>}<span className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{c.name}</span></>,
          }))} empty="No exploit attempts in this window yet" />
        </section>
        <section className="card span-12">
          <div className="card-head"><h2>Attack surface</h2><span className="sub">events by protocol</span></div>
          <BarList items={(ov?.by_proto ?? []).map((p) => ({ key: p.proto, value: p.n, label: <span className="mono">{p.proto}</span> }))} />
        </section>
      </div>
    </>
  );
}
