import { PageHead } from "@/components/Shell";
import { AUTHOR, pageMeta } from "@/lib/site";

export const metadata = pageMeta("/about");

const STAGES = [
  { t: "Sensors", d: "Cloud VPSes in several regions expose SSH/Telnet (Cowrie) and a custom HTTP(S) honeypot that impersonates Fortinet, Palo Alto, Ivanti, Citrix, routers, WordPress and more on 10 ports." },
  { t: "Shipping", d: "Vector tails the JSON logs and batches them over a WireGuard tunnel to the core, with a disk buffer so nothing is lost if the core restarts." },
  { t: "Ingest", d: "FastAPI authenticates each sensor by token and appends raw records to a Redis Stream, so ingestion never blocks on enrichment." },
  { t: "Enrichment", d: "A consumer-group worker normalizes every honeypot format into one event schema, geolocates the source IP, and runs the signature + ATT&CK engines." },
  { t: "Storage", d: "TimescaleDB hypertable with compression and continuous aggregates. KEV and EPSS feeds sync daily; AbuseIPDB and MalwareBazaar lookups stay within free-tier rate limits." },
  { t: "Dashboard", d: "This Next.js app: REST for aggregates, a WebSocket fan-out from Redis pub/sub for the live map." },
];

export default function AboutPage() {
  return (
    <>
      <PageHead eyebrow="Methodology" title="How it works" picker={false} desc="A distributed honeynet built to measure what attackers actually do on the internet right now, not what threat reports say they did last quarter." />
      <div className="grid">
        <section className="card span-12">
          <div className="card-head"><h2>Pipeline</h2></div>
          <svg viewBox="0 0 1200 120" width="100%" role="img" aria-label="Pipeline: sensors, Vector, ingest API, Redis stream, enrichment worker, TimescaleDB, dashboard">
            {["Honeypots", "Vector", "Ingest API", "Redis Stream", "Enricher", "TimescaleDB", "Dashboard"].map((n, i) => (
              <g key={n}>
                <rect x={i * 170 + 4} y={34} width={150} height={52} rx={10} fill="var(--surface-2)" stroke="var(--border)" />
                <text x={i * 170 + 79} y={65} textAnchor="middle" fontSize="15" fill="var(--ink)">{n}</text>
                {i < 6 && <path d={`M${i * 170 + 156},60 h14`} stroke="var(--muted)" strokeWidth="2" markerEnd="url(#arr)" />}
              </g>
            ))}
            <defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0L10,5L0,10z" fill="var(--muted)" /></marker></defs>
            <text x={600} y={110} textAnchor="middle" fontSize="12" fill="var(--muted)">WireGuard between sensors and core · Redis pub/sub → WebSocket for live events</text>
          </svg>
        </section>
        {STAGES.map((s) => (
          <section key={s.t} className="card span-4">
            <div className="card-head"><h2>{s.t}</h2></div>
            <p className="ink2" style={{ margin: 0 }}>{s.d}</p>
          </section>
        ))}
        <section className="card span-6">
          <div className="card-head"><h2>Detection</h2></div>
          <ul className="ink2" style={{ margin: 0, paddingLeft: 18 }}>
            <li>85 CVE signatures modelled on public PoCs and observed exploit traffic, each unit-tested with a positive payload and benign negatives.</li>
            <li>Every match is cross-referenced with the CISA KEV catalog (exploited in the wild, ransomware use) and the EPSS exploit-probability score.</li>
            <li>30+ MITRE ATT&CK technique mappings for post-login shell activity: discovery, persistence, defense evasion, resource hijacking.</li>
            <li>Recon classification: secret-file hunting, VCS exposure, webshell probes, scanner fingerprints.</li>
          </ul>
        </section>
        <section className="card span-6">
          <div className="card-head"><h2>Safety by design</h2></div>
          <ul className="ink2" style={{ margin: 0, paddingLeft: 18 }}>
            <li>Honeypots run unprivileged in read-only containers with all capabilities dropped, on an isolated bridge whose egress is firewalled.</li>
            <li>Nothing an attacker sends is executed: Cowrie emulates the shell, and the HTTP honeypot only returns canned responses.</li>
            <li>SSH port-forwarding is disabled, so the honeypot cannot be used as a relay.</li>
            <li>Malware is stored as hashes only; URLs and IPs inside payloads are defanged before display.</li>
          </ul>
        </section>
        <section className="card span-12">
          <div className="card-head"><h2>About the builder</h2></div>
          <p className="ink2" style={{ margin: "0 0 12px", maxWidth: 760 }}>
            Honeyjar is built by <strong>{AUTHOR.name}</strong>, {AUTHOR.role.toLowerCase()} who is applying that
            background to security: the sensors, the ingest and enrichment pipeline, the CVE and ATT&amp;CK detection
            rules, the deployment and this dashboard. The full source is public.
          </p>
          <div className="row" style={{ gap: 18 }}>
            <a className="link" href={AUTHOR.linkedin} rel="me noopener" target="_blank">LinkedIn</a>
            <a className="link" href={AUTHOR.github} rel="me noopener" target="_blank">GitHub</a>
            <a className="link" href={AUTHOR.repo} rel="noopener" target="_blank">Source code</a>
          </div>
        </section>
      </div>
    </>
  );
}
