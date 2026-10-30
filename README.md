# Honeyjar: live threat intelligence from internet-facing honeypots

A distributed honeynet that records real attacks against decoy SSH/Telnet servers and impersonated
VPN gateways, routers and web apps. It classifies each attack by **CVE** (cross-referenced with
**CISA KEV** and **FIRST EPSS**) and by **MITRE ATT&CK** technique, and streams everything to a
live dashboard with a 3D attack globe.

```
 Sensor VPS (×N regions)                          Core VPS
 ┌──────────────────────────────┐   WireGuard    ┌───────────────────────────────────────────────┐
 │ Cowrie   SSH 22 / Telnet 23  │──┐            │ FastAPI /api/ingest ─► Redis Stream             │
 │ HTTP(S) honeypot  10 ports   │  ├─ Vector ──►│   enrichment worker (GeoIP · CVE · ATT&CK)      │
 │ Docker · ES · Redis · ADB    │  │            │   ─► TimescaleDB ─► REST + WebSocket ─► Next.js │
 │ egress firewalled            │──┘  (disk     │                                                 │
 └──────────────────────────────┘     buffer)   │ feeds: CISA KEV · EPSS · DB-IP   Caddy (TLS)   │
                                                 └───────────────────────────────────────────────┘
```

## What it shows

| Page | Data |
|---|---|
| **Live** | 3D globe with arcs from attacker to sensor, colored by attack family; streaming feed; KPIs; trends |
| **Vulnerabilities** | CVE leaderboard: attempts, unique IPs, trend sparkline, CVSS, EPSS, KEV / ransomware status, captured payload |
| **Attackers** | source countries, hosting ASNs, targeted ports, most active IPs, per-IP profile with **session replay** |
| **Credentials** | top usernames / passwords / pairs, password length distribution |
| **ATT&CK** | technique heatmap by tactic, most common shell commands |
| **Payloads** | malware hashes (+ MalwareBazaar family), top web paths and user agents |

## Components

- **`sensor/http-honeypot`**: an aiohttp honeypot written for this project. It answers on 10 ports with
  product personas (FortiGate, GlobalProtect, Ivanti, Citrix, Exchange, GPON/Huawei/TP-Link routers, Hikvision,
  WordPress, Tomcat, phpMyAdmin, Spring Actuator, leaked `.env`/`.git`) so exploit chains reach their payload
  stage. It captures form and Basic-auth credentials. The same container runs the exposed services that
  cryptojacking crews hunt for: an unauthenticated **Docker Engine API** (2375), an open **Elasticsearch 7**
  (9200), **Redis 5** (6379, raw RESP) and an unsecured **Android Debug Bridge** (5555). They play along with
  container escapes, cron/rogue-master/Lua-escape attacks and `adb push` worms without executing anything or
  connecting out; pushed files are hashed, never stored.
- **`sensor/cowrie`**: Cowrie minus its well-known fingerprints. Instead of the stock Debian box with hostname
  `svr04`, user `phil` and an accept-everything login, it is an Ubuntu 22.04 server with 8 EPYC cores, 16 GB,
  real-looking users, bash history and app secrets as breadcrumbs. It accepts weak passwords but rejects the
  random strings bots use to detect honeypots.
- **`core/rules/cve/*.yaml`**: 85 CVE signatures plus 19 recon/abuse classes (field-scoped regex: path, raw path,
  headers, UA, body, command). Every rule is unit-tested against a real exploit request.
- **`core/rules/attack/*.yaml`**: 36 MITRE ATT&CK technique mappings for shell activity and service abuse
  (Docker API calls are normalized to `docker run …` commands so the same rules apply).
- **`core/honeyjar/worker.py`**: a Redis consumer-group worker. It normalizes Cowrie and HTTP records into one
  schema, carries session context, enriches events, bulk-`COPY`s them into TimescaleDB and publishes live events.
- **`core/honeyjar/feeds.py`**: daily sync of the CISA KEV catalog, EPSS scores and DB-IP Lite geolocation.
- **`core/honeyjar/intel.py`**: optional AbuseIPDB and MalwareBazaar lookups, rate-limited to free tiers.
- **`dashboard/`**: Next.js + TypeScript, hand-built SVG charts on a validated color-blind-safe palette.

## Run it locally (no internet exposure)

Requires Docker.

```bash
cp core/.env.example core/.env          # set POSTGRES_PASSWORD
cp sensor/.env.example sensor/.env
docker compose -f core/docker-compose.yml up -d --build      # db, redis, api, worker, feeds, dashboard
docker compose -f sensor/docker-compose.yml up -d --build    # cowrie, http + service honeypots, vector
```

- Dashboard at http://localhost:3001 (or `cd dashboard && npm run dev` on :3000). API docs at http://localhost:8000/api/docs.
- Generate test attacks against your own sensor:
  `pip install -r tools/attack-sim/requirements.txt && python tools/attack-sim/simulate.py`
- Local traffic comes from private IPs, so it has no geolocation. To preview the globe, `tools/demo-seed/seed.py`
  streams **synthetic** records under sensor id `demo`. Add `"demo": {"token": "demo-token", ...}` to
  `SENSORS`, and remove the data with `--purge`. Never run it against a public deployment, and never present it
  as real data.

Tests: `cd core && pip install -r requirements-dev.txt && pytest`.

## Deploy

The reference deployment runs entirely on **Azure for Students** free VM hours: the core on a 1 GB
`B2ats_v2` and sensors on `B1s` / `B2pts_v2`. GitHub Actions builds multi-arch images to GHCR, so the
small VMs only pull them. An Oracle Always Free micro can add a sensor. `infra/render.py` generates every secret
(WireGuard keys, sensor tokens, DB password) and renders paste-ready cloud-init for each machine.
**Step-by-step: [DEPLOY.md](DEPLOY.md).**

## Design

A honey design language in two themes: a light cream "comb" theme and a dark "night hive" theme. Each follows
the OS setting and can be switched in the header.

- **Type**: Fraunces with its `SOFT` axis at 100 for display text and numbers, Nunito Sans for UI text and DM Mono for
  IPs, CVEs and commands. All three are self-hosted with `next/font`.
- **Color**: every token is a single CSS `light-dark()` value. Each text/background pair is measured at 4.5:1 or
  better. The event families are honey (login attempts), berry (exploits) and indigo (shell activity). This palette
  passed a color-vision-deficiency validator for every pair, in both themes. Heatmaps and bars use a single-hue
  honey ramp.
- **Motifs**: a honeycomb wash behind page headers, a globe whose land is drawn as honey hexagons in a dark "jar",
  and hexagon accents on the stat tiles.
- **Accessibility**: visible focus everywhere, keyboard-operable rows, no emoji-as-icons, pause controls for live
  content and full support for `prefers-reduced-motion`.

## Safety

- **No execution**: Cowrie emulates the shell, and the HTTP honeypot only returns canned responses.
- **Containment**: honeypot containers are read-only, non-root, `cap_drop: ALL`, `no-new-privileges`, memory and PID
  limited, and sit on a dedicated bridge. `sensor/firewall.sh` drops all new egress from it, with an optional
  rate-limited HTTP(S) exception so Cowrie can capture payloads. SSH forwarding is disabled so the honeypot
  can't be used as a relay.
- **Isolation**: sensors hold no secrets except their ingest token. `/api/ingest` is reachable only over WireGuard
  (Caddy returns 404 publicly).
- **Publication**: malware is stored as hashes only, URLs and IPs inside payloads are defanged, and the public API
  is read-only and rate-limited.

## Data sources and attribution

IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
· [FIRST EPSS](https://www.first.org/epss/) · MITRE ATT&CK® · [Cowrie](https://github.com/cowrie/cowrie).
