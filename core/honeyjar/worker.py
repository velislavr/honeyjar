"""Enrichment worker: Redis stream -> normalize -> GeoIP/CVE/ATT&CK -> Postgres + live pub/sub."""
import asyncio
import logging
import os
import socket
from collections import OrderedDict

import asyncpg
import orjson
import redis.asyncio as aioredis

from . import config, db, intel
from .defang import defang
from .geo import GeoLookup
from .normalize import normalize
from .rules import RuleEngine
from .schemas import LIVE_TYPES, Event

log = logging.getLogger("worker")

GROUP = "enrichers"
BATCH = 500


class Enricher:
    """Stateless-ish enrichment, kept separate from I/O so it is unit-testable."""

    def __init__(self, rules: RuleEngine, geo: GeoLookup | None):
        self.rules = rules
        self.geo = geo
        # Cowrie only reports protocol/dst_port on the connect event; remember them per session.
        self.sessions: OrderedDict[str, tuple[str | None, int | None]] = OrderedDict()

    def enrich(self, raw: dict, sensor_id: str) -> Event | None:
        ev = normalize(raw, sensor_id)
        if ev is None:
            return None
        if ev.session_id:
            if ev.event_type == "connect":
                self.sessions[ev.session_id] = (ev.proto, ev.dst_port)
                if len(self.sessions) > 200_000:
                    self.sessions.popitem(last=False)
            elif ev.session_id in self.sessions:
                proto, port = self.sessions[ev.session_id]
                ev.proto = ev.proto or proto
                ev.dst_port = ev.dst_port or port
        if self.geo:
            for k, v in self.geo.lookup(ev.src_ip).items():
                setattr(ev, k, v)
        return self.rules.apply(ev)


def live_payload(ev: Event) -> dict:
    sensor = config.SENSORS.get(ev.sensor_id, {})
    return {
        "ts": ev.ts.isoformat(),
        "sensor_id": ev.sensor_id,
        "sensor_lat": sensor.get("lat"),
        "sensor_lon": sensor.get("lon"),
        "honeypot": ev.honeypot,
        "proto": ev.proto,
        "event_type": ev.event_type,
        "src_ip": ev.src_ip,
        "dst_port": ev.dst_port,
        "country_code": ev.country_code,
        "country": ev.country,
        "city": ev.city,
        "lat": ev.lat,
        "lon": ev.lon,
        "as_org": ev.as_org,
        "username": ev.username,
        "password": ev.password,
        "login_success": ev.login_success,
        "command": defang((ev.command or "")[:300]) or None,
        "http_method": ev.http_method,
        "http_path": defang((ev.http_path or "")[:300]) or None,
        "download_url": defang(ev.download_url),
        "cves": ev.cves,
        "tags": ev.tags,
        "techniques": ev.techniques,
    }


async def seed_cve_catalog(pool: asyncpg.Pool, rules: RuleEngine):
    rows = [(cve, m["name"], m["cvss"]) for cve, m in rules.cve_catalog.items()]
    await pool.executemany(
        """INSERT INTO cve_info (cve_id, name, cvss) VALUES ($1, $2, $3)
           ON CONFLICT (cve_id) DO UPDATE SET name = EXCLUDED.name, cvss = COALESCE(EXCLUDED.cvss, cve_info.cvss)""",
        rows,
    )


async def side_effects(pool: asyncpg.Pool, r: aioredis.Redis, events: list[Event]):
    downloads = [e for e in events if e.event_type == "download" and e.payload_hash]
    for e in downloads:
        await pool.execute(
            """INSERT INTO malware (sha256, first_seen, last_seen, hits, source_url, src_ips)
               VALUES ($1, $2, $2, 1, $3, ARRAY[$4::inet])
               ON CONFLICT (sha256) DO UPDATE SET
                 last_seen = GREATEST(malware.last_seen, EXCLUDED.last_seen),
                 hits = malware.hits + 1,
                 source_url = COALESCE(malware.source_url, EXCLUDED.source_url),
                 src_ips = CASE WHEN $4::inet = ANY(malware.src_ips) OR cardinality(malware.src_ips) >= 50
                                THEN malware.src_ips ELSE malware.src_ips || $4::inet END""",
            e.payload_hash, e.ts, e.download_url, e.src_ip,
        )
        await intel.queue_hash(r, e.payload_hash)
    for e in events:
        if e.cves or e.event_type in ("command", "download") or e.login_success:
            await intel.queue_ip(r, e.src_ip)
    sensors = {e.sensor_id: e.ts for e in events}
    await pool.executemany(
        """INSERT INTO sensors (id, last_seen) VALUES ($1, $2)
           ON CONFLICT (id) DO UPDATE SET last_seen = GREATEST(sensors.last_seen, EXCLUDED.last_seen)""",
        list(sensors.items()),
    )


async def consume(pool: asyncpg.Pool, r: aioredis.Redis, enricher: Enricher):
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    try:
        await r.xgroup_create(config.RAW_STREAM, GROUP, id="0", mkstream=True)
    except aioredis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise
    last_id = "0"  # first drain our own pending (un-acked) entries, then switch to new ones
    while True:
        resp = await r.xreadgroup(GROUP, consumer, {config.RAW_STREAM: last_id}, count=BATCH, block=5000)
        msgs = resp[0][1] if resp else []
        if last_id == "0" and not msgs:
            last_id = ">"
            continue
        if not msgs:
            continue
        events: list[Event] = []
        for _, fields in msgs:
            try:
                ev = enricher.enrich(orjson.loads(fields["data"]), fields["sensor"])
            except Exception:  # noqa: BLE001 - one bad record must not stall the stream
                log.exception("failed to process record")
                continue
            if ev:
                events.append(ev)
        await db.insert_events(pool, events)
        await side_effects(pool, r, events)
        if events:
            pipe = r.pipeline()
            for ev in events:
                if ev.event_type in LIVE_TYPES:
                    pipe.publish(config.LIVE_CHANNEL, orjson.dumps(live_payload(ev)))
            await pipe.execute()
        ids = [mid for mid, _ in msgs]
        # Stored in Postgres now; drop them from the stream so Redis memory stays flat.
        await r.pipeline().xack(config.RAW_STREAM, GROUP, *ids).xdel(config.RAW_STREAM, *ids).execute()
        log.info("processed %d records -> %d events", len(msgs), len(events))


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    rules = RuleEngine(config.RULES_DIR)
    enricher = Enricher(rules, GeoLookup(config.GEOIP_DIR))
    pool = await db.create_pool()
    r = aioredis.from_url(config.REDIS_URL, decode_responses=True)
    await seed_cve_catalog(pool, rules)
    log.info("loaded %d signatures, %d techniques", len(rules.sig_rules), len(rules.techniques))
    await asyncio.gather(
        consume(pool, r, enricher),
        intel.abuseipdb_loop(r, pool),
        intel.malwarebazaar_loop(r, pool),
    )


if __name__ == "__main__":
    asyncio.run(main())
