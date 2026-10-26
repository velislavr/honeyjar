"""External feed sync.

    python -m honeyjar.feeds kev     # CISA Known Exploited Vulnerabilities catalog
    python -m honeyjar.feeds epss    # FIRST EPSS exploit-probability scores
    python -m honeyjar.feeds geoip   # DB-IP Lite city + ASN databases
    python -m honeyjar.feeds loop    # all of the above, daily
"""
import asyncio
import gzip
import logging
import sys
from datetime import date, datetime, timedelta, timezone

import httpx

from . import config, db

log = logging.getLogger("feeds")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"


async def sync_kev(pool, client: httpx.AsyncClient):
    resp = await client.get(KEV_URL)
    resp.raise_for_status()
    vulns = resp.json()["vulnerabilities"]
    await pool.executemany(
        """INSERT INTO cve_info (cve_id, name, description, vendor, product, kev, kev_date_added, kev_ransomware, updated_at)
           VALUES ($1, $2, $3, $4, $5, true, $6, $7, now())
           ON CONFLICT (cve_id) DO UPDATE SET
             name = coalesce(cve_info.name, EXCLUDED.name), description = EXCLUDED.description,
             vendor = EXCLUDED.vendor, product = EXCLUDED.product, kev = true,
             kev_date_added = EXCLUDED.kev_date_added, kev_ransomware = EXCLUDED.kev_ransomware, updated_at = now()""",
        [(v["cveID"], v.get("vulnerabilityName"), v.get("shortDescription"), v.get("vendorProject"),
          v.get("product"), date.fromisoformat(v["dateAdded"]) if v.get("dateAdded") else None,
          v.get("knownRansomwareCampaignUse") == "Known") for v in vulns],
    )
    log.info("kev: %d entries", len(vulns))


async def sync_epss(pool, client: httpx.AsyncClient):
    # Score the CVEs we have rules for or have actually seen, rather than all ~250k.
    ids = [r["cve_id"] for r in await pool.fetch(
        """SELECT cve_id FROM cve_info WHERE cvss IS NOT NULL
           UNION SELECT DISTINCT unnest(cves) FROM events WHERE ts > now() - interval '30 days'""")]
    updated = 0
    for i in range(0, len(ids), 100):
        resp = await client.get(EPSS_URL, params={"cve": ",".join(ids[i:i + 100])})
        resp.raise_for_status()
        data = resp.json().get("data", [])
        await pool.executemany(
            """INSERT INTO cve_info (cve_id, epss, epss_percentile, updated_at) VALUES ($1, $2, $3, now())
               ON CONFLICT (cve_id) DO UPDATE SET epss = EXCLUDED.epss,
                 epss_percentile = EXCLUDED.epss_percentile, updated_at = now()""",
            [(d["cve"], float(d["epss"]), float(d["percentile"])) for d in data],
        )
        updated += len(data)
    log.info("epss: %d scores", updated)


async def sync_geoip(client: httpx.AsyncClient):
    config.GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc)
    months = [today.strftime("%Y-%m"),
              (today.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
    for kind in ("city", "asn"):
        for ym in months:
            resp = await client.get(DBIP_URL.format(kind=kind, ym=ym))
            if resp.status_code == 200:
                dest = config.GEOIP_DIR / f"dbip-{kind}-lite.mmdb"
                tmp = dest.with_suffix(".tmp")
                tmp.write_bytes(gzip.decompress(resp.content))
                tmp.replace(dest)
                log.info("geoip: %s %s (%d MB)", kind, ym, dest.stat().st_size // 2**20)
                break
        else:
            log.error("geoip: could not download db-ip %s database", kind)


async def run(cmd: str):
    async with httpx.AsyncClient(timeout=120, follow_redirects=True,
                                 headers={"User-Agent": "honeyjar-feeds/1.0"}) as client:
        if cmd == "geoip":
            await sync_geoip(client)
            return
        pool = await db.create_pool()
        try:
            if cmd in ("kev", "all"):
                await sync_kev(pool, client)
            if cmd in ("epss", "all"):
                await sync_epss(pool, client)
        finally:
            await pool.close()


async def loop():
    while True:
        for cmd in ("geoip", "all"):
            try:
                await run(cmd)
            except Exception:  # noqa: BLE001 - keep the daily loop alive
                log.exception("feed %s failed", cmd)
        await asyncio.sleep(24 * 3600)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    asyncio.run(loop() if arg == "loop" else run(arg))
