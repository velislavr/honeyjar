"""Optional third-party threat intel, rate-limited to stay within free tiers.

- AbuseIPDB `check` (free: 1000/day): reputation of the top attacking IPs.
- MalwareBazaar `get_info`: family / file type for captured payload hashes.
Only hashes and IPs leave the core; samples are never uploaded.
"""
import asyncio
import logging

import asyncpg
import httpx
import redis.asyncio as aioredis

from . import config

log = logging.getLogger(__name__)

IP_QUEUE = "intel:ip"
HASH_QUEUE = "intel:hash"
ABUSE_INTERVAL = 90  # seconds between calls ~= 960/day
BAZAAR_INTERVAL = 10


MAX_QUEUE = 2000


async def queue_ip(r: aioredis.Redis, ip: str):
    if not config.ABUSEIPDB_KEY or await r.llen(IP_QUEUE) >= MAX_QUEUE:
        return
    # SET NX acts as a 24h "already queued" marker so each IP is checked at most daily.
    if await r.set(f"intel:seen:{ip}", 1, nx=True, ex=86400):
        await r.rpush(IP_QUEUE, ip)


async def queue_hash(r: aioredis.Redis, sha256: str):
    if not config.MALWAREBAZAAR_KEY:
        return
    if await r.set(f"intel:seenhash:{sha256}", 1, nx=True, ex=7 * 86400):
        await r.rpush(HASH_QUEUE, sha256)


async def abuseipdb_loop(r: aioredis.Redis, pool: asyncpg.Pool):
    if not config.ABUSEIPDB_KEY:
        return
    async with httpx.AsyncClient(timeout=15) as client:
        while True:
            item = await r.blpop(IP_QUEUE, timeout=0)
            ip = item[1]
            try:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": config.ABUSEIPDB_KEY, "Accept": "application/json"},
                )
                resp.raise_for_status()
                d = resp.json()["data"]
                await pool.execute(
                    """INSERT INTO ip_intel (ip, abuse_score, total_reports, usage_type, isp, is_tor, checked_at)
                       VALUES ($1, $2, $3, $4, $5, $6, now())
                       ON CONFLICT (ip) DO UPDATE SET abuse_score = EXCLUDED.abuse_score,
                         total_reports = EXCLUDED.total_reports, usage_type = EXCLUDED.usage_type,
                         isp = EXCLUDED.isp, is_tor = EXCLUDED.is_tor, checked_at = now()""",
                    ip, d.get("abuseConfidenceScore"), d.get("totalReports"), d.get("usageType"),
                    d.get("isp"), d.get("isTor"),
                )
            except Exception as e:  # noqa: BLE001 - intel is best effort
                log.warning("abuseipdb %s: %s", ip, e)
            await asyncio.sleep(ABUSE_INTERVAL)


async def malwarebazaar_loop(r: aioredis.Redis, pool: asyncpg.Pool):
    if not config.MALWAREBAZAAR_KEY:
        return
    async with httpx.AsyncClient(timeout=15) as client:
        while True:
            item = await r.blpop(HASH_QUEUE, timeout=0)
            sha = item[1]
            try:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_info", "hash": sha},
                    headers={"Auth-Key": config.MALWAREBAZAAR_KEY},
                )
                resp.raise_for_status()
                body = resp.json()
                family = file_type = None
                tags = None
                if body.get("query_status") == "ok" and body.get("data"):
                    d = body["data"][0]
                    family, file_type, tags = d.get("signature"), d.get("file_type"), d.get("tags")
                await pool.execute(
                    "UPDATE malware SET family = $2, file_type = $3, intel_tags = $4, checked_at = now() WHERE sha256 = $1",
                    sha, family, file_type, tags,
                )
            except Exception as e:  # noqa: BLE001
                log.warning("malwarebazaar %s: %s", sha, e)
            await asyncio.sleep(BAZAAR_INTERVAL)
