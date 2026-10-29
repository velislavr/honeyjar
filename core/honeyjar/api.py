"""Public read-only stats API + live WebSocket + sensor ingest endpoint.

Everything is mounted under /api so a reverse proxy can forward one prefix.
/api/ingest must only be reachable from sensors (WireGuard); the proxy blocks it publicly.
"""
import asyncio
import ipaddress
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import orjson
import redis.asyncio as aioredis
from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse

from . import config, db
from .defang import defang
from .rules import RuleEngine

log = logging.getLogger("api")

WINDOWS = {
    "1h": (timedelta(hours=1), timedelta(minutes=1)),
    "24h": (timedelta(hours=24), timedelta(minutes=15)),
    "7d": (timedelta(days=7), timedelta(hours=2)),
    "30d": (timedelta(days=30), timedelta(hours=12)),
    "all": (timedelta(days=36500), timedelta(days=1)),
}
WindowParam = Query("24h", pattern="^(1h|24h|7d|30d|all)$")
ATTACK_TYPES = ("connect", "http_request", "exploit")


class LiveHub:
    """One Redis subscription fanned out to every connected WebSocket."""

    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def run(self, r: aioredis.Redis):
        while True:
            try:
                pubsub = r.pubsub()
                await pubsub.subscribe(config.LIVE_CHANNEL)
                async for msg in pubsub.listen():
                    if msg["type"] != "message" or not self.clients:
                        continue
                    data = msg["data"]
                    dead = []
                    for ws in list(self.clients):
                        try:
                            await asyncio.wait_for(ws.send_text(data), timeout=2)
                        except Exception:  # noqa: BLE001
                            dead.append(ws)
                    for ws in dead:
                        self.clients.discard(ws)
            except Exception:  # noqa: BLE001
                log.exception("live hub lost redis, reconnecting")
                await asyncio.sleep(2)


hub = LiveHub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await db.create_pool()
    app.state.redis = aioredis.from_url(config.REDIS_URL, decode_responses=True)
    app.state.rules = RuleEngine(config.RULES_DIR)
    task = asyncio.create_task(hub.run(app.state.redis))
    yield
    task.cancel()
    await app.state.pool.close()


app = FastAPI(title="Honeyjar API", lifespan=lifespan, default_response_class=ORJSONResponse,
              docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["GET"], allow_headers=["*"])
api = APIRouter(prefix="/api")


# ---------------------------------------------------------------- rate limiting

_buckets: dict[str, list[float]] = {}


def client_ip(request: Request) -> str:
    if config.TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            # The last hop is the one our proxy (Caddy) appended; earlier entries are client-supplied.
            return fwd.split(",")[-1].strip()
    return request.client.host if request.client else "?"


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path != "/api/ingest":
        ip = client_ip(request)
        now = time.monotonic()
        tokens, last = _buckets.get(ip, [config.RATE_LIMIT_PER_MIN, now])
        tokens = min(config.RATE_LIMIT_PER_MIN, tokens + (now - last) * config.RATE_LIMIT_PER_MIN / 60)
        if tokens < 1:
            return JSONResponse({"detail": "rate limited"}, status_code=429)
        _buckets[ip] = [tokens - 1, now]
        if len(_buckets) > 50_000:
            _buckets.clear()
    return await call_next(request)


# ---------------------------------------------------------------- helpers

def rows(records) -> list[dict]:
    return [dict(r) for r in records]


def since(window: str) -> datetime:
    return datetime.now(timezone.utc) - WINDOWS[window][0]


# "all" has no fixed length, so its bucket follows the history that exists: a fixed daily bucket
# would hand a young honeynet a one-point chart. Pick the finest bucket giving <= 240 points.
ALL_BUCKETS = [timedelta(minutes=m) for m in (1, 5, 15, 30)] +               [timedelta(hours=h) for h in (1, 2, 6, 12)] + [timedelta(days=d) for d in (1, 7)]


def all_bucket(span: timedelta) -> timedelta:
    return next((b for b in ALL_BUCKETS if span / b <= 240), ALL_BUCKETS[-1])


async def series_range(pool, window: str) -> tuple[datetime, timedelta]:
    """Start and bucket size for a window's time series."""
    if window != "all":
        return since(window), WINDOWS[window][1]
    now = datetime.now(timezone.utc)
    first = await pool.fetchval("SELECT min(ts) FROM events") or now - timedelta(hours=1)
    return first - timedelta(seconds=1), all_bucket(now - first)


def fill_series(records, bucket: timedelta, start: datetime, keys: tuple[str, ...]) -> list[dict]:
    """Zero-fill a time_bucket series so charts get evenly spaced points."""
    step = int(bucket.total_seconds())
    by_ts = {int(r["bucket"].timestamp()): r for r in records}
    now = int(time.time()) // step * step
    t = max(int(start.timestamp()) // step * step, now - 400 * step)
    out = []
    while t <= now:
        r = by_ts.get(t)
        out.append({"t": datetime.fromtimestamp(t, timezone.utc).isoformat(),
                    **{k: (r[k] if r else 0) for k in keys}})
        t += step
    return out


# ---------------------------------------------------------------- ingest

@api.post("/ingest")
async def ingest(request: Request):
    auth = request.headers.get("authorization", "")
    sensor = config.TOKEN_TO_SENSOR.get(auth.removeprefix("Bearer ").strip())
    if not sensor:
        raise HTTPException(401, "bad sensor token")
    body = await request.body()
    if body.lstrip()[:1] == b"[":
        records = orjson.loads(body)
    else:
        records = [orjson.loads(line) for line in body.splitlines() if line.strip()]
    r: aioredis.Redis = request.app.state.redis
    pipe = r.pipeline()
    for rec in records:
        if isinstance(rec, dict):
            pipe.xadd(config.RAW_STREAM, {"sensor": sensor, "data": orjson.dumps(rec)},
                      maxlen=200_000, approximate=True)
    await pipe.execute()
    return {"accepted": len(records)}


# ---------------------------------------------------------------- stats

@api.get("/stats/overview")
async def overview(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start, bucket = await series_range(pool, window)
    totals = await pool.fetchrow(
        """SELECT count(*) FILTER (WHERE event_type = ANY($2)) AS attacks,
                  count(*) AS events,
                  count(DISTINCT src_ip) AS unique_ips,
                  count(DISTINCT country_code) AS countries,
                  count(*) FILTER (WHERE event_type = 'login_attempt' OR username IS NOT NULL) AS login_attempts,
                  count(*) FILTER (WHERE login_success) AS login_successes,
                  count(*) FILTER (WHERE event_type = 'command') AS commands,
                  count(*) FILTER (WHERE cardinality(cves) > 0) AS exploit_attempts,
                  count(*) FILTER (WHERE event_type = 'download') AS downloads
           FROM events WHERE ts > $1""",
        start, list(ATTACK_TYPES),
    )
    distinct_cves = await pool.fetchval(
        "SELECT count(DISTINCT c) FROM events, unnest(cves) c WHERE ts > $1", start)
    series = await pool.fetch(
        """SELECT time_bucket($2::interval, ts) AS bucket,
                  count(*) FILTER (WHERE event_type = ANY($3)) AS attacks,
                  count(*) FILTER (WHERE cardinality(cves) > 0) AS exploits,
                  count(*) FILTER (WHERE event_type = 'login_attempt') AS logins
           FROM events WHERE ts > $1 GROUP BY bucket ORDER BY bucket""",
        start, bucket, list(ATTACK_TYPES),
    )
    by_proto = await pool.fetch(
        """SELECT coalesce(proto, honeypot) AS proto, count(*) AS n FROM events
           WHERE ts > $1 AND event_type = ANY($2) GROUP BY 1 ORDER BY n DESC""",
        start, list(ATTACK_TYPES),
    )
    return {
        "window": window,
        "totals": {**dict(totals), "distinct_cves": distinct_cves},
        "timeline": fill_series(series, bucket, start, ("attacks", "exploits", "logins")),
        "by_proto": rows(by_proto),
    }


@api.get("/stats/cves")
async def cves(request: Request, window: str = WindowParam, limit: int = Query(40, le=100)):
    pool = request.app.state.pool
    start, bucket = await series_range(pool, window)
    top = await pool.fetch(
        """SELECT c AS cve, count(*) AS hits, count(DISTINCT src_ip) AS ips,
                  count(DISTINCT country_code) AS countries, min(ts) AS first_seen, max(ts) AS last_seen
           FROM events, unnest(cves) c WHERE ts > $1 GROUP BY c ORDER BY hits DESC LIMIT $2""",
        start, limit,
    )
    ids = [r["cve"] for r in top]
    info = {r["cve_id"]: dict(r) for r in await pool.fetch(
        """SELECT cve_id, name, description, vendor, product, cvss, kev, kev_date_added, kev_ransomware,
                  epss, epss_percentile FROM cve_info WHERE cve_id = ANY($1)""", ids)}
    spark_rows = await pool.fetch(
        """SELECT c AS cve, time_bucket($2::interval, ts) AS bucket, count(*) AS n
           FROM events, unnest(cves) c WHERE ts > $1 AND c = ANY($3) GROUP BY c, bucket""",
        start, bucket, ids,
    )
    sparks: dict[str, list] = {}
    for r in spark_rows:
        sparks.setdefault(r["cve"], []).append(r)
    samples = {r["cve"]: r for r in await pool.fetch(
        """SELECT DISTINCT ON (c) c AS cve, http_method, http_path, http_body, command, host(src_ip) AS src_ip
           FROM events, unnest(cves) c WHERE ts > $1 AND c = ANY($2) ORDER BY c, ts DESC""",
        start, ids)}
    out = []
    for r in top:
        s = samples.get(r["cve"])
        out.append({
            **dict(r),
            **{k: v for k, v in info.get(r["cve"], {}).items() if k != "cve_id"},
            "trend": [p["n"] for p in fill_series(sparks.get(r["cve"], []), bucket, start, ("n",))],
            "sample": s and {
                "method": s["http_method"], "path": defang(s["http_path"]),
                "body": defang((s["http_body"] or "")[:600]) or None,
                "command": defang(s["command"]),
            },
        })
    return {"window": window, "cves": out}


@api.get("/stats/tags")
async def tags(request: Request, window: str = WindowParam):
    names = {r.tag: r.name for r in request.app.state.rules.sig_rules if r.tag}
    res = await request.app.state.pool.fetch(
        """SELECT t AS tag, count(*) AS hits, count(DISTINCT src_ip) AS ips
           FROM events, unnest(tags) t WHERE ts > $1 GROUP BY t ORDER BY hits DESC""",
        since(window))
    return {"window": window, "tags": [{**dict(r), "name": names.get(r["tag"])} for r in res]}


@api.get("/stats/geo")
async def geo(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start = since(window)
    countries = await pool.fetch(
        """SELECT country_code, max(country) AS country, count(*) AS events, count(DISTINCT src_ip) AS ips,
                  count(*) FILTER (WHERE cardinality(cves) > 0) AS exploits
           FROM events WHERE ts > $1 AND country_code IS NOT NULL
           GROUP BY country_code ORDER BY ips DESC""", start)
    asns = await pool.fetch(
        """SELECT asn, max(as_org) AS as_org, count(*) AS events, count(DISTINCT src_ip) AS ips
           FROM events WHERE ts > $1 AND asn IS NOT NULL GROUP BY asn ORDER BY ips DESC LIMIT 25""", start)
    ports = await pool.fetch(
        """SELECT dst_port, coalesce(proto, honeypot) AS proto, count(*) AS events, count(DISTINCT src_ip) AS ips
           FROM events WHERE ts > $1 AND dst_port IS NOT NULL AND event_type = ANY($2)
           GROUP BY 1, 2 ORDER BY events DESC LIMIT 25""", start, list(ATTACK_TYPES))
    return {"window": window, "countries": rows(countries), "asns": rows(asns), "ports": rows(ports)}


@api.get("/stats/creds")
async def creds(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start = since(window)
    base = "FROM events WHERE ts > $1 AND (event_type = 'login_attempt' OR username IS NOT NULL)"
    usernames = await pool.fetch(f"SELECT username AS value, count(*) AS n {base} AND username IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 25", start)
    passwords = await pool.fetch(f"SELECT password AS value, count(*) AS n {base} AND password IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 25", start)
    pairs = await pool.fetch(f"SELECT username, password, count(*) AS n {base} GROUP BY 1, 2 ORDER BY n DESC LIMIT 25", start)
    lengths = await pool.fetch(f"SELECT least(length(password), 20) AS len, count(*) AS n {base} AND password IS NOT NULL GROUP BY 1 ORDER BY 1", start)
    totals = await pool.fetchrow(
        f"""SELECT count(*) AS attempts, count(*) FILTER (WHERE login_success) AS successes,
                   count(DISTINCT username) AS unique_usernames, count(DISTINCT password) AS unique_passwords,
                   count(DISTINCT src_ip) AS ips {base}""", start)
    return {"window": window, "totals": dict(totals), "usernames": rows(usernames), "passwords": rows(passwords),
            "pairs": rows(pairs), "lengths": rows(lengths)}


@api.get("/stats/techniques")
async def techniques(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start = since(window)
    meta = request.app.state.rules.techniques
    res = await pool.fetch(
        """SELECT t AS technique, count(*) AS hits, count(DISTINCT src_ip) AS ips
           FROM events, unnest(techniques) t WHERE ts > $1 GROUP BY t ORDER BY hits DESC""", start)
    commands = await pool.fetch(
        """SELECT command, count(*) AS n, count(DISTINCT src_ip) AS ips FROM events
           WHERE ts > $1 AND event_type = 'command' GROUP BY command ORDER BY n DESC LIMIT 30""", start)
    seen = {r["technique"]: dict(r) for r in res}
    catalog = [
        {"technique": t.id, "name": t.name, "tactic": t.tactic,
         "hits": seen.get(t.id, {}).get("hits", 0), "ips": seen.get(t.id, {}).get("ips", 0)}
        for t in meta.values()
    ]
    return {"window": window, "techniques": catalog,
            "commands": [{**dict(r), "command": defang(r["command"])} for r in commands]}


@api.get("/stats/http")
async def http_stats(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start = since(window)
    paths = await pool.fetch(
        """SELECT http_method AS method, split_part(http_path, '?', 1) AS path, count(*) AS n,
                  count(DISTINCT src_ip) AS ips
           FROM events WHERE ts > $1 AND honeypot = 'http' GROUP BY 1, 2 ORDER BY n DESC LIMIT 30""", start)
    uas = await pool.fetch(
        """SELECT http_ua AS ua, count(*) AS n, count(DISTINCT src_ip) AS ips FROM events
           WHERE ts > $1 AND honeypot = 'http' GROUP BY 1 ORDER BY n DESC LIMIT 20""", start)
    return {"window": window, "paths": [{**dict(r), "path": defang(r["path"])} for r in paths], "user_agents": rows(uas)}


@api.get("/stats/malware")
async def malware(request: Request):
    res = await request.app.state.pool.fetch(
        """SELECT sha256, first_seen, last_seen, hits, source_url, cardinality(src_ips) AS ips,
                  family, file_type, intel_tags FROM malware ORDER BY last_seen DESC LIMIT 100""")
    return {"malware": [{**dict(r), "source_url": defang(r["source_url"])} for r in res]}


# ---------------------------------------------------------------- attackers / sessions / live

@api.get("/attackers/top")
async def top_attackers(request: Request, window: str = WindowParam, limit: int = Query(50, le=200)):
    res = await request.app.state.pool.fetch(
        """SELECT host(src_ip) AS ip, max(country_code) AS country_code, max(country) AS country,
                  max(as_org) AS as_org, count(*) AS events,
                  count(*) FILTER (WHERE event_type = 'login_attempt') AS logins,
                  count(*) FILTER (WHERE event_type = 'command') AS commands,
                  count(*) FILTER (WHERE cardinality(cves) > 0) AS exploits,
                  array_agg(DISTINCT honeypot) AS honeypots, min(ts) AS first_seen, max(ts) AS last_seen
           FROM events WHERE ts > $1 GROUP BY src_ip ORDER BY events DESC LIMIT $2""",
        since(window), limit)
    return {"window": window, "attackers": rows(res)}


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise HTTPException(400, "invalid ip") from None


@api.get("/attackers/{ip}")
async def attacker(request: Request, ip: str):
    ip = _ip(ip)
    pool = request.app.state.pool
    summary = await pool.fetchrow(
        """SELECT count(*) AS events, min(ts) AS first_seen, max(ts) AS last_seen,
                  max(country_code) AS country_code, max(country) AS country, max(city) AS city,
                  max(asn) AS asn, max(as_org) AS as_org,
                  count(*) FILTER (WHERE event_type = 'login_attempt') AS logins,
                  count(*) FILTER (WHERE login_success) AS login_successes,
                  count(*) FILTER (WHERE event_type = 'command') AS commands,
                  count(DISTINCT session_id) AS sessions,
                  array_agg(DISTINCT dst_port) FILTER (WHERE dst_port IS NOT NULL) AS ports,
                  array_agg(DISTINCT honeypot) AS honeypots
           FROM events WHERE src_ip = $1::inet""", ip)
    if not summary["events"]:
        raise HTTPException(404, "no activity from this ip")
    cve_list = await pool.fetch("SELECT DISTINCT unnest(cves) AS cve FROM events WHERE src_ip = $1::inet", ip)
    tech_list = await pool.fetch("SELECT DISTINCT unnest(techniques) AS t FROM events WHERE src_ip = $1::inet", ip)
    intel_row = await pool.fetchrow("SELECT abuse_score, total_reports, usage_type, isp, is_tor, checked_at FROM ip_intel WHERE ip = $1::inet", ip)
    sessions = await pool.fetch(
        """SELECT session_id, min(ts) AS start, max(ts) AS end, max(proto) AS proto,
                  count(*) FILTER (WHERE event_type = 'login_attempt') AS logins,
                  count(*) FILTER (WHERE event_type = 'command') AS commands,
                  bool_or(login_success) AS logged_in
           FROM events WHERE src_ip = $1::inet AND session_id IS NOT NULL
           GROUP BY session_id ORDER BY start DESC LIMIT 50""", ip)
    recent = await pool.fetch(
        """SELECT ts, honeypot, event_type, dst_port, username, password, command, http_method, http_path,
                  cves, techniques, tags FROM events WHERE src_ip = $1::inet ORDER BY ts DESC LIMIT 200""", ip)
    return {
        "ip": ip, "summary": dict(summary),
        "cves": [r["cve"] for r in cve_list], "techniques": [r["t"] for r in tech_list],
        "intel": dict(intel_row) if intel_row else None,
        "sessions": rows(sessions),
        "events": [{**dict(r), "command": defang(r["command"]), "http_path": defang(r["http_path"])} for r in recent],
    }


@api.get("/sessions/{session_id}")
async def session(request: Request, session_id: str):
    res = await request.app.state.pool.fetch(
        """SELECT ts, host(src_ip) AS src_ip, proto, event_type, username, password, login_success, command,
                  download_url, techniques, extra FROM events WHERE session_id = $1 ORDER BY ts LIMIT 2000""",
        session_id[:64])
    if not res:
        raise HTTPException(404, "unknown session")
    return {"session_id": session_id, "events": [
        {**dict(r), "command": defang(r["command"]), "download_url": defang(r["download_url"])} for r in res]}


@api.get("/events/recent")
async def recent_events(request: Request, limit: int = Query(60, le=200)):
    from .schemas import LIVE_TYPES  # local import keeps the module header readable
    res = await request.app.state.pool.fetch(
        """SELECT ts, sensor_id, honeypot, proto, event_type, host(src_ip) AS src_ip, dst_port, country_code,
                  country, city, lat, lon, as_org, username, password, login_success, command,
                  http_method, http_path, download_url, cves, tags, techniques
           FROM events WHERE ts > now() - interval '1 day' AND event_type = ANY($1)
           ORDER BY ts DESC LIMIT $2""", list(LIVE_TYPES), limit)
    out = []
    for r in res:
        d = dict(r)
        s = config.SENSORS.get(d["sensor_id"], {})
        d.update(sensor_lat=s.get("lat"), sensor_lon=s.get("lon"),
                 command=defang((d["command"] or "")[:300]) or None,
                 http_path=defang((d["http_path"] or "")[:300]) or None,
                 download_url=defang(d["download_url"]))
        out.append(d)
    return {"events": out}


@api.get("/sensors")
async def sensors(request: Request):
    seen = {r["id"]: r["last_seen"] for r in await request.app.state.pool.fetch("SELECT id, last_seen FROM sensors")}
    return {"sensors": [
        {"id": sid, "label": s.get("label", sid), "lat": s.get("lat"), "lon": s.get("lon"),
         "last_seen": seen.get(sid)}
        for sid, s in config.SENSORS.items()
    ]}


@api.get("/health")
async def health(request: Request):
    await request.app.state.pool.fetchval("SELECT 1")
    lag = await request.app.state.redis.xlen(config.RAW_STREAM)
    return {"ok": True, "stream_len": lag}


@api.websocket("/ws/live")
async def live(ws: WebSocket):
    await ws.accept()
    if len(hub.clients) >= 500:
        await ws.close(code=1013)
        return
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # keeps the connection open; client pings are ignored
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


app.include_router(api)
