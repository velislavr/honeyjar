"""Public read-only stats API + live WebSocket + sensor ingest endpoint.

Everything is mounted under /api so a reverse proxy can forward one prefix.
/api/ingest must only be reachable from sensors (WireGuard); the proxy blocks it publicly.
"""
import asyncio
import functools
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
from .rollups import COMMANDS, CREDS, HTTP, IPS, PORTS, TAGS, TECHNIQUES, Rollup
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


def source(rollup: Rollup, window: str) -> tuple[str, datetime]:
    """What a stats query reads for a window, and from when. The last hour reads raw events, since
    one hourly bucket would be most of it; longer windows read the hourly rollup."""
    start = since(window)
    if WINDOWS[window][0] <= timedelta(hours=1):
        return rollup.raw, start
    return rollup.view, start.replace(minute=0, second=0, microsecond=0)


def total(col: str, alias: str | None = None) -> str:
    return f"coalesce(sum({col}), 0)::bigint AS {alias or col}"


# Every viewer polls every stats panel, so identical requests arrive in bursts. Keep each answer
# for a while (longer for windows that barely move) and let concurrent misses share one query.
CACHE_TTL = {"1h": 10, "24h": 30, "7d": 120, "30d": 300, "all": 300}
_cache: dict[tuple, tuple[float, asyncio.Future]] = {}


def cached(fn):
    @functools.wraps(fn)
    async def wrapper(request: Request, **params):
        key = (fn.__name__, *sorted(params.items()))
        hit = _cache.get(key)
        if hit and hit[0] > time.monotonic():
            return await asyncio.shield(hit[1])
        fut = asyncio.ensure_future(fn(request, **params))
        _cache[key] = (time.monotonic() + CACHE_TTL.get(params.get("window"), 30), fut)
        try:
            return await asyncio.shield(fut)
        except Exception:
            _cache.pop(key, None)
            raise
    return wrapper


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
@cached
async def overview(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start, bucket = await series_range(pool, window)
    ips, ips_from = source(IPS, window)
    ports, ports_from = source(PORTS, window)
    totals = await pool.fetchrow(
        f"""SELECT {total("attacks")}, {total("events")},
                   count(DISTINCT src_ip) AS unique_ips, count(DISTINCT country_code) AS countries,
                   {total("login_attempts")}, {total("login_successes")}, {total("commands")},
                   {total("exploits", "exploit_attempts")}, {total("downloads")}
            FROM {ips} r WHERE bucket >= $1""", ips_from)
    distinct_cves = await pool.fetchval(
        "SELECT count(DISTINCT c) FROM events, unnest(cves) c WHERE ts > $1 AND cardinality(cves) > 0", start)
    series = await pool.fetch(
        """SELECT time_bucket($2::interval, bucket) AS bucket, sum(attacks)::bigint AS attacks,
                  sum(exploits)::bigint AS exploits, sum(logins)::bigint AS logins
           FROM events_1m WHERE bucket >= date_trunc('minute', $1::timestamptz) GROUP BY 1 ORDER BY 1""", start, bucket)
    by_proto = await pool.fetch(
        f"SELECT proto, {total('n')} FROM {ports} r WHERE bucket >= $1 GROUP BY 1 ORDER BY n DESC", ports_from)
    return {
        "window": window,
        "totals": {**dict(totals), "distinct_cves": distinct_cves},
        "timeline": fill_series(series, bucket, start, ("attacks", "exploits", "logins")),
        "by_proto": rows(by_proto),
    }


@api.get("/stats/cves")
@cached
async def cves(request: Request, window: str = WindowParam, limit: int = Query(40, le=100)):
    pool = request.app.state.pool
    start, bucket = await series_range(pool, window)
    top = await pool.fetch(
        """SELECT c AS cve, count(*) AS hits, count(DISTINCT src_ip) AS ips,
                  count(DISTINCT country_code) AS countries, min(ts) AS first_seen, max(ts) AS last_seen
           FROM events, unnest(cves) c WHERE ts > $1 AND cardinality(cves) > 0 GROUP BY c ORDER BY hits DESC LIMIT $2""",
        start, limit,
    )
    ids = [r["cve"] for r in top]
    info = {r["cve_id"]: dict(r) for r in await pool.fetch(
        """SELECT cve_id, name, description, vendor, product, cvss, kev, kev_date_added, kev_ransomware,
                  epss, epss_percentile FROM cve_info WHERE cve_id = ANY($1)""", ids)}
    spark_rows = await pool.fetch(
        """SELECT c AS cve, time_bucket($2::interval, ts) AS bucket, count(*) AS n
           FROM events, unnest(cves) c WHERE ts > $1 AND cardinality(cves) > 0 AND c = ANY($3) GROUP BY c, bucket""",
        start, bucket, ids,
    )
    sparks: dict[str, list] = {}
    for r in spark_rows:
        sparks.setdefault(r["cve"], []).append(r)
    samples = {r["cve"]: r for r in await pool.fetch(
        """SELECT DISTINCT ON (c) c AS cve, http_method, http_path, http_body, command, host(src_ip) AS src_ip
           FROM events, unnest(cves) c WHERE ts > $1 AND cardinality(cves) > 0 AND c = ANY($2) ORDER BY c, ts DESC""",
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
@cached
async def tags(request: Request, window: str = WindowParam):
    names = {r.tag: r.name for r in request.app.state.rules.sig_rules if r.tag}
    src, start = source(TAGS, window)
    res = await request.app.state.pool.fetch(
        f"""SELECT t AS tag, {total("n", "hits")}, count(DISTINCT src_ip) AS ips
            FROM {src} r, unnest(tags) t WHERE bucket >= $1 GROUP BY t ORDER BY hits DESC""", start)
    return {"window": window, "tags": [{**dict(r), "name": names.get(r["tag"])} for r in res]}


@api.get("/stats/geo")
@cached
async def geo(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    ips, start = source(IPS, window)
    ports, _ = source(PORTS, window)
    countries = await pool.fetch(
        f"""SELECT country_code, max(country) AS country, {total("events")}, count(DISTINCT src_ip) AS ips,
                   {total("exploits")}
            FROM {ips} r WHERE bucket >= $1 AND country_code IS NOT NULL
            GROUP BY country_code ORDER BY ips DESC""", start)
    asns = await pool.fetch(
        f"""SELECT asn, max(as_org) AS as_org, {total("events")}, count(DISTINCT src_ip) AS ips
            FROM {ips} r WHERE bucket >= $1 AND asn IS NOT NULL GROUP BY asn ORDER BY ips DESC LIMIT 25""", start)
    ports = await pool.fetch(
        f"""SELECT dst_port, proto, {total("n", "events")}, count(DISTINCT src_ip) AS ips
            FROM {ports} r WHERE bucket >= $1 AND dst_port IS NOT NULL
            GROUP BY 1, 2 ORDER BY events DESC LIMIT 25""", start)
    return {"window": window, "countries": rows(countries), "asns": rows(asns), "ports": rows(ports)}


@api.get("/stats/creds")
@cached
async def creds(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    src, start = source(CREDS, window)
    base = f"FROM {src} r WHERE bucket >= $1"
    n = total("n")
    usernames = await pool.fetch(f"SELECT username AS value, {n} {base} AND username IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 25", start)
    passwords = await pool.fetch(f"SELECT password AS value, {n} {base} AND password IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 25", start)
    pairs = await pool.fetch(f"SELECT username, password, {n} {base} GROUP BY 1, 2 ORDER BY n DESC LIMIT 25", start)
    lengths = await pool.fetch(f"SELECT least(length(password), 20) AS len, {n} {base} AND password IS NOT NULL GROUP BY 1 ORDER BY 1", start)
    totals = await pool.fetchrow(
        f"""SELECT {total("n", "attempts")}, {total("successes")},
                   count(DISTINCT username) AS unique_usernames, count(DISTINCT password) AS unique_passwords,
                   count(DISTINCT src_ip) AS ips {base}""", start)
    return {"window": window, "totals": dict(totals), "usernames": rows(usernames), "passwords": rows(passwords),
            "pairs": rows(pairs), "lengths": rows(lengths)}


@api.get("/stats/techniques")
@cached
async def techniques(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    meta = request.app.state.rules.techniques
    src, start = source(TECHNIQUES, window)
    res = await pool.fetch(
        f"""SELECT t AS technique, {total("n", "hits")}, count(DISTINCT src_ip) AS ips
            FROM {src} r, unnest(techniques) t WHERE bucket >= $1 GROUP BY t ORDER BY hits DESC""", start)
    src, start = source(COMMANDS, window)
    commands = await pool.fetch(
        f"""SELECT command, {total("n")}, count(DISTINCT src_ip) AS ips FROM {src} r
            WHERE bucket >= $1 GROUP BY command ORDER BY n DESC LIMIT 30""", start)
    seen = {r["technique"]: dict(r) for r in res}
    catalog = [
        {"technique": t.id, "name": t.name, "tactic": t.tactic,
         "hits": seen.get(t.id, {}).get("hits", 0), "ips": seen.get(t.id, {}).get("ips", 0)}
        for t in meta.values()
    ]
    return {"window": window, "techniques": catalog,
            "commands": [{**dict(r), "command": defang(r["command"])} for r in commands]}


@api.get("/stats/http")
@cached
async def http_stats(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    src, start = source(HTTP, window)
    paths = await pool.fetch(
        f"""SELECT method, path, {total("n")}, count(DISTINCT src_ip) AS ips
            FROM {src} r WHERE bucket >= $1 GROUP BY 1, 2 ORDER BY n DESC LIMIT 30""", start)
    uas = await pool.fetch(
        f"""SELECT ua, {total("n")}, count(DISTINCT src_ip) AS ips
            FROM {src} r WHERE bucket >= $1 GROUP BY 1 ORDER BY n DESC LIMIT 20""", start)
    return {"window": window, "paths": [{**dict(r), "path": defang(r["path"])} for r in paths], "user_agents": rows(uas)}


@api.get("/stats/malware")
async def malware(request: Request):
    res = await request.app.state.pool.fetch(
        """SELECT sha256, first_seen, last_seen, hits, source_url, cardinality(src_ips) AS ips,
                  family, file_type, intel_tags FROM malware ORDER BY last_seen DESC LIMIT 100""")
    return {"malware": [{**dict(r), "source_url": defang(r["source_url"])} for r in res]}


# ---------------------------------------------------------------- session triage

VERDICT_COLS = """session_id, sensor_id, host(src_ip) AS src_ip, started_at, ended_at, actor, intent, severity,
                  escalate, confidence, source, model"""


@api.get("/stats/triage")
async def triage_stats(request: Request, window: str = WindowParam):
    pool = request.app.state.pool
    start, bucket = await series_range(pool, window)
    totals = await pool.fetchrow(
        """SELECT count(*) AS sessions, count(*) FILTER (WHERE escalate) AS escalated,
                  count(*) FILTER (WHERE source = 'jev') AS jev, count(*) FILTER (WHERE source = 'cache') AS cached,
                  count(*) FILTER (WHERE source = 'rules') AS rules, coalesce(sum(tokens), 0) AS tokens
           FROM session_verdicts WHERE ended_at > $1""", start)

    async def counts(col: str):
        return rows(await pool.fetch(
            f"SELECT {col} AS label, count(*) AS n FROM session_verdicts WHERE ended_at > $1 GROUP BY 1 ORDER BY n DESC",
            start))

    series = await pool.fetch(
        """SELECT time_bucket($2::interval, ended_at) AS bucket,
                  count(*) FILTER (WHERE severity = 'low') AS low,
                  count(*) FILTER (WHERE severity = 'medium') AS medium,
                  count(*) FILTER (WHERE severity = 'high') AS high,
                  count(*) FILTER (WHERE severity = 'critical') AS critical
           FROM session_verdicts WHERE ended_at > $1 GROUP BY bucket ORDER BY bucket""", start, bucket)
    return {
        "window": window, "totals": dict(totals),
        "actors": await counts("actor"), "intents": await counts("intent"), "severities": await counts("severity"),
        "timeline": fill_series(series, bucket, start, ("low", "medium", "high", "critical")),
    }


@api.get("/triage/queue")
async def triage_queue(request: Request, window: str = WindowParam, limit: int = Query(50, le=200),
                       all_sessions: bool = Query(False, alias="all")):
    """Distinct behaviours worth a human's time (escalated or high/critical), newest first.

    Botnets replay one script thousands of times, so sessions are grouped by fingerprint: one row per
    behaviour with its latest session, how many sessions and source IPs showed it.
    """
    res = await request.app.state.pool.fetch(
        f"""WITH v AS (SELECT * FROM session_verdicts
                       WHERE ended_at > $1 AND ($3 OR escalate OR severity IN ('high', 'critical'))),
                 g AS (SELECT fingerprint, count(*) AS sessions, count(DISTINCT src_ip) AS ips FROM v GROUP BY 1),
                 latest AS (SELECT DISTINCT ON (fingerprint) {VERDICT_COLS}, fingerprint FROM v
                            ORDER BY fingerprint, ended_at DESC)
            SELECT latest.*, g.sessions, g.ips FROM latest JOIN g USING (fingerprint)
            ORDER BY ended_at DESC LIMIT $2""", since(window), limit, all_sessions)
    return {"window": window, "sessions": rows(res)}


# ---------------------------------------------------------------- attackers / sessions / live

@api.get("/attackers/top")
@cached
async def top_attackers(request: Request, window: str = WindowParam, limit: int = Query(50, le=200)):
    src, start = source(IPS, window)
    res = await request.app.state.pool.fetch(
        f"""SELECT host(src_ip) AS ip, max(country_code) AS country_code, max(country) AS country,
                   max(as_org) AS as_org, {total("events")}, {total("logins")}, {total("commands")},
                   {total("exploits")}, array_agg(DISTINCT honeypot) AS honeypots,
                   min(first_seen) AS first_seen, max(last_seen) AS last_seen
            FROM {src} r WHERE bucket >= $1 GROUP BY src_ip ORDER BY events DESC LIMIT $2""",
        start, limit)
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
    verdicts = await pool.fetch(
        f"SELECT {VERDICT_COLS} FROM session_verdicts WHERE src_ip = $1::inet ORDER BY ended_at DESC LIMIT 50", ip)
    recent = await pool.fetch(
        """SELECT ts, honeypot, event_type, dst_port, username, password, command, http_method, http_path,
                  cves, techniques, tags FROM events WHERE src_ip = $1::inet ORDER BY ts DESC LIMIT 200""", ip)
    return {
        "ip": ip, "summary": dict(summary),
        "cves": [r["cve"] for r in cve_list], "techniques": [r["t"] for r in tech_list],
        "intel": dict(intel_row) if intel_row else None,
        "sessions": rows(sessions),
        "verdicts": rows(verdicts),
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
    verdict = await request.app.state.pool.fetchrow(
        f"SELECT {VERDICT_COLS} FROM session_verdicts WHERE session_id = $1", session_id[:64])
    return {"session_id": session_id, "verdict": dict(verdict) if verdict else None, "events": [
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
