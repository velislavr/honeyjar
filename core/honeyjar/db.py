import asyncio
import logging
from dataclasses import astuple, fields

import asyncpg
import orjson

from . import config
from .schemas import DB_COLUMNS, Event

log = logging.getLogger(__name__)

_FIELD_INDEX = [f.name for f in fields(Event)]
_COLUMN_POS = [_FIELD_INDEX.index(c) for c in DB_COLUMNS]
_SCHEMA_LOCK = 4242


async def _init_conn(conn: asyncpg.Connection):
    # Binary jsonb (version byte 1 + JSON text) so COPY works too.
    await conn.set_type_codec("jsonb", schema="pg_catalog", format="binary",
                              encoder=lambda v: b"\x01" + orjson.dumps(v),
                              decoder=lambda b: orjson.loads(b[1:]))


async def create_pool(retries: int = 30) -> asyncpg.Pool:
    for attempt in range(retries):
        try:
            pool = await asyncpg.create_pool(config.DATABASE_URL, min_size=1, max_size=10, init=_init_conn)
            await apply_schema(pool)
            return pool
        except (OSError, asyncpg.CannotConnectNowError) as e:
            log.warning("database not ready (%s), retry %d", e, attempt + 1)
            await asyncio.sleep(2)
    raise RuntimeError("database unavailable")


async def apply_schema(pool: asyncpg.Pool):
    sql = config.SCHEMA_FILE.read_text(encoding="utf-8")
    async with pool.acquire() as conn:
        await conn.execute("SELECT pg_advisory_lock($1)", _SCHEMA_LOCK)
        try:
            await conn.execute(sql)
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", _SCHEMA_LOCK)


def event_record(ev: Event) -> tuple:
    t = astuple(ev)
    return tuple(t[i] for i in _COLUMN_POS)


async def insert_events(pool: asyncpg.Pool, events: list[Event]):
    if not events:
        return
    async with pool.acquire() as conn:
        await conn.copy_records_to_table("events", records=[event_record(e) for e in events], columns=DB_COLUMNS)
