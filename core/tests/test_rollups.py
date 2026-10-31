import asyncio
import re

import pytest

from honeyjar import api, rollups


@pytest.mark.parametrize("r", rollups.ALL, ids=lambda r: r.view)
def test_raw_form_has_the_rollup_columns(r):
    # 1h reads `raw`, longer windows read the view: both must expose the same columns
    cols = lambda sql: re.findall(r" AS (\w+)", sql)
    view_cols = cols(r.ddl().split("FROM events")[0])
    assert view_cols == cols(r.raw.split("FROM events")[0])
    assert view_cols[0] == "bucket" and "src_ip" in view_cols


def test_short_windows_read_raw_events_and_long_ones_whole_hours():
    src, start = api.source(rollups.IPS, "1h")
    assert src == rollups.IPS.raw
    src, start = api.source(rollups.IPS, "24h")
    assert src == "ip_1h"
    assert (start.minute, start.second, start.microsecond) == (0, 0, 0)


def test_routes_keep_their_query_params():
    route = next(r for r in api.app.routes if getattr(r, "path", "") == "/api/attackers/top")
    assert {p.name for p in route.dependant.query_params} == {"window", "limit"}


def test_cache_shares_concurrent_misses_and_drops_failures():
    calls = []

    @api.cached
    async def handler(request, window="24h"):
        calls.append(window)
        await asyncio.sleep(0.01)
        if window == "7d":
            raise RuntimeError("db down")
        return {"window": window}

    async def run():
        api._cache.clear()
        a, b = await asyncio.gather(handler(None, window="24h"), handler(None, window="24h"))
        assert a == b == {"window": "24h"}
        for _ in range(2):
            with pytest.raises(RuntimeError):
                await handler(None, window="7d")

    asyncio.run(run())
    assert calls == ["24h", "7d", "7d"]
