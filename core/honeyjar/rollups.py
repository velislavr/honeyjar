"""Hourly continuous aggregates behind the stats endpoints.

Scanning raw events stops scaling at ~1M events a day, but the distinct (hour, attacker, value)
combinations stay in the low thousands. Every rollup keeps src_ip as a key so distinct-attacker
counts stay exact, and its counts are sums so any window adds them back up.

Each rollup also has a `raw` form: the same row shape read straight from events (one row per
event), used where hourly buckets are too coarse. Both forms come from one spec so they can't drift.
"""
from typing import NamedTuple

_ATTACK = "event_type IN ('connect', 'http_request', 'exploit')"


class Rollup(NamedTuple):
    view: str
    keys: dict[str, str]    # column -> expression over events
    counts: dict[str, str]  # column -> per-event integer, summed per bucket
    where: str = "TRUE"

    def _cols(self, agg: bool) -> str:
        keys = [f"{e} AS {k}" for k, e in self.keys.items()]
        counts = [f"sum({e}) AS {k}" if agg else f"{e} AS {k}" for k, e in self.counts.items()]
        seen = ["min(ts) AS first_seen", "max(ts) AS last_seen"] if agg else ["ts AS first_seen", "ts AS last_seen"]
        return ", ".join(keys + counts + seen)

    @property
    def raw(self) -> str:
        return f"(SELECT ts AS bucket, {self._cols(False)} FROM events WHERE {self.where})"

    def ddl(self) -> str:
        return f"""
CREATE MATERIALIZED VIEW IF NOT EXISTS {self.view}
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT time_bucket(INTERVAL '1 hour', ts) AS bucket, {self._cols(True)}
FROM events WHERE {self.where}
GROUP BY bucket, {", ".join(self.keys.values())}
WITH NO DATA;
SELECT add_continuous_aggregate_policy('{self.view}',
    start_offset => INTERVAL '3 hours', end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '10 minutes', if_not_exists => TRUE);
"""


IPS = Rollup("ip_1h", {
    "src_ip": "src_ip", "honeypot": "honeypot", "country_code": "country_code", "country": "country",
    "asn": "asn", "as_org": "as_org",
}, {
    "events": "1",
    "attacks": f"({_ATTACK})::int",
    "login_attempts": "(event_type = 'login_attempt' OR username IS NOT NULL)::int",
    "logins": "(event_type = 'login_attempt')::int",
    "login_successes": "coalesce(login_success, false)::int",
    "commands": "(event_type = 'command')::int",
    "exploits": "(cardinality(cves) > 0)::int",
    "downloads": "(event_type = 'download')::int",
})
PORTS = Rollup("port_1h", {"dst_port": "dst_port", "proto": "coalesce(proto, honeypot)", "src_ip": "src_ip"},
               {"n": "1"}, _ATTACK)
CREDS = Rollup("cred_1h", {"username": "username", "password": "password", "src_ip": "src_ip"},
               {"n": "1", "successes": "coalesce(login_success, false)::int"},
               "(event_type = 'login_attempt' OR username IS NOT NULL)")
COMMANDS = Rollup("command_1h", {"command": "command", "src_ip": "src_ip"}, {"n": "1"}, "event_type = 'command'")
TECHNIQUES = Rollup("technique_1h", {"techniques": "techniques", "src_ip": "src_ip"}, {"n": "1"},
                    "cardinality(techniques) > 0")
TAGS = Rollup("tag_1h", {"tags": "tags", "src_ip": "src_ip"}, {"n": "1"}, "cardinality(tags) > 0")
HTTP = Rollup("http_1h", {
    "method": "http_method", "path": "split_part(http_path, '?', 1)", "ua": "http_ua", "src_ip": "src_ip",
}, {"n": "1"}, "honeypot = 'http'")

ALL = (IPS, PORTS, CREDS, COMMANDS, TECHNIQUES, TAGS, HTTP)


def ddl() -> str:
    # events_1m (schema.sql) feeds the timelines; let it fill its last minute from raw rows too.
    return "".join(r.ddl() for r in ALL) + \
        "ALTER MATERIALIZED VIEW events_1m SET (timescaledb.materialized_only = false);\n"
