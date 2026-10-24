"""Common event schema every honeypot log line is normalized into."""
from dataclasses import dataclass, field
from datetime import datetime

EVENT_TYPES = (
    "connect", "login_attempt", "command", "http_request", "exploit",
    "download", "client_info", "session_closed",
)

# Event types pushed to the live feed (the rest are only stored).
LIVE_TYPES = {"connect", "login_attempt", "command", "http_request", "exploit", "download"}


@dataclass
class Event:
    ts: datetime
    sensor_id: str
    honeypot: str
    event_type: str
    src_ip: str
    proto: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    session_id: str | None = None
    username: str | None = None
    password: str | None = None
    login_success: bool | None = None
    command: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_ua: str | None = None
    http_body: str | None = None
    payload_hash: str | None = None
    download_url: str | None = None
    # enrichment
    country_code: str | None = None
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: int | None = None
    as_org: str | None = None
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    # match context only, not stored as a column
    http_headers: dict | None = None
    http_raw_path: str | None = None


DB_COLUMNS = (
    "ts", "sensor_id", "honeypot", "proto", "event_type", "src_ip", "src_port", "dst_port",
    "session_id", "username", "password", "login_success", "command",
    "http_method", "http_path", "http_ua", "http_body", "payload_hash", "download_url",
    "country_code", "country", "city", "lat", "lon", "asn", "as_org",
    "cves", "tags", "techniques", "extra",
)
