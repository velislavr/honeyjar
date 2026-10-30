"""Turn raw honeypot log records into common `Event`s."""
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from .schemas import Event

MAX_TEXT = 4096

COWRIE_TYPES = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_attempt",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "download",
    "cowrie.client.version": "client_info",
    "cowrie.client.kex": "client_info",
    "cowrie.session.closed": "session_closed",
}


def _ts(value) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clip(value, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    s = str(value).replace("\x00", "\\x00")
    return s[:limit]


def normalize(raw: dict, sensor_id: str) -> Event | None:
    honeypot = raw.get("honeypot")
    if honeypot == "cowrie":
        return _cowrie(raw, sensor_id)
    if honeypot == "http":
        # The HTTP honeypot container also runs the raw-TCP services (Redis, ADB) and logs to the same file.
        return _tcp(raw, sensor_id) if raw.get("service") in TCP_SERVICES else _http(raw, sensor_id)
    return None


TCP_SERVICES = {"redis", "adb"}
TCP_EVENTS = {"connect": "connect", "command": "command", "login": "login_attempt", "download": "download"}


def _tcp(raw: dict, sensor_id: str) -> Event | None:
    event_type = TCP_EVENTS.get(raw.get("event", ""))
    if event_type is None or not raw.get("src_ip"):
        return None
    ev = Event(
        ts=_ts(raw.get("ts")),
        sensor_id=sensor_id,
        honeypot=raw["service"],
        event_type=event_type,
        src_ip=raw["src_ip"],
        proto=raw["service"],
        src_port=_int(raw.get("src_port")),
        dst_port=_int(raw.get("dst_port")),
        session_id=_clip(raw.get("session"), 64),
        command=_clip(raw.get("command")),
    )
    if event_type == "login_attempt":
        ev.username = _clip(raw.get("username"), 256)
        ev.password = _clip(raw.get("password"), 256)
        ev.login_success = bool(raw.get("success"))
    elif event_type == "download":
        ev.payload_hash = raw.get("sha256")
        ev.extra = {k: raw[k] for k in ("path", "size") if raw.get(k) is not None}
    return ev


DOCKER_API = re.compile(r"^(?:/v[\d.]+)?/(containers/create|containers/[^/]+/exec|images/create)")


def docker_command(method: str | None, path: str | None, body: str | None) -> str | None:
    """Rewrite a Docker Engine API call as the equivalent CLI command, so shell rules apply to it."""
    m = DOCKER_API.match(path or "")
    if method != "POST" or not m:
        return None
    if m.group(1) == "images/create":
        q = parse_qs(urlsplit(path).query)
        image = q.get("fromImage", ["?"])[0]
        tag = q.get("tag", [""])[0]
        return f"docker pull {image}{':' + tag if tag else ''}"
    try:
        spec = json.loads(body or "{}")
    except ValueError:
        return None
    if not isinstance(spec, dict):
        return None

    def words(v) -> str:
        return " ".join(map(str, v)) if isinstance(v, list) else str(v or "")

    cmd = " ".join(filter(None, [words(spec.get("Entrypoint")), words(spec.get("Cmd"))]))
    if m.group(1).endswith("/exec"):
        return f"docker exec {m.group(1).split('/')[1][:12]} {cmd}".strip()
    host = spec.get("HostConfig") or {}
    flags = ["--privileged"] if host.get("Privileged") else []
    flags += [f"--pid={host['PidMode']}"] if host.get("PidMode") else []
    flags += [f"-v {b}" for b in (host.get("Binds") or [])[:6]]
    return " ".join(["docker run", *flags, str(spec.get("Image") or "?"), cmd]).strip()


def _cowrie(raw: dict, sensor_id: str) -> Event | None:
    eventid = raw.get("eventid", "")
    event_type = COWRIE_TYPES.get(eventid)
    if event_type is None or not raw.get("src_ip"):
        return None
    ev = Event(
        ts=_ts(raw.get("timestamp")),
        sensor_id=sensor_id,
        honeypot="cowrie",
        event_type=event_type,
        src_ip=raw["src_ip"],
        proto=raw.get("protocol"),
        src_port=_int(raw.get("src_port")),
        dst_port=_int(raw.get("dst_port")),
        session_id=raw.get("session"),
    )
    if event_type == "login_attempt":
        ev.username = _clip(raw.get("username"), 256)
        ev.password = _clip(raw.get("password"), 256)
        ev.login_success = eventid == "cowrie.login.success"
    elif event_type == "command":
        ev.command = _clip(raw.get("input"))
    elif event_type == "download":
        ev.payload_hash = raw.get("shasum")
        ev.download_url = _clip(raw.get("url"), 1024)
        ev.extra = {k: raw[k] for k in ("filename", "outfile", "destfile") if raw.get(k)}
    elif eventid == "cowrie.client.version":
        ev.extra = {"client_version": _clip(raw.get("version"), 256)}
    elif eventid == "cowrie.client.kex":
        ev.extra = {"hassh": raw.get("hassh")}
    elif event_type == "session_closed":
        ev.extra = {"duration": raw.get("duration")}
    return ev


def _http(raw: dict, sensor_id: str) -> Event | None:
    if not raw.get("src_ip"):
        return None
    headers = {str(k).lower(): str(v) for k, v in (raw.get("headers") or {}).items()}
    creds = raw.get("creds") or {}
    ev = Event(
        ts=_ts(raw.get("ts")),
        sensor_id=sensor_id,
        honeypot="http",
        event_type="http_request",
        src_ip=raw["src_ip"],
        proto="https" if raw.get("tls") else "http",
        src_port=_int(raw.get("src_port")),
        dst_port=_int(raw.get("dst_port")),
        username=_clip(creds.get("username"), 256),
        password=_clip(creds.get("password"), 256),
        http_method=_clip(raw.get("method"), 16),
        http_path=_clip(raw.get("path"), 2048),
        http_ua=_clip(headers.get("user-agent"), 512),
        http_body=_clip(raw.get("body")),
        payload_hash=raw.get("body_sha256"),
        http_headers=headers,
        http_raw_path=raw.get("path"),
    )
    if creds:
        ev.login_success = False
        ev.extra["cred_source"] = creds.get("source")
    if raw.get("persona"):
        ev.extra["persona"] = raw["persona"]
    if raw.get("persona") == "docker":
        ev.command = _clip(docker_command(ev.http_method, ev.http_path, raw.get("body")))
    return ev
