"""Signature engine: tags events with CVEs, recon tags and MITRE ATT&CK techniques.

CVE/tag rules (rules/cve/*.yaml) match regexes against request fields; every
field listed in a rule's `match` must hit. Fields:
  method, path (URL-decoded), raw_path, headers ("name: value" lines),
  ua, body, command, username, password, any (all of the above joined).

ATT&CK rules (rules/attack/*.yaml) match a regex against shell commands (`command`),
match request fields like a CVE rule (`match`), or fire on an event condition
(`event: login_failed | login_success`). An id may appear in several files; its
patterns are combined.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus

import yaml

from .schemas import Event

FIELDS = {"method", "path", "raw_path", "headers", "ua", "body", "command", "username", "password", "any"}


@dataclass
class SigRule:
    id: str
    cve: str | None
    tag: str | None
    name: str
    cvss: float | None
    match: dict[str, re.Pattern]


@dataclass
class Technique:
    id: str
    name: str
    tactic: str
    commands: list[re.Pattern]
    matches: list[dict[str, re.Pattern]]
    event: str | None


def _decode(s: str, rounds: int = 2) -> str:
    for _ in range(rounds):
        s = unquote_plus(s)
    return s


class RuleEngine:
    def __init__(self, rules_dir: Path):
        self.sig_rules: list[SigRule] = []
        self.techniques: dict[str, Technique] = {}
        for f in sorted((rules_dir / "cve").glob("*.yaml")):
            for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
                unknown = set(r["match"]) - FIELDS
                if unknown:
                    raise ValueError(f"{f.name}:{r['id']}: unknown match fields {unknown}")
                if not (r.get("cve") or r.get("tag")):
                    raise ValueError(f"{f.name}:{r['id']}: needs cve or tag")
                self.sig_rules.append(SigRule(
                    id=r["id"], cve=r.get("cve"), tag=r.get("tag"), name=r["name"], cvss=r.get("cvss"),
                    match={k: re.compile(v, re.I | re.S) for k, v in r["match"].items()},
                ))
        for f in sorted((rules_dir / "attack").glob("*.yaml")):
            for t in yaml.safe_load(f.read_text(encoding="utf-8"))["techniques"]:
                tech = self.techniques.setdefault(t["id"], Technique(
                    id=t["id"], name=t["name"], tactic=t["tactic"], commands=[], matches=[], event=None))
                if t.get("command"):
                    tech.commands.append(re.compile(t["command"], re.I))
                if t.get("match"):
                    unknown = set(t["match"]) - FIELDS
                    if unknown:
                        raise ValueError(f"{f.name}:{t['id']}: unknown match fields {unknown}")
                    tech.matches.append({k: re.compile(v, re.I | re.S) for k, v in t["match"].items()})
                tech.event = tech.event or t.get("event")

    @property
    def cve_catalog(self) -> dict[str, dict]:
        """CVE id -> curated name/cvss from the rule files."""
        out = {}
        for r in self.sig_rules:
            if r.cve and r.cve not in out:
                out[r.cve] = {"name": r.name, "cvss": r.cvss}
        return out

    def fields_for(self, ev: Event) -> dict[str, str]:
        f = {
            "method": ev.http_method or "",
            "raw_path": ev.http_raw_path or ev.http_path or "",
            "headers": "\n".join(f"{k}: {v}" for k, v in (ev.http_headers or {}).items()),
            "ua": ev.http_ua or "",
            "command": ev.command or "",
            "username": ev.username or "",
            "password": ev.password or "",
        }
        f["path"] = _decode(f["raw_path"])
        body = ev.http_body or ""
        f["body"] = body + "\n" + _decode(body) if "%" in body or "+" in body else body
        f["any"] = "\n".join(v for v in f.values() if v)
        return f

    def match_signatures(self, ev: Event) -> tuple[list[str], list[str]]:
        fields = self.fields_for(ev)
        cves: list[str] = []
        tags: list[str] = []
        for r in self.sig_rules:
            if all(fields.get(k) and p.search(fields[k]) for k, p in r.match.items()):
                if r.cve and r.cve not in cves:
                    cves.append(r.cve)
                if r.tag and r.tag not in tags:
                    tags.append(r.tag)
        return cves, tags

    def map_techniques(self, ev: Event) -> list[str]:
        out = []
        fields = None
        for t in self.techniques.values():
            hit = bool(ev.command) and any(p.search(ev.command) for p in t.commands)
            if not hit and t.matches:
                fields = fields or self.fields_for(ev)
                hit = any(all(fields.get(k) and p.search(fields[k]) for k, p in m.items()) for m in t.matches)
            if not hit and t.event:
                hit = (t.event == "login_failed" and ev.login_success is False) or                       (t.event == "login_success" and ev.login_success is True)
            if hit:
                out.append(t.id)
        return out

    def apply(self, ev: Event) -> Event:
        ev.cves, ev.tags = self.match_signatures(ev)
        ev.techniques = self.map_techniques(ev)
        if ev.cves and ev.event_type == "http_request":
            ev.event_type = "exploit"
        return ev
