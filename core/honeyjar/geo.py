"""Offline IP geolocation + ASN lookup from MMDB files.

Uses MaxMind GeoLite2 if present, otherwise the DB-IP Lite databases
(CC BY 4.0, no account needed) downloaded by `feeds.py geoip`.
"""
import ipaddress
import logging
import time
from functools import lru_cache
from pathlib import Path

import geoip2.database
import geoip2.errors

log = logging.getLogger(__name__)

CITY_FILES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
ASN_FILES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")


def _find(directory: Path, names: tuple[str, ...]) -> Path | None:
    return next((directory / n for n in names if (directory / n).exists()), None)


class GeoLookup:
    """Reopens the databases when the feed job replaces them (checked once a minute)."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.city = self.asn = None
        self._stamp: tuple = ()
        self._checked = 0.0
        self._cached = lru_cache(maxsize=50_000)(self._lookup)
        self._reload()
        if not self.city:
            log.warning("geoip: no city database in %s yet; waiting for `feeds geoip`", directory)

    def _reload(self):
        paths = (_find(self.directory, CITY_FILES), _find(self.directory, ASN_FILES))
        stamp = tuple((str(p), p.stat().st_mtime) if p else None for p in paths)
        if stamp == self._stamp:
            return
        self._stamp = stamp
        self.city, self.asn = (geoip2.database.Reader(str(p)) if p else None for p in paths)
        self._cached.cache_clear()
        log.info("geoip: loaded city=%s asn=%s", paths[0], paths[1])

    def lookup(self, ip: str) -> dict:
        now = time.monotonic()
        if now - self._checked > 60:
            self._checked = now
            self._reload()
        return self._cached(ip)

    def _lookup(self, ip: str) -> dict:
        out: dict = {}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        if not addr.is_global:
            return out
        if self.city:
            try:
                r = self.city.city(ip)
                out.update(
                    country_code=r.country.iso_code,
                    country=r.country.name,
                    city=r.city.name,
                    lat=r.location.latitude,
                    lon=r.location.longitude,
                )
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        if self.asn:
            try:
                a = self.asn.asn(ip)
                out.update(asn=a.autonomous_system_number, as_org=a.autonomous_system_organization)
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        return out
