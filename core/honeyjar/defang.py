"""Defang URLs/IPs in attacker-supplied text before it is shown publicly."""
import re

_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.I)
_FTP = re.compile(r"\bftp://", re.I)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def defang(text: str | None) -> str | None:
    if not text:
        return text
    text = _SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)}://", text)
    text = _FTP.sub("fxp://", text)
    return _IPV4.sub(r"\1[.]\2[.]\3[.]\4", text)
