"""Low-interaction HTTP(S) honeypot.

Answers on many ports, impersonates commonly exploited products (VPN gateways,
routers, CMSes, Java apps) closely enough that scanners send their second-stage
payloads, and logs every request as one JSON line for the shipper. It never
executes or fetches anything an attacker sends.
"""
import asyncio
import base64
import datetime as dt
import hashlib
import json
import logging
import logging.handlers
import os
import re
import ssl
from pathlib import Path
from urllib.parse import parse_qs

from aiohttp import web

import tcp_services
from personas import ROUTES, default_page
from service_personas import PORT_PERSONAS

LOG_FILE = Path(os.environ.get("LOG_FILE", "/logs/http.json"))
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
HTTP_PORTS = [int(p) for p in os.environ.get("HTTP_PORTS", "8080").split(",") if p]
HTTPS_PORTS = [int(p) for p in os.environ.get("HTTPS_PORTS", "8443").split(",") if p]
# "2375:docker,9200:elasticsearch": ports whose every request goes to one product persona
SERVICE_PORTS = {int(p): name for p, _, name in
                 (x.partition(":") for x in os.environ.get("SERVICE_PORTS", "").split(",") if x)}
REDIS_PORTS = [int(p) for p in os.environ.get("REDIS_PORTS", "").split(",") if p]
ADB_PORTS = [int(p) for p in os.environ.get("ADB_PORTS", "").split(",") if p]
SERVER_HEADER = os.environ.get("SERVER_HEADER", "Apache/2.4.49 (Unix) OpenSSL/1.0.2k-fips PHP/7.4.33")
MAX_BODY = 64 * 1024
LOG_BODY = 8 * 1024

USER_KEYS = re.compile(r"^(user(name)?|login|log|email|uname|usr|account|admin_?user)$", re.I)
PASS_KEYS = re.compile(r"^(pass(word|wd)?|pwd|pw|passwd|admin_?pass(word)?|secret)$", re.I)

events = logging.getLogger("events")


def setup_logging():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=50 * 2**20, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    events.addHandler(handler)
    events.setLevel(logging.INFO)
    events.propagate = False
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def extract_creds(request: web.Request, body: bytes) -> dict | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace").partition(":")
            return {"username": user, "password": pw, "source": "basic-auth"}
        except ValueError:
            pass
    if not body:
        return None
    text = body[:LOG_BODY].decode("utf-8", "replace")
    fields: dict[str, str] = {}
    ctype = request.headers.get("Content-Type", "")
    if "json" in ctype or text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                fields = {k: str(v) for k, v in obj.items() if isinstance(v, (str, int))}
        except ValueError:
            pass
    else:
        fields = {k: v[0] for k, v in parse_qs(text, keep_blank_values=True).items()}
    user = next((v for k, v in fields.items() if USER_KEYS.match(k)), None)
    pw = next((v for k, v in fields.items() if PASS_KEYS.match(k)), None)
    if user is None and pw is None:
        return None
    return {"username": user, "password": pw, "source": "form"}


async def handle(request: web.Request) -> web.StreamResponse:
    body = await request.content.read(MAX_BODY)
    peer = request.transport.get_extra_info("peername") if request.transport else None
    sock = request.transport.get_extra_info("sockname") if request.transport else None
    path = request.raw_path

    persona, resp = "default", None
    port_persona = request["persona"] = SERVICE_PORTS.get(sock[1]) if sock else None
    if port_persona:
        persona, resp = port_persona, PORT_PERSONAS[port_persona](request, body)
    else:
        for pattern, name, responder in ROUTES:
            if pattern.search(path):
                persona, resp = name, responder(request, body)
                break
        if resp is None:
            resp = default_page(request, body)
        resp.headers.setdefault("Server", SERVER_HEADER)

    record = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
        "src_ip": peer[0] if peer else None,
        "src_port": peer[1] if peer else None,
        "dst_port": sock[1] if sock else None,
        "tls": request.secure,
        "method": request.method,
        "path": path,
        "version": f"{request.version.major}.{request.version.minor}",
        "headers": {k: v[:4096] for k, v in request.headers.items()},
        "body": body[:LOG_BODY].decode("utf-8", "backslashreplace") if body else "",
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "persona": persona,
        "status": resp.status,
    }
    creds = extract_creds(request, body)
    if creds:
        record["creds"] = creds
    events.info(json.dumps(record, ensure_ascii=False))
    return resp


def tls_context() -> ssl.SSLContext:
    cert, key = DATA_DIR / "cert.pem", DATA_DIR / "key.pem"
    if not cert.exists():
        make_self_signed(cert, key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # old clients and bots too
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.load_cert_chain(cert, key)
    return ctx


def make_self_signed(cert_path: Path, key_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fortinet"),
        x509.NameAttribute(NameOID.COMMON_NAME, os.environ.get("TLS_CN", "FGT60FTK2109XXXX")),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=400)).not_valid_after(now + dt.timedelta(days=3250))
            .sign(key, hashes.SHA256()))
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


async def strip_server_header(request: web.Request, response: web.StreamResponse):
    """Elasticsearch sends no Server header; without this aiohttp would announce itself.
    (on_response_prepare runs after aiohttp adds its default header, before it is written.)"""
    if request.get("persona") == "elasticsearch":
        response.headers.popall("Server", None)


async def main():
    setup_logging()
    app = web.Application(client_max_size=MAX_BODY * 2)
    app.on_response_prepare.append(strip_server_header)
    app.router.add_route("*", "/{tail:.*}", handle)
    runner = web.AppRunner(app, access_log=None, handle_signals=True)
    await runner.setup()
    for port in [*HTTP_PORTS, *SERVICE_PORTS]:
        await web.TCPSite(runner, "0.0.0.0", port).start()
    if HTTPS_PORTS:
        ctx = tls_context()
        for port in HTTPS_PORTS:
            await web.TCPSite(runner, "0.0.0.0", port, ssl_context=ctx).start()
    await tcp_services.start(lambda rec: events.info(json.dumps(rec, ensure_ascii=False)), REDIS_PORTS, ADB_PORTS)
    logging.info("listening http=%s https=%s services=%s redis=%s adb=%s",
                 HTTP_PORTS, HTTPS_PORTS, SERVICE_PORTS, REDIS_PORTS, ADB_PORTS)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
