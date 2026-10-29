"""Render cloud-init user-data for an Oracle Cloud core + Azure / Oracle sensors.

Generates every secret once (WireGuard keys, sensor ingest tokens, database password), keeps them
in infra/out/state.json (gitignored), and writes one paste-ready user-data file per machine.

    pip install cryptography
    # 1. core first (its public IP is only known after Oracle creates it)
    python infra/render.py --domain honeyjar.tech --repo https://github.com/<you>/honeyjar \\
        --ssh-key ~/.ssh/id_ed25519.pub \\
        --sensor us1=eastus --sensor sg1=southeastasia [--sensor fra1=eu-frankfurt-1]
    # 2. sensors, once the core has a public IP
    python infra/render.py ... --core-ip <oracle-public-ip>

Re-running is safe: existing keys and tokens are reused; new --sensor names get new ones.
"""
import argparse
import base64
import json
import secrets
import textwrap
from pathlib import Path
from string import Template

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
STATE = OUT / "state.json"

# Cloud region -> (label, lat, lon) for the attack map: Azure region names and Oracle region ids.
REGIONS = {
    # Azure
    "eastus": ("Virginia", 37.37, -79.82), "eastus2": ("Virginia", 36.67, -78.39),
    "centralus": ("Iowa", 41.59, -93.60), "westus2": ("Washington", 47.23, -119.85),
    "westus3": ("Arizona", 33.45, -112.07), "canadacentral": ("Toronto", 43.65, -79.38),
    "brazilsouth": ("São Paulo", -23.55, -46.63), "northeurope": ("Ireland", 53.35, -6.26),
    "westeurope": ("Netherlands", 52.37, 4.90), "uksouth": ("London", 51.51, -0.13),
    "francecentral": ("Paris", 48.86, 2.35), "germanywestcentral": ("Frankfurt", 50.11, 8.68),
    "swedencentral": ("Gävle", 60.67, 17.14), "polandcentral": ("Warsaw", 52.23, 21.01),
    "uaenorth": ("Dubai", 25.20, 55.27), "southafricanorth": ("Johannesburg", -26.20, 28.05),
    "centralindia": ("Pune", 18.52, 73.86), "southeastasia": ("Singapore", 1.35, 103.82),
    "eastasia": ("Hong Kong", 22.32, 114.17), "japaneast": ("Tokyo", 35.68, 139.69),
    "koreacentral": ("Seoul", 37.57, 126.98), "australiaeast": ("Sydney", -33.87, 151.21),
    # Oracle Cloud (for an Always Free AMD micro sensor in your home region)
    "us-ashburn-1": ("Ashburn", 39.04, -77.49), "us-phoenix-1": ("Phoenix", 33.45, -112.07),
    "us-sanjose-1": ("San Jose", 37.34, -121.89), "ca-toronto-1": ("Toronto", 43.65, -79.38),
    "sa-saopaulo-1": ("São Paulo", -23.55, -46.63), "uk-london-1": ("London", 51.51, -0.13),
    "eu-frankfurt-1": ("Frankfurt", 50.11, 8.68), "eu-amsterdam-1": ("Amsterdam", 52.37, 4.90),
    "eu-marseille-1": ("Marseille", 43.30, 5.37), "eu-stockholm-1": ("Stockholm", 59.33, 18.07),
    "me-dubai-1": ("Dubai", 25.20, 55.27), "ap-mumbai-1": ("Mumbai", 19.08, 72.88),
    "ap-singapore-1": ("Singapore", 1.35, 103.82), "ap-tokyo-1": ("Tokyo", 35.68, 139.69),
    "ap-seoul-1": ("Seoul", 37.57, 126.98), "ap-sydney-1": ("Sydney", -33.87, 151.21),
}
# Plausible hostnames so each sensor's fake shell looks like a different neglected server.
HOSTNAMES = ["web-prod-02", "srv-backup01", "db-replica-3", "build-agent-7", "nas-office", "gitlab-runner-2"]


def wg_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def block(text: str, indent: int = 6) -> str:
    """Indent a multi-line file so it nests under a cloud-init `content: |` key."""
    return textwrap.indent(text.strip("\n"), " " * indent)


def load_state() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text())
    priv, pub = wg_keypair()
    return {"postgres_password": secrets.token_urlsafe(24), "core": {"wg_private": priv, "wg_public": pub}, "sensors": {}}


def ensure_sensor(state: dict, spec: str) -> dict:
    name, _, region = spec.partition("=")
    sensors = state["sensors"]
    if name not in sensors:
        if region not in REGIONS:
            raise SystemExit(f"--sensor {spec}: use NAME=REGION with a known region, one of:\n  {', '.join(REGIONS)}")
        label, lat, lon = REGIONS[region]
        priv, pub = wg_keypair()
        used = {s["wg_ip"] for s in sensors.values()}
        wg_ip = next(f"10.66.0.{n}" for n in range(11, 250) if f"10.66.0.{n}" not in used)
        sensors[name] = {
            "wg_private": priv, "wg_public": pub, "wg_ip": wg_ip, "token": secrets.token_hex(32),
            "region": region, "label": label, "lat": lat, "lon": lon,
            "hostname": HOSTNAMES[len(sensors) % len(HOSTNAMES)],
        }
    return sensors[name]


def render(template: str, **values) -> str:
    return Template((HERE / "templates" / template).read_text()).substitute(**values)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", required=True, help="public hostname for the dashboard, e.g. honeyjar.tech")
    ap.add_argument("--repo", required=True, help="git URL the machines clone (a public repo is simplest)")
    ap.add_argument("--ssh-key", required=True, help="path to your SSH public key")
    ap.add_argument("--sensor", action="append", default=[], metavar="NAME=REGION",
                    help="a sensor and its cloud region, e.g. us1=eastus (Azure) or fra1=eu-frankfurt-1 (Oracle)")
    ap.add_argument("--core-ip", help="the core's public IP; required to render sensors")
    ap.add_argument("--no-sample-download", action="store_true", help="block Cowrie from fetching malware samples")
    a = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    (OUT / ".gitignore").write_text("*\n")  # belt and braces: nothing in out/ is ever committed
    state = load_state()
    for spec in a.sensor:
        ensure_sensor(state, spec)
    STATE.write_text(json.dumps(state, indent=2))
    ssh_key = Path(a.ssh_key).expanduser().read_text().strip()
    core = state["core"]

    peers = "\n".join(
        f"\n[Peer]\n# sensor {n}\nPublicKey = {s['wg_public']}\nAllowedIPs = {s['wg_ip']}/32"
        for n, s in state["sensors"].items()
    )
    core_wg = f"[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\nPrivateKey = {core['wg_private']}\n{peers}"
    sensors_json = json.dumps(
        {n: {"token": s["token"], "label": s["label"], "lat": s["lat"], "lon": s["lon"]} for n, s in state["sensors"].items()},
        separators=(",", ":"),
    )
    core_env = "\n".join([
        f"POSTGRES_PASSWORD={state['postgres_password']}",
        f"SENSORS={sensors_json}",
        f"DOMAIN={a.domain}",
        f"CORS_ORIGINS=https://{a.domain}",
        "API_BIND=10.66.0.1:8000",
        "DASHBOARD_BIND=127.0.0.1:3001",
        "TRUST_PROXY=1",
        "ABUSEIPDB_KEY=",
        "MALWAREBAZAAR_KEY=",
    ])
    (OUT / "core-user-data.yaml").write_text(render(
        "core.yaml", ssh_key=ssh_key, wg_conf=block(core_wg), core_env=block(core_env), repo_url=a.repo))
    written = ["core-user-data.yaml"]

    if a.core_ip:
        for name, s in state["sensors"].items():
            wg = (f"[Interface]\nAddress = {s['wg_ip']}/32\nPrivateKey = {s['wg_private']}\n\n"
                  f"[Peer]\nPublicKey = {core['wg_public']}\nEndpoint = {a.core_ip}:51820\n"
                  f"AllowedIPs = 10.66.0.1/32\nPersistentKeepalive = 25")
            env = "\n".join([
                "CORE_URL=http://10.66.0.1:8000", f"SENSOR_TOKEN={s['token']}",
                "SSH_PORT=22", "TELNET_PORT=23", "HTTP_PORT=80", "HTTPS_PORT=443",
                "ALT_HTTP_PORTS_BIND=0.0.0.0:", f"COWRIE_HOSTNAME={s['hostname']}",
            ])
            (OUT / f"sensor-{name}-user-data.yaml").write_text(render(
                "sensor.yaml", sensor_id=name, sensor_label=s["label"], ssh_key=ssh_key, wg_conf=block(wg),
                sensor_env=block(env), repo_url=a.repo, allow_sample_download="0" if a.no_sample_download else "1"))
            written.append(f"sensor-{name}-user-data.yaml")
    elif state["sensors"]:
        print("note: pass --core-ip <oracle public ip> to also render the sensors")

    print("wrote", ", ".join(f"infra/out/{w}" for w in written))
    print("sensors in core config:", ", ".join(f"{n} ({s['label']})" for n, s in state["sensors"].items()) or "none")


if __name__ == "__main__":
    main()
