"""Rewrite Cowrie's stock fake filesystem (fs.pickle) so it stops looking like Cowrie.

The stock image is a famous fingerprint: Debian 12, hostname svr04, a user called
`phil`, a 2-core Xeon E5-2680. Scanners check exactly these. This turns it into a
busy Ubuntu 22.04 application server with 8 EPYC cores and 16 GB (attractive to
miners), real-looking users, and breadcrumbs that keep an intruder exploring.

Run at image build time:
    python mkfs.py <stock fs.pickle> <output fs.pickle> <stock txtcmds dir> <output txtcmds dir>
Node layout (cowrie.shell.fs): [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
"""
import hashlib
import pickle
import shutil
import sys
import time

T_LINK, T_DIR, T_FILE = 0, 1, 2
NOW = int(time.time())
DAY = 86400


def walk(root, path):
    node = root
    for part in [p for p in path.split("/") if p]:
        node = next((c for c in node[7] if c[0] == part), None)
        if node is None:
            return None
    return node


def mkdir(root, path, uid=0, gid=0, mode=0o40755, age=400):
    node = root
    for part in [p for p in path.split("/") if p]:
        nxt = next((c for c in node[7] if c[0] == part), None)
        if nxt is None:
            nxt = [part, T_DIR, uid, gid, 4096, mode, NOW - age * DAY, [], None, None]
            node[7].append(nxt)
        node = nxt
    return node


def put(root, path, content, uid=0, gid=0, mode=0o100644, age=30):
    data = content.encode() if isinstance(content, str) else content
    parent_path, _, name = path.rpartition("/")
    parent = mkdir(root, parent_path or "/", uid if parent_path.startswith("/home") else 0,
                   gid if parent_path.startswith("/home") else 0)
    parent[7][:] = [c for c in parent[7] if c[0] != name]
    parent[7].append([name, T_FILE, uid, gid, len(data), mode, NOW - age * DAY, data, None, None])


def remove(root, path):
    parent_path, _, name = path.rpartition("/")
    parent = walk(root, parent_path or "/")
    if parent:
        parent[7][:] = [c for c in parent[7] if c[0] != name]


PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:105:111::/home/syslog:/usr/sbin/nologin
uuidd:x:106:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:107:113::/nonexistent:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
postgres:x:111:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
redis:x:112:119::/var/lib/redis:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001:,,,:/home/deploy:/bin/bash
"""
GROUP = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
cdrom:x:24:ubuntu
sudo:x:27:ubuntu,deploy
dip:x:30:ubuntu
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
plugdev:x:46:ubuntu
staff:x:50:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
messagebus:x:104:
systemd-timesync:x:105:
syslog:x:111:
uuidd:x:112:
tcpdump:x:113:
ssl-cert:x:117:postgres
postgres:x:118:
redis:x:119:
docker:x:998:ubuntu,deploy
ubuntu:x:1000:
deploy:x:1001:
"""
def _yescrypt(user: str) -> str:
    """A stable, plausible-looking Ubuntu 22.04 yescrypt hash (not a hash of any real password)."""
    abc = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    digest = hashlib.sha512(f"honeyjar:{user}".encode()).digest()
    s = "".join(abc[b % 64] for b in digest)
    return f"$y$j9T${s[:22]}${s[22:65]}"


SHADOW = "".join(
    f"{u}:{_yescrypt(u) if u in ('root', 'ubuntu', 'deploy') else '*'}:19800:0:99999:7:::\n"
    for u in (line.split(":")[0] for line in PASSWD.splitlines())
)

OS_RELEASE = """PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"""
LSB = """DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.5 LTS"
"""
MOTD = """Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

17 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

"""
SOURCES = """deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu jammy stable
"""
PROC_VERSION = ("Linux version 5.15.0-122-generic (buildd@lcy02-amd64-034) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) "
                "11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024\n")
CPU = """processor\t: {n}
vendor_id\t: AuthenticAMD
cpu family\t: 25
model\t\t: 1
model name\t: AMD EPYC 7763 64-Core Processor
stepping\t: 1
microcode\t: 0xffffffff
cpu MHz\t\t: 2445.426
cache size\t: 512 KB
physical id\t: 0
siblings\t: 8
core id\t\t: {core}
cpu cores\t: 4
apicid\t\t: {n}
initial apicid\t: {n}
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 13
wp\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext invpcid_single vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves clzero xsaveerptr rdpru arat npt nrip_save umip vaes vpclmulqdq rdpid fsrm
bugs\t\t: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass srso
bogomips\t: 4890.85
TLB size\t: 2560 4K pages
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 48 bits physical, 48 bits virtual
power management:

"""
MEMINFO = """MemTotal:       16374012 kB
MemFree:         2318840 kB
MemAvailable:    9876544 kB
Buffers:          412300 kB
Cached:          6982112 kB
SwapCached:            0 kB
Active:          7741220 kB
Inactive:        4402896 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:               412 kB
Shmem:            203716 kB
"""
ROOT_HISTORY = """apt update && apt upgrade -y
systemctl status docker
docker ps
cd /opt/portal
docker compose pull
docker compose up -d
docker logs portal-web --tail 50
vim /opt/portal/.env
psql -h 10.0.12.4 -U portal portal_prod
ssh deploy@10.0.12.7
crontab -l
df -h
journalctl -u nginx --since today
certbot renew --dry-run
"""
DEPLOY_HISTORY = """cd /opt/portal
git pull origin main
docker compose build web
docker compose up -d web
cat ~/.aws/credentials
aws s3 ls s3://portal-backups-prod/
ssh ubuntu@10.0.12.4
exit
"""
COMPOSE = """services:
  web:
    image: registry.portal.local/portal-web:2.14.3
    restart: always
    env_file: .env
    ports: ["80:8080"]
    depends_on: [db]
  db:
    image: postgres:13
    restart: always
    environment:
      POSTGRES_USER: portal
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes: ["pgdata:/var/lib/postgresql/data"]
volumes:
  pgdata:
"""
ENV = """APP_ENV=production
DB_HOST=10.0.12.4
DB_USER=portal
DB_PASSWORD=Pr0d!portal#2024
REDIS_URL=redis://10.0.12.5:6379/0
JWT_SECRET=7f3d9a1c5e8b2f4a6d0c9e7b1a3f5d8c
"""
KNOWN_HOSTS = ("|1|kXq2b8nZ3v+Lr1mT4yWgQ3xvLb0=|Wq3xLb0yTqW1n8m2Kc4fZgPq7Rs= ssh-ed25519 "
               "AAAAC3NzaC1lZDI1NTE5AAAAIK8n2Lq7RsTyU4wX0vN3mB8eZp1Lq7RsTyU4wX0vN3mB\n")


# Static command outputs ("txtcmds") that must agree with the hardware above.
TXTCMDS = {
    "usr/bin/nproc": "8\n",
    "usr/bin/lscpu": """Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Address sizes:         48 bits physical, 48 bits virtual
  Byte Order:            Little Endian
CPU(s):                  8
  On-line CPU(s) list:   0-7
Vendor ID:               AuthenticAMD
  Model name:            AMD EPYC 7763 64-Core Processor
    CPU family:          25
    Model:               1
    Thread(s) per core:  2
    Core(s) per socket:  4
    Socket(s):           1
    Stepping:            1
    BogoMIPS:            4890.85
Virtualization features:
  Hypervisor vendor:     Microsoft
  Virtualization type:   full
Caches (sum of all):
  L1d:                   128 KiB (4 instances)
  L1i:                   128 KiB (4 instances)
  L2:                    2 MiB (4 instances)
  L3:                    32 MiB (1 instance)
""",
    "bin/df": """Filesystem      Size  Used Avail Use% Mounted on
tmpfs           1.6G  1.2M  1.6G   1% /run
/dev/sda1        62G   21G   41G  34% /
tmpfs           7.9G     0  7.9G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda15      105M  6.1M   99M   6% /boot/efi
/dev/sdb1        32G   28K   30G   1% /mnt
tmpfs           1.6G  4.0K  1.6G   1% /run/user/1000
""",
}


def write_txtcmds(src: str, dst: str):
    shutil.copytree(src, dst)
    TXTCMDS["usr/bin/df"] = TXTCMDS["bin/df"]  # Ubuntu resolves df to /usr/bin/df
    for rel, body in TXTCMDS.items():
        with open(f"{dst}/{rel}", "w", encoding="utf-8", newline="\n") as f:
            f.write(body)


def main(src: str, dst: str):
    with open(src, "rb") as f:
        root = pickle.load(f)

    remove(root, "/home/phil")
    for path, body in [("/etc/passwd", PASSWD), ("/etc/passwd-", PASSWD), ("/etc/group", GROUP),
                       ("/etc/group-", GROUP), ("/usr/lib/os-release", OS_RELEASE), ("/etc/lsb-release", LSB),
                       ("/etc/issue", "Ubuntu 22.04.5 LTS \\n \\l\n\n"), ("/etc/issue.net", "Ubuntu 22.04.5 LTS\n"),
                       ("/etc/debian_version", "bookworm/sid\n"), ("/etc/motd", MOTD),
                       ("/etc/apt/sources.list", SOURCES), ("/proc/version", PROC_VERSION),
                       ("/proc/cpuinfo", "".join(CPU.format(n=n, core=n % 4) for n in range(8))),
                       ("/proc/meminfo", MEMINFO), ("/etc/timezone", "Etc/UTC\n")]:
        put(root, path, body)
    put(root, "/etc/shadow", SHADOW, gid=42, mode=0o100640)
    remove(root, "/etc/apt/sources.list.d/debian.sources")

    # people live here: history, keys, an app with secrets
    put(root, "/root/.bash_history", ROOT_HISTORY, mode=0o100600, age=2)
    put(root, "/root/.ssh/known_hosts", KNOWN_HOSTS, mode=0o100644, age=90)
    for user, uid in (("ubuntu", 1000), ("deploy", 1001)):
        mkdir(root, f"/home/{user}", uid, uid, 0o40750, age=500)
        put(root, f"/home/{user}/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n", uid, uid, age=500)
        put(root, f"/home/{user}/.profile", "# ~/.profile: executed by the command interpreter for login shells.\n",
            uid, uid, age=500)
    put(root, "/home/deploy/.bash_history", DEPLOY_HISTORY, 1001, 1001, 0o100600, age=5)
    put(root, "/opt/portal/docker-compose.yml", COMPOSE, age=12)
    put(root, "/opt/portal/.env", ENV, mode=0o100600, age=12)

    with open(dst, "wb") as f:
        pickle.dump(root, f)
    print(f"wrote {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
    if len(sys.argv) > 4:
        write_txtcmds(sys.argv[3], sys.argv[4])
