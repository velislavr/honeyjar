# Deploying Honeyjar on Azure for Students

Target layout, about **$0 out of pocket** with student offers:

| Machine | Azure size (free hours\*) | Specs | Disk |
|---|---|---|---|
| **Core**: DB, API, worker, dashboard, Caddy | `Standard_B2ats_v2` (x86) | 2 vCPU / 1 GB + 2 GB swap | Premium SSD 64 GiB (P6, free\*) |
| **Sensor 1**, e.g. `us1=eastus` | `Standard_B1s` (x86) | 1 vCPU / 1 GB | Premium SSD 64 GiB (P6, free\*) |
| **Sensor 2** (optional), e.g. `sg1=southeastasia` | `Standard_B2pts_v2` (ARM) | 2 vCPU / 1 GB | Standard SSD 30 GiB (~$2.40/mo) |
| **Domain** `honeyjar.tech` | GitHub Student Pack (.tech) | | free for year 1 |

\* Azure for Students includes 750 hours/month each of B1s, B2ats v2 and B2pts v2 (one VM of each size can
run full-time) and two P6 SSD disks, for 12 months. Check *Free services* in the portal for the current
terms. What **does** cost credit is **public IPv4: about $3.65/month per VM**. Core + 1 sensor is roughly
$8/month (the $100 credit lasts about a year); three machines are roughly $13/month.

```
 sensor VMs                                       core VM
 cowrie + http honeypot ─► vector ══ WireGuard ══► 10.66.0.1:8000 ingest ─► … ─► Caddy :443 ─► you
 honeypot egress firewalled                       sensors may reach ONLY port 8000 over the tunnel
```

The 1 GB VMs never build anything: GitHub Actions (`.github/workflows/images.yml`) builds the core,
dashboard and HTTP honeypot images for amd64 and arm64 and pushes them to GHCR. The VMs pull them.

Read Azure's acceptable-use policy first. Expect abuse notices: your sensor IPs will appear in other
people's logs. The core runs no honeypot, so it is the least sensitive part.

## 0. Prepare (on your PC)

1. Push this repo to GitHub as a **public** repo; the VMs `git clone` it at boot. Secrets are never in
   the repo: they live in `infra/out/`, which is gitignored.
2. **Publish the images.** The push runs the *images* workflow (repo → *Actions*, ~10–15 min the first
   time). The VMs pull without logging in, so the packages must be public. Packages from a public repo
   usually are; if not: GitHub → your profile → *Packages* → `honeyjar-core`, `honeyjar-dashboard`,
   `honeyjar-http` → *Package settings* → *Change visibility* → **Public**.
3. Have an SSH key (`ssh-keygen -t ed25519` if you don't), and `pip install cryptography`.

## 1. Render the core config

Choose sensor names and regions up front (`NAME=REGION`; `python infra/render.py --help` lists them).
The region also sets the sensor's spot on the globe. You can create fewer sensors than you list.

```bash
python infra/render.py --domain honeyjar.tech --repo https://github.com/<you>/honeyjar \
    --ssh-key ~/.ssh/id_ed25519.pub --sensor us1=eastus --sensor sg1=southeastasia
```

This writes `infra/out/core-user-data.yaml` and `infra/out/state.json`, which holds every key, token and
password. **Back up `state.json`** somewhere private. Re-running reuses it.

## 2. Create the core VM

Azure portal → *Virtual machines* → *Create* → *Azure virtual machine*:

| Tab | Field | Value |
|---|---|---|
| Basics | Resource group | new: `honeyjar` |
| | Name | `honeyjar-core` |
| | Region | one near you, e.g. *(US) East US* |
| | Image | *Ubuntu Server 24.04 LTS - x64 Gen2* |
| | Size | `Standard_B2ats_v2` (*See all sizes* and search for it) |
| | Authentication | *SSH public key*, username `azureuser`, *Use existing public key*: paste `~/.ssh/id_ed25519.pub` |
| | Public inbound ports | **None** (rules are added below) |
| Disks | OS disk | *Premium SSD*, size **64 GiB (P6)** |
| Advanced | Custom data | paste `infra/out/core-user-data.yaml` |

*Review + create* → *Create*. Azure gives the VM a **static** Standard public IP, so it won't change.

Then on the VM: *Networking* → *Network settings* → *Create port rule* → *Inbound port rule*, once per row:

| Priority | Port | Protocol | Source | Purpose |
|---|---|---|---|---|
| 100 | `22` | TCP | **My IP address** | your admin SSH |
| 110 | `80,443` | TCP | Any | dashboard + TLS certificate |
| 120 | `51820` | UDP | Any | WireGuard from sensors |

**DNS**: at your .tech registrar, add an `A` record for `honeyjar.tech` pointing at the core's public IP.
Caddy fetches the HTTPS certificate automatically once DNS resolves.

First boot takes about 5 minutes:
```bash
ssh azureuser@<core-ip>
cloud-init status --wait && cd /opt/honeyjar/core && docker compose ps
```

## 3. Render and create the sensors

```bash
python infra/render.py --domain honeyjar.tech --repo https://github.com/<you>/honeyjar \
    --ssh-key ~/.ssh/id_ed25519.pub --sensor us1=eastus --sensor sg1=southeastasia --core-ip <core-ip>
```

For each sensor you want, create a VM like the core, with these differences:
- **Name** `honeyjar-<name>`; **Region** matching the name (`us1=eastus` → East US, `sg1` → Southeast Asia)
- **Size** `Standard_B1s` with image *Ubuntu Server 24.04 LTS - x64 Gen2*, or `Standard_B2pts_v2` with
  *Ubuntu Server 24.04 LTS - **Arm64***. Use each size once so each runs on its own free hours.
- **Disk**: the second free P6, or *Standard SSD* 30 GiB once both P6 disks are used
- **Custom data**: `infra/out/sensor-<name>-user-data.yaml`

Inbound port rules:

| Priority | Port(s) | Protocol | Source | Purpose |
|---|---|---|---|---|
| 100 | `22222` | TCP | **My IP address** | your admin SSH |
| 110 | `22,23,80,443,2375,5555,6379,7547,8080,8443,9200,10443,37215,52869` | TCP | Any | the honeypots (SSH/Telnet, web, Docker API, ADB, Redis, Elasticsearch) |

If your home IP changes, edit rule 100 on each VM.

Admin SSH on sensors moves to **port 22222**; port 22 now belongs to the honeypot:
```bash
ssh -p 22222 ops@<sensor-ip>
cloud-init status --wait && cd /opt/honeyjar/sensor && docker compose ps
```

### Optional: Oracle Always Free sensor

An Oracle Cloud *VM.Standard.E2.1.Micro* (AMD, 1 GB) also works as a sensor: render it with an Oracle
region (e.g. `--sensor fra1=eu-frankfurt-1`), paste its user-data as the instance's cloud-init script, and in
its subnet's security list open the honeypot TCP ports from `0.0.0.0/0` plus TCP 22222 from `<your-ip>/32`.

## 4. Verify

- `https://honeyjar.tech` loads, and the green dot next to the logo means the API is healthy.
- Within minutes of a sensor booting, real SSH/Telnet attempts appear in the live feed. Bots scan the
  whole IPv4 space continuously.
- On the core: `sudo wg show` lists each sensor with a recent handshake; `free -h` shows memory headroom.
- Sensor containment, run on a sensor (should fail):
  `docker exec honeyjar-sensor-http-1 python -c "import urllib.request as u; u.urlopen('http://example.com', timeout=5)"`
- Core isolation, run on a sensor (should fail): `nc -zv -w 3 10.66.0.1 22`

## Adding a sensor later

Cloud-init only runs on first boot, so the core needs the new peer pushed by hand:
1. Re-run `render.py` with the extra `--sensor` and `--core-ip`.
2. On the core, update `/etc/wireguard/wg0.conf` and `/opt/honeyjar/core/.env` from the new
   `core-user-data.yaml`, then `sudo systemctl restart wg-quick@wg0 && cd /opt/honeyjar/core && docker compose up -d`.
3. Create the VM with its new user-data.

## Costs and housekeeping

- **Watch the credit** in *Cost Management*. Public IPs are the main draw. When the credit or student
  status ends, Azure stops the VMs instead of billing you, but check the current terms.
- Sensors are disposable: if one misbehaves, delete it and recreate it from the same user-data.
- Updates: push to GitHub, wait for the *images* workflow, then on each VM
  `cd /opt/honeyjar && git pull && cd core && docker compose --profile prod pull && docker compose --profile prod up -d`
  (sensors: `cd sensor && docker compose pull && docker compose up -d`).
- On a bigger core (2 GB+), raise `DB_TUNE_MEMORY` and `REDIS_MAXMEMORY` in the rendered core config
  before first boot. Postgres is tuned once, when its data volume is created.
