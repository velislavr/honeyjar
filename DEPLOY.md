# Deploying Honeyjar: Oracle Cloud core + Azure sensors

Target layout, about **$0 out of pocket** with student offers:

| Machine | Where | Size | Cost |
|---|---|---|---|
| **Core**: DB, API, worker, dashboard, Caddy | Oracle Cloud Always Free, `VM.Standard.A1.Flex` (ARM) | 2 OCPU / 12 GB | free |
| **Sensor 1**, e.g. `us1=eastus` | Azure for Students, `Standard_B2ats_v2` (x86) | 2 vCPU / 1 GB | free VM hours\*; public IP from the $100 credit |
| **Sensor 2**, e.g. `sg1=southeastasia` | Azure for Students, `Standard_B1s` | 1 vCPU / 1 GB | free VM hours\*; public IP from the $100 credit |
| **Sensor 3** (optional), e.g. `fra1=eu-frankfurt-1` | Oracle Always Free AMD micro, your Oracle **home region** | 1/8 OCPU / 1 GB | free |
| **Domain** `honeyjar.tech` | GitHub Student Pack (.tech) | | free for year 1 |

\* Azure for Students includes 750 hours/month of each of B1s, B2ats v2 and B2pts v2: one VM of each type
can run full-time. Check the current terms in the portal. Azure **does charge for public IPv4 addresses**
(~$3–4/month each), so two sensors use roughly $7/month of the $100 credit. Use **Standard SSD** disks of the
default size.

Heroku (also in the Student Pack) can't host this: it only routes HTTP to apps and can't expose raw ports
like 22/23. It also has no TimescaleDB.

```
 sensors (Azure / Oracle)                        core (Oracle)
 cowrie + http honeypot ─► vector ══ WireGuard ══► 10.66.0.1:8000 ingest ─► … ─► Caddy :443 ─► you
 honeypot egress firewalled                       sensors may reach ONLY port 8000 over the tunnel
```

Before you start, read each provider's acceptable-use policy. Expect abuse notices: your sensor IPs will
show up in other people's logs. The core runs no honeypot, so it is the least sensitive part.

## 0. Prepare (on your PC)

1. Push this repo to GitHub. A **public** repo is simplest, because the machines `git clone` it at boot. Secrets
   are never in the repo: they live in `infra/out/`, which is gitignored.
2. Have an SSH key (`ssh-keygen -t ed25519` if you don't).
3. `pip install cryptography`

## 1. Render the core config

Choose sensor names and regions up front (`NAME=REGION`, Azure region names or Oracle region ids;
`python infra/render.py --help` lists them all). The region also sets the sensor's spot on the globe.

```bash
python infra/render.py --domain honeyjar.tech --repo https://github.com/<you>/honeyjar \
    --ssh-key ~/.ssh/id_ed25519.pub --sensor us1=eastus --sensor sg1=southeastasia
```

This creates `infra/out/core-user-data.yaml` and `infra/out/state.json`, which holds every key, token and
password. **Back up `state.json`** somewhere private. Re-running reuses it.

## 2. Create the core on Oracle Cloud

1. **Create instance**: image *Canonical Ubuntu 24.04*, shape *Ampere / VM.Standard.A1.Flex*, 2 OCPU, 12 GB.
   Add your SSH key. Under *Show advanced options → Management → Cloud-init script*, paste
   `infra/out/core-user-data.yaml`.
   - "Out of capacity" is common on Always Free. Retry later or try another availability domain.
2. **Reserve the public IP** (*Networking → Reserved public IPs*) so it never changes. Sensors are configured with it.
3. **Open the cloud firewall.** In *Networking → Virtual cloud networks → your VCN → Security lists → Default*,
   add ingress rules:
   - TCP 80 and 443 from `0.0.0.0/0` (dashboard, TLS certificate)
   - UDP 51820 from `0.0.0.0/0` (WireGuard from sensors)
   - SSH 22 is already open. Narrow its source to `<your-ip>/32`.
4. **DNS**: point an `A` record for `honeyjar.tech` at the reserved IP. Caddy fetches the HTTPS certificate
   automatically once DNS resolves.
5. First boot takes ~10 minutes (the dashboard is built on the VM):
   ```bash
   ssh ubuntu@<core-ip>
   cloud-init status --wait && cd /opt/honeyjar/core && docker compose ps
   ```

## 3. Render and create the sensors

```bash
python infra/render.py --domain honeyjar.tech --repo https://github.com/<you>/honeyjar \
    --ssh-key ~/.ssh/id_ed25519.pub --sensor us1=eastus --sensor sg1=southeastasia --core-ip <core-ip>
```

### Azure sensors

For each `infra/out/sensor-<name>-user-data.yaml`: *Create a virtual machine* →
- **Region** matching the name (`us1=eastus` → East US); **Image** *Ubuntu Server 24.04 LTS*
- **Size** `Standard_B2ats_v2` for one sensor and `Standard_B1s` for the other, so each uses its own free hours
- **Authentication** SSH public key; **Public inbound ports** *None*
- **Disks**: Standard SSD
- **Advanced → Custom data**: paste the rendered file

Then on the VM's **Networking → Network settings**, add inbound security rules:

| Priority | Port(s) | Protocol | Source | Purpose |
|---|---|---|---|---|
| 100 | `22222` | TCP | **My IP address** | your admin SSH |
| 110 | `22,23,80,443,7547,8080,8443,10443,37215,52869` | TCP | Any | the honeypots |

If your home IP changes, edit rule 100 in the portal.

### Optional: Oracle AMD micro sensor

In your Oracle home region: *Create instance*, shape *VM.Standard.E2.1.Micro*, image *Ubuntu 24.04*, paste the
sensor's user-data as the cloud-init script. In its subnet's security list, open the honeypot TCP ports above
from `0.0.0.0/0`, plus TCP 22222 from `<your-ip>/32`.

### Check a sensor

Admin SSH on sensors moves to **port 22222**; port 22 now belongs to the honeypot:
```bash
ssh -p 22222 ops@<sensor-ip>
cloud-init status --wait && cd /opt/honeyjar/sensor && docker compose ps
```

## 4. Verify

- `https://honeyjar.tech` loads, and the green dot next to the logo means the API is healthy.
- Within minutes of a sensor booting, real SSH/Telnet attempts appear in the live feed. Bots scan the
  whole IPv4 space continuously.
- On the core: `sudo wg show` lists each sensor with a recent handshake.
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

- **Watch the Azure credit** (*Cost Management*). Public IPs are the main draw. When the credit or student
  status ends, Azure stops the VMs instead of billing you, but check the current terms.
- Oracle reclaims Always Free instances it considers idle. A running core is not idle.
- Sensors are disposable: if one misbehaves, delete it and recreate it from the same user-data.
- Updates: `cd /opt/honeyjar && git pull && cd core && docker compose --profile prod up -d --build`
  (sensors: `cd sensor && docker compose up -d --build`).
