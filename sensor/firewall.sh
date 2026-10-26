#!/usr/bin/env bash
# Egress containment for honeypot containers (run at boot after Docker, see infra/honeyjar-firewall.service).
#
# Containers on the br-honeypots bridge may answer inbound connections but may not
# open new outbound ones, so a compromised/abused honeypot cannot attack third parties.
# Optional: ALLOW_SAMPLE_DOWNLOAD=1 lets Cowrie fetch attacker payloads over HTTP(S)
# (standard practice for malware capture; it only ever contacts attacker infrastructure).
set -euo pipefail

BRIDGE=br-honeypots
CHAIN=HONEYPOT-EGRESS

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
if [[ "${ALLOW_SAMPLE_DOWNLOAD:-0}" == "1" ]]; then
  iptables -A "$CHAIN" -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW \
    -m hashlimit --hashlimit-name hp-dl --hashlimit-upto 10/min --hashlimit-mode srcip -j RETURN
fi
iptables -A "$CHAIN" -j LOG --log-prefix "honeypot-egress-drop: " -m limit --limit 6/min
iptables -A "$CHAIN" -j DROP

# Hook it for traffic leaving the honeypot bridge (idempotent).
iptables -C DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$CHAIN" 2>/dev/null \
  || iptables -I DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -j "$CHAIN"

# Same for IPv6 if Docker has it enabled.
if ip6tables -L DOCKER-USER >/dev/null 2>&1; then
  ip6tables -C DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -m conntrack --ctstate NEW -j DROP 2>/dev/null \
    || ip6tables -I DOCKER-USER -i "$BRIDGE" ! -o "$BRIDGE" -m conntrack --ctstate NEW -j DROP
fi
echo "honeypot egress policy applied (sample downloads: ${ALLOW_SAMPLE_DOWNLOAD:-0})"
