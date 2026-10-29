#!/usr/bin/env bash
# Core-side containment of sensors (run at boot after Docker, see infra/templates/core.yaml).
#
# Sensors face the internet and could be compromised. Over WireGuard they may reach exactly one
# thing: the ingest API on port 8000. No SSH, no database, no other containers.
set -euo pipefail

WG=wg0
CHAIN=HONEYJAR-SENSORS

# Traffic to the API is DNAT'ed by Docker, so it traverses FORWARD -> DOCKER-USER.
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A "$CHAIN" -p tcp -m conntrack --ctorigdstport 8000 -j RETURN
iptables -A "$CHAIN" -j LOG --log-prefix "honeyjar-sensor-drop: " -m limit --limit 6/min
iptables -A "$CHAIN" -j DROP
iptables -C DOCKER-USER -i "$WG" -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER -i "$WG" -j "$CHAIN"

# Host services (sshd, anything else listening) are not for sensors either.
iptables -C INPUT -i "$WG" -m conntrack --ctstate NEW -j DROP 2>/dev/null \
  || iptables -I INPUT -i "$WG" -m conntrack --ctstate NEW -j DROP

echo "sensor containment applied on $WG (only tcp/8000 allowed)"
