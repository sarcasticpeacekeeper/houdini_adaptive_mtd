#!/usr/bin/env bash
# Legit client "follow-the-surface" loop.
# Runs on the sensor. Polls the dashboard for the current VIP, then hits
# the server's internal 443 directly on the DMZ (the sensor is on the DMZ subnet,
# so it can reach 172.16.10.x directly — no need to go through the WAN DNAT,
# which only applies to traffic coming in from the WAN).
#
# Run in a terminal on the sensor's XFCE desktop during the demo:
#   bash /opt/mtd-client/follow-surface.sh
#
# Narration: "This green stream is a normal user. It never breaks —
# legit users follow the service, attackers chase a snapshot."

set -u
DASHBOARD="http://localhost:43123/api/surface"

while true; do
    vip=$(curl -s "$DASHBOARD" 2>/dev/null | jq -r '.current_vip // empty')
    if [ -z "$vip" ]; then
        printf '%s dashboard-down\n' "$(date +%T)"
        sleep 2
        continue
    fi
    curl -k --resolve "svc.local:443:$vip" "https://svc.local:443/" \
        -o /dev/null -s -w "$(date +%T) %{http_code}\n" 2>/dev/null || \
        printf '%s request-failed\n' "$(date +%T)"
    sleep 2
done
