#!/bin/sh
set -eu

READY_FILE="/tmp/egress-ready"
CONFIG_FILE="/tmp/sing-box.json"
META_FILE="/tmp/egress-meta.env"
NAT_DUMP="/tmp/egress-nat.rules"
ROUTE_DUMP="/tmp/egress-routes.txt"

rm -f "$READY_FILE" "$CONFIG_FILE" "$META_FILE" "$NAT_DUMP" "$ROUTE_DUMP"

log() {
  printf '[egress-gw] %s\n' "$*" >&2
}

detect_iptables() {
  for candidate in iptables-nft iptables-legacy iptables; do
    if command -v "${candidate}-save" >/dev/null 2>&1; then
      if "${candidate}-save" -t nat 2>/dev/null | grep -q "DOCKER_OUTPUT"; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  done
  for candidate in iptables-nft iptables-legacy iptables; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -t filter -L OUTPUT >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

matching_ip6tables() {
  case "$1" in
    iptables-nft) printf '%s\n' "ip6tables-nft" ;;
    iptables-legacy) printf '%s\n' "ip6tables-legacy" ;;
    *) printf '%s\n' "ip6tables" ;;
  esac
}

IPTABLES="$(detect_iptables)" || {
  log "ERROR: no working iptables backend found (ensure CAP_NET_ADMIN is granted)"
  exit 1
}
IP6TABLES="$(matching_ip6tables "$IPTABLES")"
log "using firewall backend: $IPTABLES"

if [ ! -c /dev/net/tun ]; then
  log "ERROR: /dev/net/tun is missing; mount /dev/net/tun:/dev/net/tun in compose"
  exit 1
fi

"${IPTABLES}-save" -t nat > "$NAT_DUMP" 2>/dev/null || : > "$NAT_DUMP"
ip -4 route show scope link > "$ROUTE_DUMP" 2>/dev/null || : > "$ROUTE_DUMP"

python3 /usr/local/lib/artex-egress/render_config.py \
  --config-out "$CONFIG_FILE" \
  --meta-out "$META_FILE" \
  --nat-file "$NAT_DUMP" \
  --route-file "$ROUTE_DUMP"

rm -f "$NAT_DUMP" "$ROUTE_DUMP"

# Validate generated sing-box config before touching any iptables rule.
sing-box check -c "$CONFIG_FILE"

# shellcheck disable=SC1090
. "$META_FILE"

# 1. Intercept Docker embedded DNS (127.0.0.11:53) before DOCKER_OUTPUT so external
#    DNS queries never escape via Docker's host-namespace resolver (e.g. 127.0.0.53).
if [ "$HAS_DOCKER_DNS" = "1" ]; then
  for proto in udp tcp; do
    while "$IPTABLES" -t nat -D OUTPUT -d 127.0.0.11/32 -p "$proto" --dport 53 \
      -j DNAT --to-destination "${DNS_LISTEN_IP}:${DNS_LISTEN_PORT}" 2>/dev/null; do
      :
    done
    "$IPTABLES" -t nat -I OUTPUT 1 -d 127.0.0.11/32 -p "$proto" --dport 53 \
      -j DNAT --to-destination "${DNS_LISTEN_IP}:${DNS_LISTEN_PORT}"
  done
  log "intercepted Docker embedded DNS 127.0.0.11:53 -> ${DNS_LISTEN_IP}:${DNS_LISTEN_PORT}"
else
  log "WARNING: DOCKER_OUTPUT nat chain not found; skipping 127.0.0.11:53 intercept"
fi

# 2. Keep inbound reply traffic (e.g. :8787 Web UI when userland-proxy=false) on eth+
#    instead of being sucked into tun0.
if "$IPTABLES" -t mangle -C PREROUTING -i eth+ -m conntrack --ctstate NEW -j CONNMARK --set-mark "$INBOUND_MARK" 2>/dev/null \
  || "$IPTABLES" -t mangle -A PREROUTING -i eth+ -m conntrack --ctstate NEW -j CONNMARK --set-mark "$INBOUND_MARK" 2>/dev/null; then
  if "$IPTABLES" -t mangle -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark 2>/dev/null \
    || "$IPTABLES" -t mangle -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j CONNMARK --restore-mark 2>/dev/null; then
    if ! ip -4 rule list | grep -q "fwmark ${INBOUND_MARK} lookup main"; then
      ip -4 rule add fwmark "$INBOUND_MARK" lookup main priority 100 2>/dev/null || true
    fi
  fi
else
  log "WARNING: mangle/CONNMARK unavailable; inbound traffic relies on Docker bridge subnet exclusion"
fi

# 3. Fail-closed OUTPUT Kill Switch: even if sing-box crashes or a tool tries raw/direct
#    egress, nothing outside loopback/tun0/Docker bridges/marked SOCKS5 can leave.
if [ "$KILL_SWITCH" = "1" ]; then
  "$IPTABLES" -N EGRESS_KILLSWITCH 2>/dev/null || "$IPTABLES" -F EGRESS_KILLSWITCH
  while "$IPTABLES" -D OUTPUT -j EGRESS_KILLSWITCH 2>/dev/null; do
    :
  done

  "$IPTABLES" -A EGRESS_KILLSWITCH -o lo -j ACCEPT
  "$IPTABLES" -A EGRESS_KILLSWITCH -o tun0 -j ACCEPT
  "$IPTABLES" -A EGRESS_KILLSWITCH -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  for cidr in $DOCKER_SUBNETS_V4; do
    "$IPTABLES" -A EGRESS_KILLSWITCH -d "$cidr" -j ACCEPT
  done

  for ip in $SOCKS5_IPV4S; do
    "$IPTABLES" -A EGRESS_KILLSWITCH -d "${ip}/32" -p tcp --dport "$SOCKS5_PORT" -m mark --mark "$SOCKS_MARK" -j ACCEPT
    if [ "$SOCKS5_UDP" = "1" ]; then
      "$IPTABLES" -A EGRESS_KILLSWITCH -d "${ip}/32" -p udp -m mark --mark "$SOCKS_MARK" -j ACCEPT
    fi
  done

  for cidr in $BYPASS_CIDRS_V4; do
    "$IPTABLES" -A EGRESS_KILLSWITCH -d "$cidr" -j ACCEPT
  done

  if [ "$HAS_BYPASS_DOMAINS" = "1" ]; then
    "$IPTABLES" -A EGRESS_KILLSWITCH -m mark --mark "$DIRECT_MARK" -j ACCEPT
  fi

  "$IPTABLES" -A EGRESS_KILLSWITCH -j REJECT --reject-with icmp-net-prohibited
  "$IPTABLES" -I OUTPUT 1 -j EGRESS_KILLSWITCH

  # IPv6 Kill Switch (prevents accidental IPv6 leaks when kernel has IPv6 enabled).
  if [ -d /proc/sys/net/ipv6 ] && command -v "$IP6TABLES" >/dev/null 2>&1 \
    && "$IP6TABLES" -t filter -L OUTPUT >/dev/null 2>&1; then
    "$IP6TABLES" -N EGRESS_KILLSWITCH 2>/dev/null || "$IP6TABLES" -F EGRESS_KILLSWITCH
    while "$IP6TABLES" -D OUTPUT -j EGRESS_KILLSWITCH 2>/dev/null; do
      :
    done

    "$IP6TABLES" -A EGRESS_KILLSWITCH -o lo -j ACCEPT
    "$IP6TABLES" -A EGRESS_KILLSWITCH -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    if [ "$IPV6_ENABLED" = "1" ]; then
      "$IP6TABLES" -A EGRESS_KILLSWITCH -o tun0 -j ACCEPT
      for ip6 in $SOCKS5_IPV6S; do
        "$IP6TABLES" -A EGRESS_KILLSWITCH -d "${ip6}/128" -p tcp --dport "$SOCKS5_PORT" -m mark --mark "$SOCKS_MARK" -j ACCEPT
        if [ "$SOCKS5_UDP" = "1" ]; then
          "$IP6TABLES" -A EGRESS_KILLSWITCH -d "${ip6}/128" -p udp -m mark --mark "$SOCKS_MARK" -j ACCEPT
        fi
      done
      for cidr6 in $BYPASS_CIDRS_V6; do
        "$IP6TABLES" -A EGRESS_KILLSWITCH -d "$cidr6" -j ACCEPT
      done
      if [ "$HAS_BYPASS_DOMAINS" = "1" ]; then
        "$IP6TABLES" -A EGRESS_KILLSWITCH -m mark --mark "$DIRECT_MARK" -j ACCEPT
      fi
    elif [ -n "$SOCKS5_IPV6S" ]; then
      # Upstream SOCKS5 itself is IPv6 even though container target traffic is IPv4-only.
      for ip6 in $SOCKS5_IPV6S; do
        "$IP6TABLES" -A EGRESS_KILLSWITCH -d "${ip6}/128" -p tcp --dport "$SOCKS5_PORT" -m mark --mark "$SOCKS_MARK" -j ACCEPT
        if [ "$SOCKS5_UDP" = "1" ]; then
          "$IP6TABLES" -A EGRESS_KILLSWITCH -d "${ip6}/128" -p udp -m mark --mark "$SOCKS_MARK" -j ACCEPT
        fi
      done
    fi

    "$IP6TABLES" -A EGRESS_KILLSWITCH -j REJECT --reject-with icmp6-adm-prohibited
    "$IP6TABLES" -I OUTPUT 1 -j EGRESS_KILLSWITCH
  fi

  log "fail-closed OUTPUT kill switch active"
fi

touch "$READY_FILE"
exec sing-box run -c "$CONFIG_FILE"
