#!/usr/bin/env python3
"""Render sing-box transparent SOCKS5 gateway config and firewall metadata.

Stdlib-only so the exact same validation and rendering logic runs inside the
Alpine gateway container and in local unit tests without extra dependencies.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import sys
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping
from urllib.parse import unquote, urlsplit

INBOUND_MARK = 0x2028
DIRECT_MARK = 0x202A
SOCKS_MARK = 0x202B

DNS_LISTEN_IP = "127.0.0.11"
DNS_LISTEN_PORT = 1053
DEFAULT_TUN_IPV4 = "198.19.0.1/30"
DEFAULT_TUN_IPV6 = "fdfe:dcba:9876::1/126"

_VALID_LOG_LEVELS = {"trace", "debug", "info", "warn", "error", "fatal", "panic"}
_VALID_DNS_STRATEGIES = {"ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6"}
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_DOCKER_DNS_DNAT_RE = re.compile(
    r"DOCKER_OUTPUT\b.*?-p\s+udp\b.*?--dport\s+53\b.*?-j\s+DNAT\s+--to-destination\s+"
    r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)"
)

ResolverFn = Callable[[str, int], list[str]]


class ConfigError(ValueError):
    """Raised when gateway environment configuration is invalid."""


@dataclass(frozen=True)
class SocksEndpoint:
    scheme: str
    host: str
    port: int
    username: str | None
    password: str | None

    @property
    def redacted(self) -> str:
        host_fmt = f"[{self.host}]" if ":" in self.host else self.host
        auth = "***@" if (self.username is not None or self.password is not None) else ""
        return f"{self.scheme}://{auth}{host_fmt}:{self.port}"


def _parse_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    raw = env.get(key, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{key} must be a boolean (0/1/true/false), got {env.get(key)!r}")


def _split_csv(raw: str) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for part in re.split(r"[\s,]+", raw.strip()):
        val = part.strip()
        if not val or val in seen:
            continue
        seen.add(val)
        items.append(val)
    return items


def parse_socks5_url(raw: str) -> SocksEndpoint:
    text = raw.strip()
    if not text:
        raise ConfigError("EGRESS_SOCKS5_URL is required (e.g. socks5://1.2.3.4:1080)")
    parsed = urlsplit(text)
    scheme = parsed.scheme.lower()
    if scheme not in {"socks5", "socks5h"}:
        raise ConfigError(
            f"EGRESS_SOCKS5_URL must use socks5:// or socks5h:// scheme, got {scheme or '<empty>'!r}"
        )
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigError("EGRESS_SOCKS5_URL must not contain a path, query, or fragment")
    host = (parsed.hostname or "").strip()
    if not host:
        raise ConfigError("EGRESS_SOCKS5_URL is missing a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("EGRESS_SOCKS5_URL has an invalid port") from exc
    if port is None or not (1 <= port <= 65535):
        raise ConfigError("EGRESS_SOCKS5_URL must specify an explicit port (1-65535)")
    username = unquote(parsed.username) if parsed.username is not None else None
    password = unquote(parsed.password) if parsed.password is not None else None
    if username == "" and password is None:
        username = None
    return SocksEndpoint(
        scheme=scheme,
        host=host,
        port=port,
        username=username,
        password=password,
    )


def parse_dns_server(raw: str) -> tuple[str, int]:
    text = (raw or "").strip() or "1.1.1.1"
    host = text
    port = 53
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ConfigError(f"EGRESS_DNS_SERVER has malformed IPv6 brackets: {text!r}")
        host = text[1:end]
        rest = text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ConfigError(f"EGRESS_DNS_SERVER has invalid port syntax: {text!r}")
            port = _parse_port(rest[1:], "EGRESS_DNS_SERVER")
    elif text.count(":") == 1:
        host, port_s = text.rsplit(":", 1)
        port = _parse_port(port_s, "EGRESS_DNS_SERVER")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ConfigError(
            f"EGRESS_DNS_SERVER must be an IP address (optionally with :port), got {text!r}"
        ) from exc
    if ip.is_loopback or ip.is_unspecified:
        raise ConfigError(f"EGRESS_DNS_SERVER must not be loopback/unspecified: {text!r}")
    return str(ip), port


def _parse_port(raw: str, name: str) -> int:
    try:
        port = int(raw, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} port must be an integer, got {raw!r}") from exc
    if not (1 <= port <= 65535):
        raise ConfigError(f"{name} port out of range (1-65535): {port}")
    return port


def parse_docker_dns(nat_rules: str) -> tuple[str, int] | None:
    """Extract Docker embedded DNS UDP backend (e.g. 127.0.0.11:56718) from iptables-save -t nat."""
    for line in nat_rules.splitlines():
        m = _DOCKER_DNS_DNAT_RE.search(line)
        if m:
            ip = m.group(1)
            port = int(m.group(2), 10)
            if 1 <= port <= 65535:
                return ip, port
    return None


def parse_connected_ipv4_subnets(ip_route_output: str, exclude_ifaces: Iterable[str] = ("tun0", "lo")) -> list[str]:
    """Parse directly connected IPv4 CIDRs from `ip -4 route show scope link`."""
    excluded = set(exclude_ifaces)
    subnets: list[str] = []
    seen: set[str] = set()
    for line in ip_route_output.splitlines():
        parts = line.split()
        if not parts:
            continue
        dest = parts[0]
        if dest in {"default", "local", "broadcast", "multicast"}:
            continue
        iface = ""
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                iface = parts[idx + 1]
        if iface in excluded:
            continue
        try:
            net = ipaddress.ip_network(dest, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.is_loopback or net.prefixlen == 0:
            continue
        cidr = str(net)
        if cidr not in seen:
            seen.add(cidr)
            subnets.append(cidr)
    return subnets


def _validate_domain(raw: str, env_name: str) -> str:
    d = raw.strip().lstrip(".").rstrip(".").lower()
    if not d or len(d) > 253:
        raise ConfigError(f"{env_name} contains invalid domain: {raw!r}")
    labels = d.split(".")
    for label in labels:
        if not _DOMAIN_LABEL_RE.match(label):
            raise ConfigError(f"{env_name} contains invalid domain label in {raw!r}")
    return d


def _parse_cidrs(raw: str, env_name: str) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for item in _split_csv(raw):
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise ConfigError(f"{env_name} contains invalid IP/CIDR {item!r}") from exc
        if net.prefixlen == 0:
            raise ConfigError(f"{env_name} must not contain a default catch-all route ({item!r})")
        if net.version == 4:
            v4.append(str(net))
        else:
            v6.append(str(net))
    return v4, v6


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    seen: set[str] = set()
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def resolve_socks_ips(endpoint: SocksEndpoint, resolver: ResolverFn) -> tuple[list[str], list[str]]:
    try:
        literal = ipaddress.ip_address(endpoint.host)
        raw_ips = [str(literal)]
    except ValueError:
        try:
            raw_ips = resolver(endpoint.host, endpoint.port)
        except OSError as exc:
            raise ConfigError(
                f"Failed to resolve SOCKS5 host {endpoint.host!r}: {exc}"
            ) from exc

    v4: list[str] = []
    v6: list[str] = []
    for raw in raw_ips:
        ip = ipaddress.ip_address(raw)
        if ip.is_loopback or ip.is_unspecified:
            raise ConfigError(
                f"SOCKS5 host {endpoint.host!r} resolved to loopback/unspecified address ({ip}). "
                "容器内 127.0.0.1 指向网关自身而非宿主机；若代理运行在宿主机请改用 "
                "socks5://host.docker.internal:<port>"
            )
        if ip.version == 4:
            if str(ip) not in v4:
                v4.append(str(ip))
        else:
            if str(ip) not in v6:
                v6.append(str(ip))
    if not v4 and not v6:
        raise ConfigError(f"SOCKS5 host {endpoint.host!r} resolved to no usable IP addresses")
    return v4, v6


def select_tun_ipv4(raw_addr: str, docker_subnets_v4: list[str]) -> str:
    explicit = bool(raw_addr.strip())
    candidate = raw_addr.strip() or DEFAULT_TUN_IPV4
    try:
        iface = ipaddress.IPv4Interface(candidate)
    except ValueError as exc:
        raise ConfigError(f"EGRESS_TUN_ADDR must be an IPv4 interface CIDR (e.g. 198.19.0.1/30), got {candidate!r}") from exc
    if iface.network.prefixlen < 24 or iface.network.prefixlen > 30:
        raise ConfigError(f"EGRESS_TUN_ADDR prefix length must be between /24 and /30, got {candidate!r}")
    docker_nets = [ipaddress.IPv4Network(c) for c in docker_subnets_v4]
    if not any(iface.network.overlaps(net) for net in docker_nets):
        return str(iface)
    if explicit:
        raise ConfigError(
            f"EGRESS_TUN_ADDR {candidate!r} overlaps a local Docker subnet ({', '.join(docker_subnets_v4)})"
        )
    # Auto-pick a free /30 inside RFC 2544 benchmark range 198.19.0.0/16.
    for third in range(0, 256):
        for host_base in range(0, 256, 4):
            alt = ipaddress.IPv4Interface(f"198.19.{third}.{host_base + 1}/30")
            if not any(alt.network.overlaps(net) for net in docker_nets):
                return str(alt)
    raise ConfigError("Unable to find a non-overlapping IPv4 /30 for tun0")


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_gateway_bundle(
    env: Mapping[str, str],
    *,
    nat_rules: str = "",
    ip_route_output: str = "",
    resolver: ResolverFn = default_resolver,
) -> tuple[dict, dict, str]:
    """Build (sing_box_config, firewall_meta, redacted_summary)."""
    endpoint = parse_socks5_url(env.get("EGRESS_SOCKS5_URL", ""))
    socks_v4, socks_v6 = resolve_socks_ips(endpoint, resolver)

    ipv6_enabled = _parse_bool(env, "EGRESS_IPV6", False)
    kill_switch = _parse_bool(env, "EGRESS_KILL_SWITCH", True)
    socks5_udp = _parse_bool(env, "EGRESS_SOCKS5_UDP", False)
    hijack_tun_dns = _parse_bool(env, "EGRESS_HIJACK_TUN_DNS", True)

    log_level = (env.get("EGRESS_LOG_LEVEL", "info").strip() or "info").lower()
    if log_level not in _VALID_LOG_LEVELS:
        raise ConfigError(f"EGRESS_LOG_LEVEL must be one of {sorted(_VALID_LOG_LEVELS)}, got {log_level!r}")

    default_strategy = "prefer_ipv4" if ipv6_enabled else "ipv4_only"
    dns_strategy = (env.get("EGRESS_DNS_STRATEGY", "").strip() or default_strategy).lower()
    if dns_strategy not in _VALID_DNS_STRATEGIES:
        raise ConfigError(
            f"EGRESS_DNS_STRATEGY must be one of {sorted(_VALID_DNS_STRATEGIES)}, got {dns_strategy!r}"
        )

    dns_server_ip, dns_server_port = parse_dns_server(env.get("EGRESS_DNS_SERVER", "1.1.1.1"))
    docker_dns = parse_docker_dns(nat_rules)
    docker_subnets_v4 = parse_connected_ipv4_subnets(ip_route_output)
    tun_ipv4 = select_tun_ipv4(env.get("EGRESS_TUN_ADDR", ""), docker_subnets_v4)

    internal_domains = _dedupe(
        [_validate_domain(d, "EGRESS_INTERNAL_DOMAINS") for d in _split_csv(env.get("EGRESS_INTERNAL_DOMAINS", ""))]
        + ["host.docker.internal"]
    )
    bypass_domains = _dedupe(
        [_validate_domain(d, "EGRESS_BYPASS_DOMAINS") for d in _split_csv(env.get("EGRESS_BYPASS_DOMAINS", ""))]
    )
    bypass_cidrs_v4, bypass_cidrs_v6 = _parse_cidrs(env.get("EGRESS_BYPASS_CIDRS", ""), "EGRESS_BYPASS_CIDRS")

    # Prefer IPv4 upstream IP unless IPv6-only upstream was given.
    if socks_v4:
        selected_socks_ip = socks_v4[0]
    else:
        selected_socks_ip = socks_v6[0]

    # Build DNS servers & rules (sing-box 1.12+/1.14+ typed format).
    dns_servers: list[dict] = [
        {
            "tag": "remote-dns",
            "type": "tcp",
            "server": dns_server_ip,
            "server_port": dns_server_port,
            "detour": "socks-out",
        }
    ]
    dns_rules: list[dict] = []
    if docker_dns is not None:
        docker_dns_ip, docker_dns_port = docker_dns
        dns_servers.append(
            {
                "tag": "docker-dns",
                "type": "udp",
                "server": docker_dns_ip,
                "server_port": docker_dns_port,
            }
        )
        default_domain_resolver = "docker-dns"
        if internal_domains:
            dns_rules.append(
                {
                    "domain": internal_domains,
                    "action": "route",
                    "server": "docker-dns",
                }
            )
    else:
        default_domain_resolver = "remote-dns"

    # Build inbounds.
    inbounds: list[dict] = []
    if docker_dns is not None:
        inbounds.append(
            {
                "type": "direct",
                "tag": "dns-in",
                "listen": DNS_LISTEN_IP,
                "listen_port": DNS_LISTEN_PORT,
            }
        )

    tun_addresses = [tun_ipv4]
    if ipv6_enabled:
        tun_ipv6 = env.get("EGRESS_TUN_IPV6_ADDR", "").strip() or DEFAULT_TUN_IPV6
        try:
            ipaddress.IPv6Interface(tun_ipv6)
        except ValueError as exc:
            raise ConfigError(f"EGRESS_TUN_IPV6_ADDR is invalid: {tun_ipv6!r}") from exc
        tun_addresses.append(tun_ipv6)

    exclude_addresses = _dedupe(
        list(docker_subnets_v4)
        + [f"{ip}/32" for ip in socks_v4]
        + ([f"{ip}/128" for ip in socks_v6] if ipv6_enabled else [])
        + list(bypass_cidrs_v4)
        + (list(bypass_cidrs_v6) if ipv6_enabled else [])
    )

    tun_inbound: dict = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": "tun0",
        "address": tun_addresses,
        "mtu": 1400,
        "auto_route": True,
        "strict_route": True,
    }
    if exclude_addresses:
        tun_inbound["route_exclude_address"] = exclude_addresses
    inbounds.append(tun_inbound)

    # Build outbounds.
    socks_outbound: dict = {
        "type": "socks",
        "tag": "socks-out",
        "server": selected_socks_ip,
        "server_port": endpoint.port,
        "version": "5",
        "routing_mark": SOCKS_MARK,
    }
    if not socks5_udp:
        socks_outbound["network"] = "tcp"
    if endpoint.username is not None:
        socks_outbound["username"] = endpoint.username
    if endpoint.password is not None:
        socks_outbound["password"] = endpoint.password

    direct_outbound: dict = {
        "type": "direct",
        "tag": "direct",
        "routing_mark": DIRECT_MARK,
    }

    # Build route rules.
    route_rules: list[dict] = []
    if docker_dns is not None:
        route_rules.append({"inbound": ["dns-in"], "action": "hijack-dns"})

    if hijack_tun_dns:
        # Match port 53 directly so server-speaks-first TCP probes (nmap/SSH/MySQL)
        # suffer zero sniff latency on non-DNS ports.
        route_rules.append({"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"})

    if bypass_domains:
        route_rules.append(
            {
                "inbound": ["tun-in"],
                "network": "tcp",
                "port": [80, 443],
                "action": "sniff",
                "sniffer": ["http", "tls"],
                "timeout": "100ms",
            }
        )
        route_rules.append(
            {
                "domain_suffix": bypass_domains,
                "action": "route",
                "outbound": "direct",
            }
        )

    bypass_cidrs_all = list(bypass_cidrs_v4) + (list(bypass_cidrs_v6) if ipv6_enabled else [])
    if bypass_cidrs_all:
        route_rules.append(
            {
                "ip_cidr": bypass_cidrs_all,
                "action": "route",
                "outbound": "direct",
            }
        )

    # SOCKS5 cannot proxy ICMP; reject explicitly to avoid forged local echo replies.
    route_rules.append({"network": "icmp", "action": "reject"})
    if not socks5_udp:
        # Reject non-DNS UDP (QUIC/STUN/WebRTC) so browsers fall back to TCP via SOCKS5
        # and UDP packets never leak or hang waiting for unsupported UDP Associate.
        route_rules.append({"network": "udp", "action": "reject"})

    sing_box_config = {
        "log": {
            "level": log_level,
            "timestamp": True,
        },
        "dns": {
            "servers": dns_servers,
            "rules": dns_rules,
            "final": "remote-dns",
            "strategy": dns_strategy,
            "reverse_mapping": True,
        },
        "inbounds": inbounds,
        "outbounds": [socks_outbound, direct_outbound],
        "route": {
            "auto_detect_interface": True,
            "default_domain_resolver": default_domain_resolver,
            "rules": route_rules,
            "final": "socks-out",
        },
    }

    firewall_meta = {
        "SOCKS5_IPV4S": " ".join(socks_v4),
        "SOCKS5_IPV6S": " ".join(socks_v6),
        "SOCKS5_PORT": str(endpoint.port),
        "DOCKER_SUBNETS_V4": " ".join(docker_subnets_v4),
        "BYPASS_CIDRS_V4": " ".join(bypass_cidrs_v4),
        "BYPASS_CIDRS_V6": " ".join(bypass_cidrs_v6),
        "HAS_BYPASS_DOMAINS": "1" if bypass_domains else "0",
        "HAS_DOCKER_DNS": "1" if docker_dns is not None else "0",
        "DNS_LISTEN_IP": DNS_LISTEN_IP,
        "DNS_LISTEN_PORT": str(DNS_LISTEN_PORT),
        "INBOUND_MARK": hex(INBOUND_MARK),
        "DIRECT_MARK": hex(DIRECT_MARK),
        "SOCKS_MARK": hex(SOCKS_MARK),
        "KILL_SWITCH": "1" if kill_switch else "0",
        "SOCKS5_UDP": "1" if socks5_udp else "0",
        "IPV6_ENABLED": "1" if ipv6_enabled else "0",
    }

    summary = (
        f"upstream={endpoint.redacted} resolved={selected_socks_ip}:{endpoint.port} "
        f"tun={tun_ipv4} dns={dns_server_ip}:{dns_server_port}(tcp-over-socks5) "
        f"docker_dns={'on' if docker_dns else 'off'} kill_switch={'on' if kill_switch else 'off'} "
        f"udp={'socks5' if socks5_udp else 'reject'} ipv6={'on' if ipv6_enabled else 'off'}"
    )
    return sing_box_config, firewall_meta, summary


def format_meta_env(meta: Mapping[str, str]) -> str:
    lines = [f"{k}={shlex.quote(v)}" for k, v in meta.items()]
    return "\n".join(lines) + "\n"


def _write_secure(path: str, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render ARTEX sing-box egress gateway configuration")
    parser.add_argument("--config-out", default="/tmp/sing-box.json", help="Output path for sing-box JSON config")
    parser.add_argument("--meta-out", default="/tmp/egress-meta.env", help="Output path for shell firewall metadata")
    parser.add_argument("--nat-file", default="", help="Optional path to saved `iptables-save -t nat` output")
    parser.add_argument("--route-file", default="", help="Optional path to saved `ip -4 route show scope link` output")
    args = parser.parse_args(argv)

    nat_rules = ""
    if args.nat_file and os.path.exists(args.nat_file):
        with open(args.nat_file, "r", encoding="utf-8", errors="replace") as fh:
            nat_rules = fh.read()
    route_output = ""
    if args.route_file and os.path.exists(args.route_file):
        with open(args.route_file, "r", encoding="utf-8", errors="replace") as fh:
            route_output = fh.read()

    try:
        config, meta, summary = build_gateway_bundle(
            os.environ,
            nat_rules=nat_rules,
            ip_route_output=route_output,
        )
    except ConfigError as exc:
        sys.stderr.write(f"[egress-gw] configuration error: {exc}\n")
        return 2

    _write_secure(args.config_out, json.dumps(config, indent=2) + "\n")
    _write_secure(args.meta_out, format_meta_env(meta))
    sys.stderr.write(f"[egress-gw] configured: {summary}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
