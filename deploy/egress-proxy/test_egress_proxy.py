#!/usr/bin/env python3
"""Unit and configuration tests for ARTEX transparent SOCKS5 egress gateway."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

EGRESS_DIR = Path(__file__).resolve().parent
REPO_ROOT = EGRESS_DIR.parent.parent
sys.path.insert(0, str(EGRESS_DIR))

import render_config  # noqa: E402


SAMPLE_NAT_RULES = """*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [13:746]
:POSTROUTING ACCEPT [33:1806]
:DOCKER_OUTPUT - [0:0]
:DOCKER_POSTROUTING - [0:0]
-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT
-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING
-A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j DNAT --to-destination 127.0.0.11:42739
-A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp -m udp --dport 53 -j DNAT --to-destination 127.0.0.11:56718
COMMIT
"""

SAMPLE_ROUTES = """172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.3
172.20.0.0/16 dev eth1 proto kernel scope link src 172.20.0.2
198.19.0.0/30 dev tun0 proto kernel scope link src 198.19.0.1
"""


class TestEgressProxyConfig(unittest.TestCase):
    def test_shell_and_python_files_use_lf_and_valid_syntax(self) -> None:
        for name in ("Dockerfile", "entrypoint.sh", "render_config.py", "docker-compose.socks5.yml", "README.md"):
            raw = (EGRESS_DIR / name).read_bytes()
            self.assertNotIn(b"\r\n", raw, f"{name} must use LF line endings")

        env_example = (REPO_ROOT / ".env.example").read_bytes()
        self.assertNotIn(b"\r\n", env_example, ".env.example must use LF line endings")
        self.assertIn(b"EGRESS_SOCKS5_URL=", env_example)

        proc = subprocess.run(
            ["sh", "-n", str(EGRESS_DIR / "entrypoint.sh")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"entrypoint.sh syntax error: {proc.stderr}")

    def test_parse_docker_dns_and_connected_subnets(self) -> None:
        self.assertEqual(render_config.parse_docker_dns(SAMPLE_NAT_RULES), ("127.0.0.11", 56718))
        self.assertIsNone(render_config.parse_docker_dns(""))
        self.assertEqual(
            render_config.parse_connected_ipv4_subnets(SAMPLE_ROUTES),
            ["172.18.0.0/16", "172.20.0.0/16"],
        )

    def test_default_strict_config_with_auth_and_domain_resolution(self) -> None:
        def fake_resolver(host: str, port: int) -> list[str]:
            self.assertEqual((host, port), ("proxy.example.net", 1080))
            return ["203.0.113.10", "203.0.113.11"]

        env = {
            "EGRESS_SOCKS5_URL": "socks5h://alice:p%40ss%3Asecret@proxy.example.net:1080",
            "EGRESS_INTERNAL_DOMAINS": "postgres,artex",
        }
        cfg, meta, summary = render_config.build_gateway_bundle(
            env,
            nat_rules=SAMPLE_NAT_RULES,
            ip_route_output=SAMPLE_ROUTES,
            resolver=fake_resolver,
        )

        # Credentials must never leak into summary.
        self.assertNotIn("secret", summary)
        self.assertNotIn("alice", summary)
        self.assertIn("socks5h://***@proxy.example.net:1080", summary)

        # DNS: remote-dns over TCP via socks-out + docker-dns only for internal names.
        dns_servers = {s["tag"]: s for s in cfg["dns"]["servers"]}
        self.assertEqual(dns_servers["remote-dns"]["type"], "tcp")
        self.assertEqual(dns_servers["remote-dns"]["server"], "1.1.1.1")
        self.assertEqual(dns_servers["remote-dns"]["detour"], "socks-out")
        self.assertEqual(dns_servers["docker-dns"], {
            "tag": "docker-dns",
            "type": "udp",
            "server": "127.0.0.11",
            "server_port": 56718,
        })
        self.assertEqual(cfg["dns"]["final"], "remote-dns")
        self.assertEqual(cfg["dns"]["strategy"], "ipv4_only")
        self.assertTrue(cfg["dns"]["reverse_mapping"])
        self.assertEqual(
            cfg["dns"]["rules"],
            [{"domain": ["postgres", "artex", "host.docker.internal"], "action": "route", "server": "docker-dns"}],
        )

        # Inbounds: dns-in + tun-in excluding Docker subnets and resolved SOCKS5 IPs.
        inbounds = {i["tag"]: i for i in cfg["inbounds"]}
        self.assertEqual(inbounds["dns-in"]["listen"], "127.0.0.11")
        self.assertEqual(inbounds["dns-in"]["listen_port"], 1053)
        tun = inbounds["tun-in"]
        self.assertEqual(tun["interface_name"], "tun0")
        self.assertEqual(tun["address"], ["198.19.0.1/30"])
        self.assertTrue(tun["auto_route"])
        self.assertTrue(tun["strict_route"])
        self.assertIn("172.18.0.0/16", tun["route_exclude_address"])
        self.assertIn("172.20.0.0/16", tun["route_exclude_address"])
        self.assertIn("203.0.113.10/32", tun["route_exclude_address"])
        self.assertIn("203.0.113.11/32", tun["route_exclude_address"])

        # Outbounds: socks-out uses resolved IP, decoded password, TCP-only default, marked.
        outbounds = {o["tag"]: o for o in cfg["outbounds"]}
        socks = outbounds["socks-out"]
        self.assertEqual(socks["server"], "203.0.113.10")
        self.assertEqual(socks["server_port"], 1080)
        self.assertEqual(socks["username"], "alice")
        self.assertEqual(socks["password"], "p@ss:secret")
        self.assertEqual(socks["network"], "tcp")
        self.assertEqual(socks["routing_mark"], render_config.SOCKS_MARK)

        # Route rules: no HTTP/TLS sniff when bypass_domains is empty (zero banner-grab stall),
        # DNS hijacked, ICMP + non-DNS UDP rejected, final -> socks-out.
        rules = cfg["route"]["rules"]
        self.assertIn({"inbound": ["dns-in"], "action": "hijack-dns"}, rules)
        self.assertIn({"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"}, rules)
        self.assertIn({"network": "icmp", "action": "reject"}, rules)
        self.assertIn({"network": "udp", "action": "reject"}, rules)
        self.assertFalse(any(r.get("action") == "sniff" for r in rules))
        self.assertEqual(cfg["route"]["final"], "socks-out")

        # Firewall metadata.
        self.assertEqual(meta["SOCKS5_IPV4S"], "203.0.113.10 203.0.113.11")
        self.assertEqual(meta["SOCKS5_PORT"], "1080")
        self.assertEqual(meta["HAS_DOCKER_DNS"], "1")
        self.assertEqual(meta["HAS_BYPASS_DOMAINS"], "0")
        self.assertEqual(meta["KILL_SWITCH"], "1")
        self.assertEqual(meta["SOCKS5_UDP"], "0")

    def test_bypass_domains_cidrs_and_udp_mode(self) -> None:
        env = {
            "EGRESS_SOCKS5_URL": "socks5://198.51.100.2:1080",
            "EGRESS_INTERNAL_DOMAINS": "artex",
            "EGRESS_BYPASS_DOMAINS": "api.openai.com, .anthropic.com",
            "EGRESS_BYPASS_CIDRS": "10.10.0.0/16",
            "EGRESS_SOCKS5_UDP": "1",
            "EGRESS_HIJACK_TUN_DNS": "0",
            "EGRESS_DNS_SERVER": "8.8.8.8:53",
        }
        cfg, meta, _ = render_config.build_gateway_bundle(
            env,
            nat_rules=SAMPLE_NAT_RULES,
            ip_route_output=SAMPLE_ROUTES,
        )
        socks = next(o for o in cfg["outbounds"] if o["tag"] == "socks-out")
        self.assertNotIn("network", socks)

        rules = cfg["route"]["rules"]
        self.assertNotIn({"inbound": ["tun-in"], "port": 53, "action": "hijack-dns"}, rules)
        self.assertNotIn({"network": "udp", "action": "reject"}, rules)
        self.assertIn(
            {"domain_suffix": ["api.openai.com", "anthropic.com"], "action": "route", "outbound": "direct"},
            rules,
        )
        self.assertIn({"ip_cidr": ["10.10.0.0/16"], "action": "route", "outbound": "direct"}, rules)
        self.assertTrue(
            any(r.get("action") == "sniff" and r.get("port") == [80, 443] for r in rules),
            "HTTP/TLS sniff should be scoped to 80/443 when bypass_domains is configured",
        )
        self.assertEqual(meta["HAS_BYPASS_DOMAINS"], "1")
        self.assertEqual(meta["BYPASS_CIDRS_V4"], "10.10.0.0/16")
        self.assertEqual(meta["SOCKS5_UDP"], "1")

    def test_tun_auto_avoids_colliding_docker_subnet(self) -> None:
        routes = "198.19.0.0/24 dev eth0 proto kernel scope link src 198.19.0.2\n"
        cfg, _, _ = render_config.build_gateway_bundle(
            {"EGRESS_SOCKS5_URL": "socks5://198.51.100.2:1080"},
            ip_route_output=routes,
        )
        tun = next(i for i in cfg["inbounds"] if i["tag"] == "tun-in")
        self.assertEqual(tun["address"], ["198.19.1.1/30"])

    def test_rejects_invalid_configs_and_loopback_socks(self) -> None:
        bad_cases = [
            {"EGRESS_SOCKS5_URL": ""},
            {"EGRESS_SOCKS5_URL": "http://1.2.3.4:8080"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4"},
            {"EGRESS_SOCKS5_URL": "socks5://127.0.0.1:1080"},
            {"EGRESS_SOCKS5_URL": "socks5://[::1]:1080"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4:1080/extra"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4:1080", "EGRESS_DNS_SERVER": "dns.google"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4:1080", "EGRESS_BYPASS_CIDRS": "0.0.0.0/0"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4:1080", "EGRESS_BYPASS_DOMAINS": "bad domain!"},
            {"EGRESS_SOCKS5_URL": "socks5://1.2.3.4:1080", "EGRESS_KILL_SWITCH": "maybe"},
        ]
        for env in bad_cases:
            with self.assertRaises(render_config.ConfigError, msg=f"expected failure for {env}"):
                render_config.build_gateway_bundle(env)

    def test_cli_writes_secure_files_and_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "sing-box.json"
            meta_path = Path(tmp) / "meta.env"
            nat_path = Path(tmp) / "nat.rules"
            route_path = Path(tmp) / "routes.txt"
            nat_path.write_text(SAMPLE_NAT_RULES, encoding="utf-8")
            route_path.write_text(SAMPLE_ROUTES, encoding="utf-8")

            env = os.environ.copy()
            env["EGRESS_SOCKS5_URL"] = "socks5://u:supersecret@198.51.100.5:1080"
            env["EGRESS_INTERNAL_DOMAINS"] = "postgres,artex"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(EGRESS_DIR / "render_config.py"),
                    "--config-out",
                    str(cfg_path),
                    "--meta-out",
                    str(meta_path),
                    "--nat-file",
                    str(nat_path),
                    "--route-file",
                    str(route_path),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("supersecret", proc.stderr)
            self.assertEqual(os.stat(cfg_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(meta_path).st_mode & 0o777, 0o600)
            parsed = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["route"]["final"], "socks-out")

    def test_docker_compose_override_merges_cleanly_for_artex_and_runners(self) -> None:
        if shutil.which("docker") is None:
            self.skipTest("docker CLI not installed")

        env = os.environ.copy()
        env["POSTGRES_PASSWORD"] = "test-password"
        env["EGRESS_SOCKS5_URL"] = "socks5://198.51.100.10:1080"
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(REPO_ROOT / "docker-compose.yml"),
                "-f",
                str(EGRESS_DIR / "docker-compose.socks5.yml"),
                "--profile",
                "runners",
                "config",
                "--format",
                "json",
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"docker compose config failed:\n{proc.stderr}")
        merged = json.loads(proc.stdout)
        services = merged["services"]

        # artex shares artex-egress-gw netns, keeps cap_drop: [ALL], has no ports/networks of its own.
        artex = services["artex"]
        self.assertEqual(artex["network_mode"], "service:artex-egress-gw")
        self.assertFalse(artex.get("ports"))
        self.assertFalse(artex.get("networks"))
        self.assertEqual(artex["depends_on"]["artex-egress-gw"]["condition"], "service_healthy")
        self.assertEqual(artex["depends_on"]["postgres"]["condition"], "service_healthy")
        self.assertIn("ALL", artex["cap_drop"])

        # artex-egress-gw exposes 8787/8788 and advertises alias `artex` on default + runners.
        artex_gw = services["artex-egress-gw"]
        self.assertEqual(artex_gw["build"]["context"], str(EGRESS_DIR))
        self.assertEqual(artex_gw["networks"]["default"]["aliases"], ["artex"])
        self.assertEqual(artex_gw["networks"]["runners"]["aliases"], ["artex"])
        published = {(p["published"], p["target"]) for p in artex_gw["ports"]}
        self.assertIn(("8787", 8787), published)
        self.assertIn(("8788", 8788), published)

        # runner-egress-gw is strictly isolated on `runners` network only (never `default`/postgres!).
        runner_gw = services["runner-egress-gw"]
        self.assertEqual(runner_gw["build"]["context"], str(EGRESS_DIR))
        self.assertEqual(runner_gw["container_name"], "artex-runner-egress-gw")
        self.assertEqual(list(runner_gw["networks"].keys()), ["runners"])
        self.assertNotIn("default", runner_gw["networks"])
        self.assertEqual(runner_gw["environment"]["EGRESS_INTERNAL_DOMAINS"], "artex")

        # runner-manager waits for runner-egress-gw healthy and spawns sandboxes in its netns.
        rm = services["runner-manager"]
        self.assertEqual(
            rm["environment"]["ARTEX_RUNNER_DOCKER_NETWORK"],
            "container:artex-runner-egress-gw",
        )
        self.assertEqual(rm["depends_on"]["runner-egress-gw"]["condition"], "service_healthy")

        # Main-only mode (without --profile runners) also merges cleanly with only ARTEX_EGRESS_SOCKS5_URL.
        main_env = os.environ.copy()
        main_env.pop("EGRESS_SOCKS5_URL", None)
        main_env.pop("RUNNER_EGRESS_SOCKS5_URL", None)
        main_env["POSTGRES_PASSWORD"] = "test-password"
        main_env["ARTEX_EGRESS_SOCKS5_URL"] = "socks5://198.51.100.10:1080"
        main_proc = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(REPO_ROOT / "docker-compose.yml"),
                "-f",
                str(EGRESS_DIR / "docker-compose.socks5.yml"),
                "config",
                "--format",
                "json",
            ],
            cwd=str(REPO_ROOT),
            env=main_env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(main_proc.returncode, 0, f"main-only compose config failed:\n{main_proc.stderr}")
        main_services = json.loads(main_proc.stdout)["services"]
        self.assertIn("artex-egress-gw", main_services)
        self.assertIn("artex", main_services)
        self.assertNotIn("runner-egress-gw", main_services)
        self.assertNotIn("runner-manager", main_services)


if __name__ == "__main__":
    unittest.main()
