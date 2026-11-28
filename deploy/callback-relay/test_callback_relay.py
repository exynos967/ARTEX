#!/usr/bin/env python3
"""Unit and Compose merge tests for ARTEX optional SSH reverse callback relay."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RELAY_DIR = Path(__file__).resolve().parent
REPO_ROOT = RELAY_DIR.parent.parent
EGRESS_COMPOSE = REPO_ROOT / "deploy" / "egress-proxy" / "docker-compose.socks5.yml"
sys.path.insert(0, str(RELAY_DIR))

import render_relay  # noqa: E402


class TestCallbackRelay(unittest.TestCase):
    def test_files_use_lf_and_entrypoint_valid_posix_syntax(self) -> None:
        for name in ("Dockerfile", "entrypoint.sh", "render_relay.py", "docker-compose.ssh.yml", "README.md"):
            raw = (RELAY_DIR / name).read_bytes()
            self.assertNotIn(b"\r\n", raw, f"{name} must use LF line endings")

        env_example = (REPO_ROOT / ".env.example").read_bytes()
        self.assertNotIn(b"\r\n", env_example, ".env.example must use LF line endings")
        for key in (b"ARTEX_OOB_SERVER=", b"ARTEX_OOB_TOKEN=", b"CALLBACK_SSH_HOST=", b"ARTEX_CALLBACK_PORTS="):
            self.assertIn(key, env_example)

        proc = subprocess.run(
            ["sh", "-n", str(RELAY_DIR / "entrypoint.sh")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"entrypoint.sh syntax error: {proc.stderr}")

    def test_port_mapping_parser_supports_single_range_and_explicit_pairs(self) -> None:
        got = render_relay.parse_port_mappings("20001-20003, 8080:18080, 20002")
        self.assertEqual(
            got,
            [
                render_relay.PortMapping(20001, 20001),
                render_relay.PortMapping(20002, 20002),
                render_relay.PortMapping(20003, 20003),
                render_relay.PortMapping(8080, 18080),
            ],
        )

    def test_port_mapping_rejects_conflicts_and_excessive_ranges(self) -> None:
        for bad in ("", "0", "70000", "20005-20001", "20001-20100", "8080:18080,8080:18081", "1:2:3", "abc"):
            with self.assertRaises(render_relay.RelayConfigError, msg=f"expected failure for {bad!r}"):
                render_relay.parse_port_mappings(bad)

    def test_build_ssh_config_accept_new_and_strict_known_hosts(self) -> None:
        base_env = {
            "CALLBACK_SSH_HOST": "203.0.113.20",
            "CALLBACK_SSH_PORT": "2222",
            "CALLBACK_SSH_USER": "artex-relay",
            "CALLBACK_BIND_ADDRESS": "0.0.0.0",
            "CALLBACK_TARGET_HOST": "artex",
            "CALLBACK_PORTS": "20001-20002,8080:18080",
        }
        cfg, summary = render_relay.build_ssh_config(base_env)
        self.assertIn("HostName 203.0.113.20", cfg)
        self.assertIn("Port 2222", cfg)
        self.assertIn("User artex-relay", cfg)
        self.assertIn("ExitOnForwardFailure yes", cfg)
        self.assertIn("StrictHostKeyChecking accept-new", cfg)
        self.assertIn("RemoteForward 0.0.0.0:20001 artex:20001", cfg)
        self.assertIn("RemoteForward 0.0.0.0:20002 artex:20002", cfg)
        self.assertIn("RemoteForward 0.0.0.0:8080 artex:18080", cfg)
        self.assertIn("strict_host_key=accept-new", summary)

        pinned_env = dict(base_env)
        pinned_env["CALLBACK_SSH_KNOWN_HOSTS"] = "203.0.113.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
        cfg_strict, summary_strict = render_relay.build_ssh_config(pinned_env)
        self.assertIn("StrictHostKeyChecking yes", cfg_strict)
        self.assertIn("strict_host_key=yes", summary_strict)

    def test_rejects_loopback_and_invalid_ssh_options(self) -> None:
        bad_cases = [
            {"CALLBACK_SSH_HOST": "", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "127.0.0.1", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "localhost", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "::1", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "203.0.113.20", "CALLBACK_SSH_USER": "bad user", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "203.0.113.20", "CALLBACK_SSH_STRICT_HOST_KEY": "yes", "CALLBACK_PORTS": "20001"},
            {"CALLBACK_SSH_HOST": "203.0.113.20", "CALLBACK_BIND_ADDRESS": "not-an-ip", "CALLBACK_PORTS": "20001"},
        ]
        for env in bad_cases:
            with self.assertRaises(render_relay.RelayConfigError, msg=f"expected failure for {env}"):
                render_relay.build_ssh_config(env)

    def test_cli_writes_secure_config_and_known_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "ssh_config"
            kh_path = Path(tmp) / "known_hosts"
            env = os.environ.copy()
            env["CALLBACK_SSH_HOST"] = "203.0.113.20"
            env["CALLBACK_PORTS"] = "20001-20002"
            env["CALLBACK_SSH_KNOWN_HOSTS"] = "203.0.113.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(RELAY_DIR / "render_relay.py"),
                    "--config-out",
                    str(cfg_path),
                    "--known-hosts",
                    str(kh_path),
                ],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(os.stat(cfg_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(kh_path).st_mode & 0o777, 0o600)
            self.assertIn("StrictHostKeyChecking yes", cfg_path.read_text(encoding="utf-8"))

    def test_compose_merge_standalone_and_with_socks5_and_runners(self) -> None:
        if shutil.which("docker") is None:
            self.skipTest("docker CLI not installed")

        # 1) Standalone callback relay without SOCKS5 gateway.
        env1 = os.environ.copy()
        env1["POSTGRES_PASSWORD"] = "test-pass"
        env1["CALLBACK_SSH_HOST"] = "203.0.113.20"
        env1["ARTEX_CALLBACK_PUBLIC_HOST"] = "203.0.113.20"
        env1["ARTEX_CALLBACK_PORTS"] = "20001-20003"
        proc1 = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(REPO_ROOT / "docker-compose.yml"),
                "-f",
                str(RELAY_DIR / "docker-compose.ssh.yml"),
                "config",
                "--format",
                "json",
            ],
            cwd=str(REPO_ROOT),
            env=env1,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc1.returncode, 0, f"standalone callback compose failed:\n{proc1.stderr}")
        s1 = json.loads(proc1.stdout)["services"]
        relay1 = s1["artex-callback-relay"]
        self.assertEqual(relay1["build"]["context"], str(RELAY_DIR))
        self.assertTrue(relay1["read_only"])
        self.assertIn("ALL", relay1["cap_drop"])
        self.assertEqual(list(relay1["networks"].keys()), ["default"])
        self.assertEqual(relay1["environment"]["CALLBACK_TARGET_HOST"], "artex")
        self.assertEqual(relay1["environment"]["CALLBACK_PORTS"], "20001-20003")
        self.assertNotIn("runner-callback-relay", s1)

        # 2) Full stack: SOCKS5 transparent gateway + SSH callback relay + Runners + Runner callback relay.
        env2 = dict(env1)
        env2["EGRESS_SOCKS5_URL"] = "socks5://198.51.100.10:1080"
        env2["ARTEX_OOB_SERVER"] = "https://oob.example.com"
        env2["ARTEX_OOB_TOKEN"] = "secret-oob-token"
        env2["ARTEX_RUNNER_CALLBACK_PORTS"] = "20011-20013"
        proc2 = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(REPO_ROOT / "docker-compose.yml"),
                "-f",
                str(EGRESS_COMPOSE),
                "-f",
                str(RELAY_DIR / "docker-compose.ssh.yml"),
                "--profile",
                "runners",
                "--profile",
                "runner-callback",
                "config",
                "--format",
                "json",
            ],
            cwd=str(REPO_ROOT),
            env=env2,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc2.returncode, 0, f"combined compose failed:\n{proc2.stderr}")
        s2 = json.loads(proc2.stdout)["services"]
        self.assertEqual(s2["artex"]["network_mode"], "service:artex-egress-gw")
        self.assertEqual(s2["artex"]["environment"]["ARTEX_OOB_SERVER"], "https://oob.example.com")
        self.assertEqual(s2["artex"]["environment"]["ARTEX_CALLBACK_PORTS"], "20001-20003")
        self.assertEqual(s2["artex"]["environment"]["ARTEX_RUNNER_CALLBACK_PORTS"], "20011-20013")

        runner_relay = s2["runner-callback-relay"]
        self.assertEqual(list(runner_relay["networks"].keys()), ["runners"])
        self.assertNotIn("default", runner_relay["networks"])
        self.assertEqual(runner_relay["environment"]["CALLBACK_TARGET_HOST"], "artex-runner-egress-gw")
        self.assertEqual(runner_relay["environment"]["CALLBACK_PORTS"], "20011-20013")


if __name__ == "__main__":
    unittest.main()
