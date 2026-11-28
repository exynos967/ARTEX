#!/usr/bin/env python3
"""Render an OpenSSH client config for ARTEX reverse-tunnel callback relay.

Stdlib-only so the exact same validation and rendering logic runs inside the
unprivileged Alpine relay container and in local unit tests.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from dataclasses import dataclass
from typing import Mapping

MAX_FORWARD_PORTS = 64

_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_SAFE_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
_VALID_STRICT_MODES = {"yes", "accept-new", "no"}


class RelayConfigError(ValueError):
    """Raised when SSH callback relay configuration is invalid."""


@dataclass(frozen=True)
class PortMapping:
    remote_port: int
    local_port: int


def _parse_int(raw: str, name: str, minimum: int, maximum: int) -> int:
    text = (raw or "").strip()
    if not text or not text.isdigit():
        raise RelayConfigError(f"{name} must be an integer in [{minimum}, {maximum}], got {raw!r}")
    val = int(text, 10)
    if not (minimum <= val <= maximum):
        raise RelayConfigError(f"{name} out of range [{minimum}, {maximum}]: {val}")
    return val


def _validate_host(raw: str, name: str, *, allow_loopback: bool = False) -> str:
    text = (raw or "").strip()
    if not text:
        raise RelayConfigError(f"{name} is required")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        if text.lower() in {"localhost", "localhost.localdomain"} and not allow_loopback:
            raise RelayConfigError(
                f"{name} must point to an external edge VPS, not loopback ({text!r})"
            )
        if not _SAFE_HOST_RE.match(text):
            raise RelayConfigError(f"{name} contains invalid host characters: {raw!r}")
        return text
    if not allow_loopback and (ip.is_loopback or ip.is_unspecified):
        raise RelayConfigError(
            f"{name} must point to an external edge VPS, not loopback/unspecified ({ip})"
        )
    return str(ip)


def _validate_bind_address(raw: str) -> str:
    text = (raw or "").strip() or "0.0.0.0"
    if text in {"0.0.0.0", "::", "*"}:
        return text
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise RelayConfigError(
            f"CALLBACK_BIND_ADDRESS must be 0.0.0.0, ::, *, or a valid IP address, got {raw!r}"
        ) from exc
    return str(ip)


def parse_port_mappings(raw: str, env_name: str = "CALLBACK_PORTS") -> list[PortMapping]:
    """Parse specs like '20001-20005', '20001,8080:18080', or combinations."""
    text = (raw or "").strip()
    if not text:
        raise RelayConfigError(f"{env_name} is required (e.g. 20001-20005 or 20001,8080:18080)")

    mappings: list[PortMapping] = []
    seen_remote: dict[int, int] = {}

    def add_pair(remote_p: int, local_p: int) -> None:
        if remote_p in seen_remote:
            if seen_remote[remote_p] != local_p:
                raise RelayConfigError(
                    f"{env_name} maps remote port {remote_p} to conflicting local ports "
                    f"({seen_remote[remote_p]} vs {local_p})"
                )
            return
        if len(mappings) >= MAX_FORWARD_PORTS:
            raise RelayConfigError(
                f"{env_name} exceeds maximum of {MAX_FORWARD_PORTS} forwarded ports"
            )
        seen_remote[remote_p] = local_p
        mappings.append(PortMapping(remote_port=remote_p, local_port=local_p))

    for token in re.split(r"[\s,]+", text):
        part = token.strip()
        if not part:
            continue
        if ":" in part:
            pieces = part.split(":")
            if len(pieces) != 2:
                raise RelayConfigError(f"{env_name} has invalid remote:local spec: {part!r}")
            rport = _parse_int(pieces[0], env_name, 1, 65535)
            lport = _parse_int(pieces[1], env_name, 1, 65535)
            add_pair(rport, lport)
        elif "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2:
                raise RelayConfigError(f"{env_name} has invalid range spec: {part!r}")
            start = _parse_int(pieces[0], env_name, 1, 65535)
            end = _parse_int(pieces[1], env_name, 1, 65535)
            if end < start:
                raise RelayConfigError(f"{env_name} range end < start: {part!r}")
            if (end - start + 1) > MAX_FORWARD_PORTS:
                raise RelayConfigError(
                    f"{env_name} range {part!r} exceeds maximum of {MAX_FORWARD_PORTS} ports"
                )
            for port in range(start, end + 1):
                add_pair(port, port)
        else:
            port = _parse_int(part, env_name, 1, 65535)
            add_pair(port, port)

    if not mappings:
        raise RelayConfigError(f"{env_name} produced no valid port mappings")
    return mappings


def _format_ssh_addr(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def build_ssh_config(
    env: Mapping[str, str],
    *,
    key_file: str = "/tmp/id_key",
    known_hosts_file: str = "/tmp/known_hosts",
    control_path: str = "/tmp/ssh-relay.ctl",
    has_pinned_known_hosts: bool = False,
) -> tuple[str, str]:
    """Build (ssh_config_text, summary_line)."""
    ssh_host = _validate_host(env.get("CALLBACK_SSH_HOST", ""), "CALLBACK_SSH_HOST")
    ssh_port = _parse_int(env.get("CALLBACK_SSH_PORT", "22") or "22", "CALLBACK_SSH_PORT", 1, 65535)
    ssh_user = (env.get("CALLBACK_SSH_USER", "artex-relay") or "artex-relay").strip()
    if not _SAFE_USER_RE.match(ssh_user):
        raise RelayConfigError(f"CALLBACK_SSH_USER contains invalid characters: {ssh_user!r}")

    bind_addr = _validate_bind_address(env.get("CALLBACK_BIND_ADDRESS", "0.0.0.0"))
    target_host = _validate_host(
        env.get("CALLBACK_TARGET_HOST", "artex") or "artex",
        "CALLBACK_TARGET_HOST",
        allow_loopback=True,
    )
    mappings = parse_port_mappings(env.get("CALLBACK_PORTS", ""), "CALLBACK_PORTS")

    alive_interval = _parse_int(
        env.get("CALLBACK_SERVER_ALIVE_INTERVAL", "15") or "15",
        "CALLBACK_SERVER_ALIVE_INTERVAL",
        5,
        300,
    )
    alive_count = _parse_int(
        env.get("CALLBACK_SERVER_ALIVE_COUNT_MAX", "3") or "3",
        "CALLBACK_SERVER_ALIVE_COUNT_MAX",
        1,
        20,
    )

    pinned_env = (env.get("CALLBACK_SSH_KNOWN_HOSTS") or "").strip()
    has_known_hosts = has_pinned_known_hosts or bool(pinned_env)
    strict_mode = (env.get("CALLBACK_SSH_STRICT_HOST_KEY") or "").strip().lower()
    if not strict_mode:
        strict_mode = "yes" if has_known_hosts else "accept-new"
    if strict_mode not in _VALID_STRICT_MODES:
        raise RelayConfigError(
            f"CALLBACK_SSH_STRICT_HOST_KEY must be one of {sorted(_VALID_STRICT_MODES)}, got {strict_mode!r}"
        )
    if strict_mode == "yes" and not has_known_hosts:
        raise RelayConfigError(
            "CALLBACK_SSH_STRICT_HOST_KEY=yes requires CALLBACK_SSH_KNOWN_HOSTS (e.g. output of ssh-keyscan)"
        )

    lines = [
        "Host relay",
        f"  HostName {ssh_host}",
        f"  Port {ssh_port}",
        f"  User {ssh_user}",
        f"  IdentityFile {key_file}",
        "  IdentitiesOnly yes",
        "  BatchMode yes",
        "  ExitOnForwardFailure yes",
        "  ForwardAgent no",
        "  ForwardX11 no",
        "  RequestTTY no",
        f"  ServerAliveInterval {alive_interval}",
        f"  ServerAliveCountMax {alive_count}",
        "  TCPKeepAlive yes",
        "  ControlMaster yes",
        f"  ControlPath {control_path}",
        "  ControlPersist no",
        f"  StrictHostKeyChecking {strict_mode}",
        f"  UserKnownHostsFile {known_hosts_file}",
    ]

    bind_fmt = _format_ssh_addr(bind_addr)
    target_fmt = _format_ssh_addr(target_host)
    for m in mappings:
        lines.append(f"  RemoteForward {bind_fmt}:{m.remote_port} {target_fmt}:{m.local_port}")

    port_preview = ",".join(
        f"{m.remote_port}" if m.remote_port == m.local_port else f"{m.remote_port}->{m.local_port}"
        for m in mappings
    )
    summary = (
        f"edge={ssh_user}@{_format_ssh_addr(ssh_host)}:{ssh_port} "
        f"bind={bind_fmt} target={target_fmt} ports=[{port_preview}] "
        f"strict_host_key={strict_mode}"
    )
    return "\n".join(lines) + "\n", summary


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
    parser = argparse.ArgumentParser(description="Render ARTEX SSH callback relay OpenSSH config")
    parser.add_argument("--config-out", default="/tmp/ssh_relay_config")
    parser.add_argument("--key-file", default="/tmp/id_key")
    parser.add_argument("--known-hosts", default="/tmp/known_hosts")
    parser.add_argument("--control-path", default="/tmp/ssh-relay.ctl")
    args = parser.parse_args(argv)

    pinned_inline = (os.environ.get("CALLBACK_SSH_KNOWN_HOSTS") or "").strip()
    if pinned_inline:
        _write_secure(args.known_hosts, pinned_inline + "\n")
    elif not os.path.exists(args.known_hosts):
        _write_secure(args.known_hosts, "")

    has_pinned = bool(pinned_inline) or (
        os.path.isfile(args.known_hosts) and os.path.getsize(args.known_hosts) > 0
    )

    try:
        config_text, summary = build_ssh_config(
            os.environ,
            key_file=args.key_file,
            known_hosts_file=args.known_hosts,
            control_path=args.control_path,
            has_pinned_known_hosts=has_pinned,
        )
    except RelayConfigError as exc:
        sys.stderr.write(f"[callback-relay] configuration error: {exc}\n")
        return 2

    _write_secure(args.config_out, config_text)
    sys.stderr.write(f"[callback-relay] configured: {summary}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
