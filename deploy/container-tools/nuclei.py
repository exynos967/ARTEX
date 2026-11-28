#!/usr/bin/env python3
"""Use bundled templates with a fresh non-root HOME and enforce scanner network guardrails."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile

PASSTHROUGH_FLAGS = frozenset({"-version", "--version", "-h", "-help", "--help"})
HEADLESS_FLAGS = frozenset({"-headless", "--headless", "-hl", "--hl"})
DEBUG_LOG_FLAGS = frozenset({
    "-elog", "--elog", "-error-log", "--error-log",
    "-trace-log", "--trace-log",
})
UPDATE_FLAGS = frozenset({
    "-ut", "--ut", "-update-templates", "--update-templates",
    "-up", "--up", "-update", "--update",
})
OOB_SERVER_FLAGS = frozenset({"-iserver", "--iserver", "-interactsh-server", "--interactsh-server"})
OOB_TOKEN_FLAGS = frozenset({"-itoken", "--itoken", "-interactsh-token", "--interactsh-token"})
OOB_DISABLE_FLAGS = frozenset({"-ni", "--ni", "-no-interactsh", "--no-interactsh"})

# (canonical_flag, aliases, env_var, default_max, default_inject, min_val)
GUARD_RULES = (
    ("-rl", ("-rl", "--rl", "-rate-limit", "--rate-limit"), "ARTEX_NUCLEI_MAX_RL", 30, 25, 1),
    ("-c", ("-c", "--c", "-concurrency", "--concurrency"), "ARTEX_NUCLEI_MAX_CONCURRENCY", 10, 10, 1),
    ("-bs", ("-bs", "--bs", "-bulk-size", "--bulk-size"), "ARTEX_NUCLEI_MAX_BULK_SIZE", 10, 10, 1),
    ("-timeout", ("-timeout", "--timeout"), "ARTEX_NUCLEI_MAX_TIMEOUT", 10, 10, 1),
    ("-retries", ("-retries", "--retries"), "ARTEX_NUCLEI_MAX_RETRIES", 1, 1, 0),
)


def _parse_int(raw):
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or not s.isascii() or not s.isdigit():
        return None
    return int(s)


def _env_max(env, key, default_max, min_val):
    val = _parse_int(env.get(key))
    if val is None or val < min_val or val > 10**9:
        return default_max
    return val


def _clamp_int(raw, max_val, default_val, min_val):
    val = _parse_int(raw)
    if val is None or val < min_val:
        return default_val
    if val > max_val:
        return max_val
    return val


def guard_args(argv, env=None):
    """Rewrite nuclei argv to enforce concurrency/rate/timeout/retry ceilings."""
    if env is None:
        env = os.environ
    args = list(argv)

    # Pass through help/version checks untouched before any `--`.
    for arg in args:
        if arg == "--":
            break
        if arg in PASSTHROUGH_FLAGS:
            return args

    # Build lookup from every accepted flag spelling to its active rule.
    alias_map = {}
    resolved = []
    for canonical, aliases, env_key, def_max, def_inject, min_val in GUARD_RULES:
        max_val = _env_max(env, env_key, def_max, min_val)
        eff_def = min(def_inject, max_val)
        rule = (canonical, max_val, eff_def, min_val)
        resolved.append(rule)
        for alias in aliases:
            alias_map[alias] = rule

    allow_headless = env.get("ARTEX_ALLOW_NUCLEI_HEADLESS") == "1"
    allow_debug_log = env.get("ARTEX_ALLOW_TOOL_DEBUG_LOG") == "1"
    seen = set()
    rewritten = []
    explicit_update = False
    seen_oob_server = False
    seen_oob_token = False
    seen_oob_disable = False
    i = 0
    n = len(args)
    while i < n:
        arg = args[i]
        if arg == "--":
            rewritten.extend(args[i:])
            break
        head = arg.split("=", 1)[0]
        if head in HEADLESS_FLAGS and not allow_headless:
            sys.stderr.write("nuclei headless mode is disabled by resource guard; use Browser MCP\n")
            raise SystemExit(2)
        if head in DEBUG_LOG_FLAGS and not allow_debug_log:
            sys.stderr.write("nuclei error/trace file logging is disabled by resource guard to prevent unbounded disk growth\n")
            raise SystemExit(2)
        if head in UPDATE_FLAGS:
            explicit_update = True
        if head in OOB_SERVER_FLAGS:
            seen_oob_server = True
        elif head in OOB_TOKEN_FLAGS:
            seen_oob_token = True
        elif head in OOB_DISABLE_FLAGS:
            seen_oob_disable = True
        if "=" in arg:
            flag, val = arg.split("=", 1)
            rule = alias_map.get(flag)
            if rule is not None:
                canonical, max_val, eff_def, min_val = rule
                clamped = _clamp_int(val, max_val, eff_def, min_val)
                rewritten.append(f"{canonical}={clamped}")
                seen.add(canonical)
                i += 1
                continue
        else:
            rule = alias_map.get(arg)
            if rule is not None:
                canonical, max_val, eff_def, min_val = rule
                if i + 1 < n:
                    clamped = _clamp_int(args[i + 1], max_val, eff_def, min_val)
                    rewritten.extend([canonical, str(clamped)])
                    seen.add(canonical)
                    i += 2
                    continue
                rewritten.append(arg)
                i += 1
                continue
        rewritten.append(arg)
        i += 1

    injected = []
    if not explicit_update:
        injected.append("-disable-update-check")
    if not seen_oob_disable and not seen_oob_server:
        oob_server = str(env.get("ARTEX_OOB_SERVER") or "").strip()
        oob_token = str(env.get("ARTEX_OOB_TOKEN") or "").strip()
        disable_public = str(env.get("ARTEX_OOB_DISABLE_PUBLIC") or "").strip().lower() in {"1", "true", "yes"}
        if oob_server:
            injected.extend(["-iserver", oob_server])
            if oob_token and not seen_oob_token:
                injected.extend(["-itoken", oob_token])
        elif disable_public:
            injected.append("-ni")
    for canonical, _max_val, eff_def, _min_val in resolved:
        if canonical not in seen:
            injected.extend([canonical, str(eff_def)])
    return injected + rewritten


def ensure_templates_config(env=None):
    """Initialize bundled nuclei templates config atomically on first run."""
    if env is None:
        env = os.environ
    config = Path(env.setdefault("NUCLEI_CONFIG_DIR", str(Path.home() / ".config/nuclei")))
    config.mkdir(parents=True, exist_ok=True)
    target = config / ".templates-config.json"
    if target.exists():
        return
    lock_path = Path(env.get("ARTEX_SECURITY_TOOLS_LOCK", "/opt/artex-tools/security-tools.lock.json"))
    if not lock_path.is_file():
        return
    version = json.loads(lock_path.read_text())["nuclei-templates"]["version"]
    # Link a complete temporary file into place atomically. Parallel calls in the
    # same sandbox cannot observe a partially written first-run configuration.
    with tempfile.NamedTemporaryFile(mode="w", dir=config, delete=False) as stream:
        json.dump({"nuclei-templates-directory": "/opt/nuclei-templates", "nuclei-templates-version": "v" + version}, stream)
        temporary = stream.name
    try:
        try:
            os.link(temporary, target)
        except FileExistsError:
            pass
    finally:
        os.unlink(temporary)


def _redact_audit_args(final_args):
    redacted = []
    redact_next = False
    for arg in final_args:
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue
        head = arg.split("=", 1)[0]
        if head in OOB_TOKEN_FLAGS:
            if "=" in arg:
                redacted.append(f"{head}=[REDACTED]")
            else:
                redacted.append(arg)
                redact_next = True
            continue
        redacted.append(arg)
    return redacted


def _audit_log(log_path, final_args):
    if not log_path:
        return
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(log_path, "a", encoding="utf-8") as stream:
            stream.write(f"{ts}  [nuclei] {' '.join(_redact_audit_args(final_args))}\n")
    except OSError:
        pass


def main():
    ensure_templates_config(os.environ)
    final_args = guard_args(sys.argv[1:], os.environ)
    if os.environ.get("ARTEX_TOOL_GUARD_DEBUG"):
        print("nuclei.shim argv:", " ".join(final_args))
        return
    _audit_log(os.environ.get("ARTEX_TOOL_GUARD_LOG", ""), final_args)
    binary = os.environ.get("ARTEX_TOOL_REAL_BIN") or "/usr/local/libexec/artex/nuclei"
    os.execv(binary, [binary, *final_args])


if __name__ == "__main__":
    main()
