#!/usr/bin/env python3
"""Unit tests for ARTEX scanner network/resource guardrails (shell shims + nuclei.py)."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

GUARD_DIR = Path(__file__).resolve().parent
REPO_ROOT = GUARD_DIR.parent.parent
NUCLEI_PY = REPO_ROOT / "deploy" / "container-tools" / "nuclei.py"

SHELL_FILES = (
    "guard-common.sh",
    "katana",
    "httpx",
    "ffuf",
    "naabu",
    "sqlmap",
    "nuclei",
)


def find_posix_sh():
    """Find a real POSIX /bin/sh (works on Linux, macOS, and Windows with Git Bash)."""
    if os.name != "nt":
        if Path("/bin/sh").is_file():
            return "/bin/sh"
        return shutil.which("sh")
    candidates = [
        r"C:\Program Files\Git\bin\sh.exe",
        r"C:\Program Files\Git\usr\bin\sh.exe",
        r"C:\Program Files (x86)\Git\bin\sh.exe",
    ]
    for path in candidates:
        if Path(path).is_file():
            return path
    found = shutil.which("sh")
    if found and "windowsapps" not in found.lower() and "system32" not in found.lower():
        return found
    return None


def to_posix_path(path):
    """Convert Windows drive path to Git Bash /c/... path when running under Windows sh.exe."""
    p = str(Path(path).resolve())
    if os.name == "nt" and len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        rest = p[2:].replace("\\", "/")
        return f"/{drive}{rest}"
    return p


POSIX_SH = find_posix_sh()


def load_nuclei_module():
    spec = importlib.util.spec_from_file_location("artex_nuclei_guard", str(NUCLEI_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestGuardFormattingAndSyntax(unittest.TestCase):
    def test_lf_line_endings_and_shebang(self):
        for name in SHELL_FILES:
            path = GUARD_DIR / name
            self.assertTrue(path.is_file(), f"missing {path}")
            data = path.read_bytes()
            self.assertNotIn(b"\r", data, f"{name} must use LF line endings only (found CR)")
            self.assertTrue(data.startswith(b"#!/bin/sh\n"), f"{name} must start with #!/bin/sh")

        nuclei_data = NUCLEI_PY.read_bytes()
        self.assertNotIn(b"\r", nuclei_data, "nuclei.py must use LF line endings only (found CR)")
        self.assertTrue(nuclei_data.startswith(b"#!/usr/bin/env python3\n"))

    @unittest.skipIf(POSIX_SH is None, "POSIX sh not available")
    def test_posix_sh_syntax_check(self):
        for name in SHELL_FILES:
            script = to_posix_path(GUARD_DIR / name)
            res = subprocess.run([POSIX_SH, "-n", script], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"sh -n failed for {name}: {res.stderr}")


class TestNucleiPythonGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_nuclei_module()

    def test_defaults_injected_when_omitted(self):
        got = self.mod.guard_args(["-u", "https://example.com"], env={})
        self.assertEqual(
            got,
            [
                "-disable-update-check",
                "-rl", "25",
                "-c", "10",
                "-bs", "10",
                "-timeout", "10",
                "-retries", "1",
                "-u", "https://example.com",
            ],
        )

    def test_clamps_oversized_space_and_equals_and_double_dash_flags(self):
        got = self.mod.guard_args(
            [
                "-u", "https://example.com",
                "-rl", "200",
                "--concurrency=99",
                "-bulk-size", "50",
                "--timeout=60",
                "-retries", "4",
            ],
            env={},
        )
        self.assertEqual(
            got,
            [
                "-disable-update-check",
                "-u", "https://example.com",
                "-rl", "30",
                "-c=10",
                "-bs", "10",
                "-timeout=10",
                "-retries", "1",
            ],
        )

    def test_preserves_in_range_and_zero_retries(self):
        got = self.mod.guard_args(
            ["-rl", "12", "-c", "4", "-bs", "5", "-timeout", "3", "-retries", "0", "-u", "https://t"],
            env={},
        )
        self.assertEqual(
            got,
            ["-disable-update-check", "-rl", "12", "-c", "4", "-bs", "5", "-timeout", "3", "-retries", "0", "-u", "https://t"],
        )

    def test_zero_and_invalid_values_fallback_to_defaults(self):
        got = self.mod.guard_args(
            ["-rl", "0", "-c", "-3", "-bs", "abc", "-timeout", "0", "-retries", "bad"],
            env={},
        )
        self.assertEqual(
            got,
            ["-disable-update-check", "-rl", "25", "-c", "10", "-bs", "10", "-timeout", "10", "-retries", "1"],
        )

    def test_duplicate_flags_all_clamped(self):
        got = self.mod.guard_args(["-rl", "5", "-rl", "500", "-u", "https://t"], env={})
        self.assertIn("-rl", got)
        # Ensure second occurrence is also clamped to 30
        rl_vals = [got[i + 1] for i in range(len(got) - 1) if got[i] == "-rl"]
        self.assertEqual(rl_vals, ["5", "30"])

    def test_passthrough_version_and_help(self):
        for flag in ("-version", "--version", "-h", "-help", "--help"):
            self.assertEqual(self.mod.guard_args([flag], env={}), [flag])

    def test_explicit_update_omits_disable_update_check(self):
        got = self.mod.guard_args(["-ut"], env={})
        self.assertNotIn("-disable-update-check", got)
        self.assertIn("-ut", got)

    def test_env_overrides_and_lowered_default_cap(self):
        got = self.mod.guard_args(["-rl", "45", "-u", "https://t"], env={"ARTEX_NUCLEI_MAX_RL": "60"})
        self.assertEqual(got[got.index("-rl") + 1], "45")
        got2 = self.mod.guard_args(["-rl", "90", "-u", "https://t"], env={"ARTEX_NUCLEI_MAX_RL": "60"})
        self.assertEqual(got2[got2.index("-rl") + 1], "60")
        # Lowering max below default (25) must also cap injected default
        got3 = self.mod.guard_args(["-u", "https://t"], env={"ARTEX_NUCLEI_MAX_RL": "10"})
        self.assertEqual(got3[got3.index("-rl") + 1], "10")

    def test_end_of_options_double_dash(self):
        got = self.mod.guard_args(["-u", "https://t", "--", "-rl", "999", "-headless"], env={})
        idx = got.index("--")
        self.assertEqual(got[idx:], ["--", "-rl", "999", "-headless"])

    def test_headless_rejected_unless_env_enabled(self):
        import io
        from contextlib import redirect_stderr

        for bad_flag in ("-headless", "--headless", "-headless=true", "-hl", "--hl", "-hl=true"):
            buf = io.StringIO()
            with redirect_stderr(buf):
                with self.assertRaises(SystemExit) as cm:
                    self.mod.guard_args(["-u", "https://t", bad_flag], env={})
            self.assertEqual(cm.exception.code, 2, f"{bad_flag} must exit with code 2")
            self.assertIn("nuclei headless mode is disabled by resource guard; use Browser MCP", buf.getvalue())
            self.assertNotIn("ARTEX_ALLOW_NUCLEI_HEADLESS", buf.getvalue())

        got = self.mod.guard_args(
            ["-u", "https://t", "-headless"],
            env={"ARTEX_ALLOW_NUCLEI_HEADLESS": "1"},
        )
        self.assertIn("-headless", got)

    def test_ensure_templates_config_atomic_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "cfg"
            lock = Path(tmp) / "lock.json"
            lock.write_text(json.dumps({"nuclei-templates": {"version": "10.5.0"}}), encoding="utf-8")
            env = {
                "NUCLEI_CONFIG_DIR": str(cfg_dir),
                "ARTEX_SECURITY_TOOLS_LOCK": str(lock),
            }
            self.mod.ensure_templates_config(env)
            target = cfg_dir / ".templates-config.json"
            self.assertTrue(target.is_file())
            parsed = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(parsed["nuclei-templates-version"], "v10.5.0")


@unittest.skipIf(POSIX_SH is None, "POSIX sh not available")
class TestShellGuardShims(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        self.mock_bin = self.tmp / "mock-real-bin"
        self.mock_bin.write_bytes(
            b"#!/bin/sh\n"
            b"for a in \"$@\"; do\n"
            b"  printf '%s\\0' \"$a\"\n"
            b"done\n"
        )
        self.mock_bin.chmod(self.mock_bin.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def tearDown(self):
        self.tmpdir.cleanup()

    def run_shim(self, tool, args, extra_env=None, use_real_bin=True):
        script = to_posix_path(GUARD_DIR / tool)
        env = os.environ.copy()
        for k in list(env.keys()):
            if k.startswith("ARTEX_") or k.startswith("KATANA_SHIM_"):
                env.pop(k, None)
        if use_real_bin:
            env["ARTEX_TOOL_REAL_BIN"] = to_posix_path(self.mock_bin)
        if extra_env:
            env.update(extra_env)
        res = subprocess.run([POSIX_SH, script, *args], capture_output=True, env=env)
        argv = [part.decode("utf-8") for part in res.stdout.split(b"\0")[:-1]]
        return res.returncode, argv, res.stderr.decode("utf-8", errors="replace")

    def test_katana_defaults_and_clamping_and_jsluice_strip(self):
        rc, argv, err = self.run_shim("katana", ["-u", "https://example.com", "-jsluice"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            argv,
            [
                "-c", "3", "-p", "3", "-d", "2", "-rl", "15", "-timeout", "10",
                "-headless=false", "-jsluice=false", "-u", "https://example.com",
            ],
        )

        rc, argv, err = self.run_shim(
            "katana",
            [
                "-u", "https://example.com/a b?x=1&y=2",
                "-H", "X-Glob: a*b?c",
                "-c", "20",
                "--parallelism=12",
                "-depth", "08",
                "--rate-limit=99999999999999",
                "-timeout=0",
            ],
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            argv,
            [
                "-headless=false",
                "-jsluice=false",
                "-u", "https://example.com/a b?x=1&y=2",
                "-H", "X-Glob: a*b?c",
                "-c", "4",
                "-p=4",
                "-d", "2",
                "-rl=20",
                "-timeout=10",
            ],
        )

        # In-range values must remain unchanged (with explicit -headless=false -jsluice=false)
        rc, argv, err = self.run_shim(
            "katana",
            ["-c", "2", "-p", "1", "-d", "1", "-rl", "5", "-timeout", "4", "-u", "https://t"],
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            argv,
            [
                "-headless=false", "-jsluice=false",
                "-c", "2", "-p", "1", "-d", "1", "-rl", "5", "-timeout", "4", "-u", "https://t",
            ],
        )

        # Allowing jsluice keeps -jsluice and omits -jsluice=false
        rc, argv, err = self.run_shim(
            "katana",
            ["-u", "https://t", "-jsluice"],
            extra_env={"ARTEX_ALLOW_KATANA_JSLUICE": "1"},
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("-jsluice", argv)
        self.assertNotIn("-jsluice=false", argv)
        self.assertIn("-headless=false", argv)

        # Duplicate flag attack: second occurrence must also be clamped
        rc, argv, err = self.run_shim("katana", ["-c", "1", "-c", "50", "-u", "https://t"])
        self.assertEqual(rc, 0, err)
        c_vals = [argv[i + 1] for i in range(len(argv) - 1) if argv[i] == "-c"]
        self.assertEqual(c_vals, ["1", "4"])

    def test_katana_headless_rejected_unless_env_enabled(self):
        expected_msg = "katana headless mode is disabled by resource guard; use Browser MCP"
        for bad_flag in ("-headless", "--headless", "-headless=true", "-hl", "--hl", "-system-chrome", "--system-chrome"):
            rc, argv, err = self.run_shim("katana", ["-u", "https://example.com", bad_flag])
            self.assertEqual(rc, 2, f"{bad_flag} should exit 2")
            self.assertIn(expected_msg, err)
            self.assertNotIn("ARTEX_ALLOW_KATANA_HEADLESS", err)
            self.assertEqual(argv, [])

        rc, argv, err = self.run_shim(
            "katana",
            ["-u", "https://example.com", "-headless"],
            extra_env={"ARTEX_ALLOW_KATANA_HEADLESS": "1"},
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("-headless", argv)
        self.assertNotIn("-headless=false", argv)

    def test_katana_passthrough_and_env_override(self):
        for flag in ("-version", "-h", "-help", "--help"):
            rc, argv, err = self.run_shim("katana", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

        rc, argv, err = self.run_shim(
            "katana",
            ["-rl", "50", "-u", "https://t"],
            extra_env={"ARTEX_KATANA_MAX_RL": "60"},
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-rl") + 1], "50")

        rc, argv, err = self.run_shim(
            "katana",
            ["-u", "https://t"],
            extra_env={"ARTEX_KATANA_MAX_RL": "7"},
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-rl") + 1], "7")

    def test_httpx_defaults_clamping_passthrough_override(self):
        rc, argv, err = self.run_shim("httpx", ["-u", "https://t"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rl", "40", "-t", "15", "-timeout", "10", "-retries", "1", "-u", "https://t"])

        rc, argv, err = self.run_shim(
            "httpx",
            ["-rate-limit", "500", "--threads=100", "-timeout=30", "-retries=0", "-u", "https://t"],
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rl", "50", "-t=20", "-timeout=10", "-retries=0", "-u", "https://t"])

        for flag in ("-version", "-h", "-help"):
            rc, argv, err = self.run_shim("httpx", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

        rc, argv, err = self.run_shim("httpx", ["-rl", "80"], extra_env={"ARTEX_HTTPX_MAX_RL": "90"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-rl") + 1], "80")

    def test_ffuf_defaults_clamping_zero_rate_and_passthrough(self):
        rc, argv, err = self.run_shim("ffuf", ["-u", "https://t/FUZZ", "-w", "wl.txt"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-t", "10", "-rate", "30", "-timeout", "10", "-u", "https://t/FUZZ", "-w", "wl.txt"])

        # -rate 0 means unlimited in ffuf -> must be clamped back to default 30
        rc, argv, err = self.run_shim("ffuf", ["-t", "64", "-rate", "0", "-timeout=99"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-t", "16", "-rate", "30", "-timeout=10"])

        for flag in ("-V", "-h"):
            rc, argv, err = self.run_shim("ffuf", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

        rc, argv, err = self.run_shim("ffuf", ["-rate", "70"], extra_env={"ARTEX_FFUF_MAX_RATE": "80"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-rate") + 1], "70")

    def test_naabu_defaults_clamping_and_passthrough(self):
        rc, argv, err = self.run_shim("naabu", ["-host", "example.com"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rate", "200", "-c", "10", "-timeout", "5000ms", "-retries", "1", "-host", "example.com"])

        # Valid sub-second / second / bare-seconds inputs keep explicit ms unit
        for raw, want in (
            ("500ms", "500ms"),
            ("2s", "2000ms"),
            ("1.5s", "1500ms"),
            ("3", "3000ms"),
            ("10", "5000ms"),
            ("30s", "5000ms"),
            ("1m", "5000ms"),
            ("30000", "5000ms"),
            ("0", "5000ms"),
            ("0ms", "5000ms"),
            ("invalid", "5000ms"),
        ):
            rc, argv, err = self.run_shim("naabu", ["-timeout", raw, "-host", "example.com"])
            self.assertEqual(rc, 0, f"raw={raw}: {err}")
            self.assertEqual(argv[argv.index("-timeout") + 1], want, f"raw={raw} -> {argv}")

        rc, argv, err = self.run_shim("naabu", ["-rate=10000", "-c", "50", "-timeout=30s", "-retries", "0"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rate=300", "-c", "15", "-timeout=5000ms", "-retries", "0"])

        # Env override accepts explicit s/ms or bare seconds/ms cleanly
        rc, argv, err = self.run_shim("naabu", ["-host", "t"], extra_env={"ARTEX_NAABU_MAX_TIMEOUT": "2s"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-timeout") + 1], "2000ms")

        rc, argv, err = self.run_shim("naabu", ["-timeout", "5s"], extra_env={"ARTEX_NAABU_MAX_TIMEOUT": "3000ms"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-timeout") + 1], "3000ms")

        rc, argv, err = self.run_shim("naabu", ["-timeout", "8s"], extra_env={"ARTEX_NAABU_MAX_TIMEOUT": "10"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv[argv.index("-timeout") + 1], "8000ms")

        # UID 0 without CAP_NET_RAW (simulated via ARTEX_NAABU_NO_NET_RAW=1) injects -s c when omitted
        rc, argv, err = self.run_shim(
            "naabu",
            ["-host", "example.com"],
            extra_env={"ARTEX_NAABU_NO_NET_RAW": "1"},
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            argv,
            ["-rate", "200", "-c", "10", "-timeout", "5000ms", "-retries", "1", "-s", "c", "-host", "example.com"],
        )

        # Explicit -s or -scan-type is preserved without duplicate injection
        for scan_args in (["-s", "c"], ["-scan-type=s"]):
            rc, argv, err = self.run_shim(
                "naabu",
                [*scan_args, "-host", "example.com"],
                extra_env={"ARTEX_NAABU_NO_NET_RAW": "1"},
            )
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv.count("-s") + sum(1 for a in argv if a.startswith("-scan-type")), 1, argv)

        for flag in ("-version", "-h"):
            rc, argv, err = self.run_shim("naabu", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

    def test_sqlmap_defaults_clamping_decimal_and_passthrough(self):
        rc, argv, err = self.run_shim("sqlmap", ["-u", "https://t/?id=1", "--batch"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["--threads=3", "--timeout=15", "--retries=1", "-u", "https://t/?id=1", "--batch"])

        rc, argv, err = self.run_shim(
            "sqlmap",
            ["--threads", "10", "--timeout=5.5", "--retries=3", "-t", "/tmp/traffic.log"],
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["--threads=4", "--timeout=5.5", "--retries=1", "-t", "/tmp/traffic.log"])

        rc, argv, err = self.run_shim("sqlmap", ["--timeout=15.5", "--threads=2", "--retries=0"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["--timeout=15", "--threads=2", "--retries=0"])

        for flag in ("--version", "-h", "-hh", "--help"):
            rc, argv, err = self.run_shim("sqlmap", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

    def test_nuclei_shell_shim_parity(self):
        rc, argv, err = self.run_shim("nuclei", ["-u", "https://t"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rl", "25", "-c", "10", "-bs", "10", "-timeout", "10", "-retries", "1", "-u", "https://t"])

        rc, argv, err = self.run_shim(
            "nuclei",
            ["--rate-limit=100", "-concurrency", "50", "-bs=25", "-timeout=30", "-retries", "4"],
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-rl=30", "-c", "10", "-bs=10", "-timeout=10", "-retries", "1"])

        for flag in ("-version", "-h", "-help"):
            rc, argv, err = self.run_shim("nuclei", [flag])
            self.assertEqual(rc, 0, err)
            self.assertEqual(argv, [flag])

        for bad_flag in ("-headless", "--headless", "-headless=true", "-hl", "--hl", "-hl=true"):
            rc, argv, err = self.run_shim("nuclei", ["-u", "https://t", bad_flag])
            self.assertEqual(rc, 2, f"nuclei {bad_flag} should exit 2")
            self.assertIn("nuclei headless mode is disabled by resource guard; use Browser MCP", err)
            self.assertNotIn("ARTEX_ALLOW_NUCLEI_HEADLESS", err)
            self.assertEqual(argv, [])

        rc, argv, err = self.run_shim(
            "nuclei",
            ["-u", "https://t", "-headless"],
            extra_env={"ARTEX_ALLOW_NUCLEI_HEADLESS": "1"},
        )
        self.assertEqual(rc, 0, err)
        self.assertIn("-headless", argv)

    def test_path_fallback_skips_self_without_loop(self):
        # Put GUARD_DIR first in PATH, followed by a fake real binary directory.
        real_dir = self.tmp / "real-bin"
        real_dir.mkdir()
        fake_ffuf = real_dir / "ffuf"
        shutil.copyfile(self.mock_bin, fake_ffuf)
        fake_ffuf.chmod(fake_ffuf.stat().st_mode | stat.S_IXUSR)

        posix_path = f"{to_posix_path(GUARD_DIR)}:{to_posix_path(real_dir)}:/usr/bin:/bin"
        rc, argv, err = self.run_shim(
            "ffuf",
            ["-u", "https://t/FUZZ"],
            extra_env={"PATH": posix_path},
            use_real_bin=False,
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(argv, ["-t", "10", "-rate", "30", "-timeout", "10", "-u", "https://t/FUZZ"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
