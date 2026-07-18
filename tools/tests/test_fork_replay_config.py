#!/usr/bin/env python3
"""PR 105 — workspace watch config smoke tests (no real RPC)."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fork-replay.sh"

# PR 212 — fork-replay.sh needs real `jq` to parse the mocked `cast tx` JSON.
# Tests that run through the full pipeline are gated on jq availability; the
# reject-before-network / help / silent-missing-config tests do not reach the
# jq-dependent code path and stay active even without jq.
HAS_JQ = shutil.which("jq") is not None
REQUIRES_JQ = unittest.skipUnless(
    HAS_JQ, "jq not present — fork-replay.sh needs it to parse cast JSON"
)
TX = "0x" + "ab" * 32
TOKEN = "0x2222222222222222222222222222222222222222"
HOLDER_A = "0x3333333333333333333333333333333333333333"
HOLDER_B = "0x4444444444444444444444444444444444444444"
NATIVE_ADDR = "0x5555555555555555555555555555555555555555"


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _fake_cast_body(post_flag: Path) -> str:
    """A permissive fake cast that responds to every expected subcommand."""
    return f"""
        #!/usr/bin/env bash
        set -euo pipefail
        cmd="${{1:-}}"
        shift || true
        case "$cmd" in
          tx)
            echo '{{"blockNumber":"0x65","from":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to":"0x1111111111111111111111111111111111111111"}}'
            ;;
          to-dec)
            echo 101
            ;;
          rpc)
            echo '{{"trace":"ok"}}'
            ;;
          block-number)
            echo 100
            ;;
          keccak)
            echo 0xhash
            ;;
          code)
            echo 0x6000
            ;;
          storage)
            echo 0x00
            ;;
          balance)
            if [ -f "{post_flag}" ]; then echo 150; else echo 100; fi
            ;;
          call)
            if [ -f "{post_flag}" ]; then echo "75 [0x4b]"; else echo "50 [0x32]"; fi
            ;;
          run)
            touch "{post_flag}"
            echo "replay ok"
            ;;
          *)
            echo "unexpected cast command: $cmd" >&2
            exit 9
            ;;
        esac
        """


def _setup_fake_bin(tmp_path: Path) -> tuple[Path, dict]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    post_flag = tmp_path / "post.flag"
    write_executable(
        fake_bin / "anvil",
        """
        #!/usr/bin/env bash
        sleep 60
        """,
    )
    write_executable(fake_bin / "cast", _fake_cast_body(post_flag))
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    return fake_bin, env


def _setup_tripwire_bin(tmp_path: Path) -> tuple[Path, Path, dict]:
    """Install cast/anvil binaries that must NEVER be invoked.

    Returns (fake_bin, call_log, env). If either binary runs, call_log is created.
    """
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    call_log = tmp_path / "cast_calls.log"
    write_executable(
        fake_bin / "cast",
        f"""
        #!/usr/bin/env bash
        echo "CAST CALLED: $*" >> "{call_log}"
        echo "cast should not have been invoked" >&2
        exit 77
        """,
    )
    write_executable(
        fake_bin / "anvil",
        f"""
        #!/usr/bin/env bash
        echo "ANVIL CALLED: $*" >> "{call_log}"
        echo "anvil should not have been invoked" >&2
        exit 77
        """,
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    return fake_bin, call_log, env


class ForkReplayConfigTest(unittest.TestCase):
    # ------------------------------------------------------------------
    # Help output advertises the new flags and default path.
    # ------------------------------------------------------------------
    def test_help_mentions_config_flags(self) -> None:
        proc = subprocess.run(
            ["bash", str(TOOL), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--watch-config", proc.stdout)
        self.assertIn("--no-watch-config", proc.stdout)
        self.assertIn("fork_replay.watch.json", proc.stdout)

    # ------------------------------------------------------------------
    # 1. Config-only: one native + one erc20 entry becomes two targeted rows.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_config_only_run_emits_two_targeted_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            cfg = {
                "schema_version": 1,
                "native_watches": [
                    {"address": NATIVE_ADDR, "label": "victim"},
                ],
                "erc20_watches": [
                    {"token": TOKEN, "holder": HOLDER_A, "label": "protocol"},
                ],
            }
            (cfg_dir / "fork_replay.watch.json").write_text(json.dumps(cfg))

            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("loading watch config", proc.stderr)

            deltas = json.loads((out_dir / f"{TX}_deltas.json").read_text())
            targeted = deltas["targeted_watches"]
            self.assertEqual(len(targeted), 2)
            labels = {row["label"] for row in targeted}
            self.assertEqual(labels, {"victim", "protocol"})

    # ------------------------------------------------------------------
    # 2. CLI-only with no config file: existing pipeline keeps working.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_cli_only_no_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            # NOTE: no monitoring/ directory at all.
            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--watch-erc20", f"{TOKEN}:{HOLDER_A}=attacker",
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("loading watch config", proc.stderr)
            deltas = json.loads((out_dir / f"{TX}_deltas.json").read_text())
            targeted = deltas["targeted_watches"]
            self.assertEqual(len(targeted), 1)
            self.assertEqual(targeted[0]["label"], "attacker")

    # ------------------------------------------------------------------
    # 3. Config + CLI add distinct specs: both labels preserved.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_config_plus_cli_additive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            cfg = {
                "schema_version": 1,
                "erc20_watches": [
                    {"token": TOKEN, "holder": HOLDER_A, "label": "victim"},
                ],
            }
            (cfg_dir / "fork_replay.watch.json").write_text(json.dumps(cfg))

            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--watch-erc20", f"{TOKEN}:{HOLDER_B}=attacker",
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            deltas = json.loads((out_dir / f"{TX}_deltas.json").read_text())
            targeted = deltas["targeted_watches"]
            self.assertEqual(len(targeted), 2)
            labels = {row["label"] for row in targeted}
            self.assertEqual(labels, {"victim", "attacker"})

    # ------------------------------------------------------------------
    # 4. Dedup across config + CLI: config label wins on conflict.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_config_label_wins_on_dedup_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            cfg = {
                "schema_version": 1,
                "erc20_watches": [
                    {"token": TOKEN, "holder": HOLDER_A, "label": "config-label"},
                ],
            }
            (cfg_dir / "fork_replay.watch.json").write_text(json.dumps(cfg))

            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--watch-erc20", f"{TOKEN}:{HOLDER_A}=cli-label",
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            # The "duplicate ... ignored" note is emitted by the dedup branch.
            self.assertIn("duplicate targeted watch", proc.stderr)
            deltas = json.loads((out_dir / f"{TX}_deltas.json").read_text())
            targeted = deltas["targeted_watches"]
            self.assertEqual(len(targeted), 1)
            self.assertEqual(targeted[0]["label"], "config-label")

    # ------------------------------------------------------------------
    # 5. Invalid JSON → nonzero exit with clear error BEFORE any cast call.
    # ------------------------------------------------------------------
    def test_invalid_config_exits_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            (cfg_dir / "fork_replay.watch.json").write_text("{this is not valid json")

            out_dir = tmp_path / "fork_replay"
            _, call_log, env = _setup_tripwire_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("config error", proc.stderr)
            self.assertFalse(call_log.exists(), "cast/anvil invoked despite invalid config")

    def test_unknown_schema_version_exits_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            (cfg_dir / "fork_replay.watch.json").write_text(
                json.dumps({"schema_version": 99, "native_watches": [], "erc20_watches": []})
            )

            out_dir = tmp_path / "fork_replay"
            _, call_log, env = _setup_tripwire_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("schema_version", proc.stderr)
            self.assertFalse(call_log.exists())

    # ------------------------------------------------------------------
    # 6. Missing config with no override is silently OK.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_missing_config_is_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            # Do NOT create monitoring/ — config file is absent.
            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--watch-erc20", f"{TOKEN}:{HOLDER_A}=solo",
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("loading watch config", proc.stderr)
            self.assertNotIn("config error", proc.stderr)

    # ------------------------------------------------------------------
    # 7. --no-watch-config disables automatic loading even if file exists.
    # ------------------------------------------------------------------
    @REQUIRES_JQ
    def test_no_watch_config_disables_autoload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            cfg_dir = workspace / "monitoring"
            cfg_dir.mkdir()
            cfg = {
                "schema_version": 1,
                "erc20_watches": [
                    {"token": TOKEN, "holder": HOLDER_A, "label": "should-not-appear"},
                ],
            }
            (cfg_dir / "fork_replay.watch.json").write_text(json.dumps(cfg))

            out_dir = tmp_path / "fork_replay"
            _, env = _setup_fake_bin(tmp_path)

            proc = subprocess.run(
                [
                    "bash", str(TOOL),
                    "--no-watch-config",
                    "--watch-erc20", f"{TOKEN}:{HOLDER_B}=cli-only",
                    "--out-dir", str(out_dir),
                    str(workspace), TX, "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("loading watch config", proc.stderr)
            deltas = json.loads((out_dir / f"{TX}_deltas.json").read_text())
            targeted = deltas["targeted_watches"]
            self.assertEqual(len(targeted), 1)
            self.assertEqual(targeted[0]["label"], "cli-only")


if __name__ == "__main__":
    unittest.main()
