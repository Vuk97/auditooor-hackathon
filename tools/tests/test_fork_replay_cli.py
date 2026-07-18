#!/usr/bin/env python3
"""Smoke-test fork-replay delta artifacts without a real RPC."""
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
TX = "0x" + "ab" * 32
WATCH = "0x1111111111111111111111111111111111111111"
TOKEN = "0x2222222222222222222222222222222222222222"
HOLDER = "0x3333333333333333333333333333333333333333"

# PR 212 — fork-replay.sh invokes `jq` to parse `cast tx` JSON. The cast
# binary is PATH-shadowed with a mock per-test, but jq must be a real binary
# somewhere on the system PATH. If it isn't present, these tests exercise
# glue code we can't verify offline, so skip cleanly. The ci-preflight report
# flags this as an optional gap.
HAS_JQ = shutil.which("jq") is not None
REQUIRES_JQ = unittest.skipUnless(
    HAS_JQ, "jq not present — fork-replay.sh needs it to parse cast JSON"
)


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip())
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class ForkReplayCliTest(unittest.TestCase):
    def test_help_mentions_delta_tracking_flags(self) -> None:
        proc = subprocess.run(
            ["bash", str(TOOL), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--watch <address>", proc.stdout)
        self.assertIn("--erc20 <token>", proc.stdout)
        self.assertIn("--out-dir <dir>", proc.stdout)
        self.assertIn("--watch-erc20", proc.stdout)
        self.assertIn("--watch-native", proc.stdout)

    @REQUIRES_JQ
    def test_mocked_replay_writes_pre_post_and_delta_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            post_flag = tmp_path / "post.flag"
            out_dir = tmp_path / "fork_replay"
            workspace = tmp_path / "workspace"
            workspace.mkdir()

            write_executable(
                fake_bin / "anvil",
                """
                #!/usr/bin/env bash
                sleep 60
                """,
            )
            write_executable(
                fake_bin / "cast",
                f"""
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
                    if [ -f "{post_flag}" ]; then echo 75; else echo 50; fi
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
                """,
            )

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            proc = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch",
                    WATCH,
                    "--erc20",
                    TOKEN,
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("[fork-replay] done", proc.stdout)

            pre_state = out_dir / f"{TX}_pre_state.json"
            post_state = out_dir / f"{TX}_post_state.json"
            deltas = out_dir / f"{TX}_deltas.json"
            manifest = out_dir / f"{TX}_manifest.json"
            for artifact in (pre_state, post_state, deltas, manifest):
                self.assertTrue(artifact.exists(), artifact)

            delta_doc = json.loads(deltas.read_text())
            watch_delta = delta_doc["addresses"][WATCH]
            self.assertEqual(watch_delta["nativeWei"]["delta"], "50")
            self.assertEqual(watch_delta["erc20"][TOKEN]["delta"], "25")

            manifest_doc = json.loads(manifest.read_text())
            self.assertEqual(manifest_doc["status"], "executed")
            self.assertEqual(manifest_doc["artifacts"]["deltas"], str(deltas))

    # ------------------------------------------------------------------
    # PR 103 — targeted replay watches
    # ------------------------------------------------------------------

    def _targeted_fake_cast(self, post_flag: Path, fail_balance_of: bool = False) -> str:
        """Return a shell body for a fake `cast` binary supporting targeted-watch cast calls."""
        fail_branch = 'echo "balanceOf reverted" >&2; exit 1' if fail_balance_of else 'if [ -f "{post_flag}" ]; then echo "75 [0x4b]"; else echo "50 [0x32]"; fi'
        # We interpolate post_flag via .format below.
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
                # $1..$N remain the call args: <token> <sig> <addr>
                # Differentiate targeted (holder == HOLDER) from broadcast.
                holder_arg="${{3:-}}"
                if [ "$holder_arg" = "{HOLDER.lower()}" ] || [ "$holder_arg" = "{HOLDER}" ]; then
                  {fail_branch}
                else
                  if [ -f "{post_flag}" ]; then echo 75; else echo 50; fi
                fi
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

    def _setup_targeted_env(self, tmp_path: Path, fail_balance_of: bool = False):
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
        body = self._targeted_fake_cast(post_flag, fail_balance_of=fail_balance_of)
        # Replace the {post_flag} placeholders (not an f-string, so format-by-str.replace).
        body = body.replace("{post_flag}", str(post_flag))
        write_executable(fake_bin / "cast", body)
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        return fake_bin, env

    @REQUIRES_JQ
    def test_targeted_watch_erc20_emits_labeled_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "fork_replay"
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            _, env = self._setup_targeted_env(tmp_path)

            proc = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch-erc20",
                    f"{TOKEN}:{HOLDER}=victim",
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("[fork-replay] done", proc.stdout)

            deltas = out_dir / f"{TX}_deltas.json"
            delta_doc = json.loads(deltas.read_text())
            targeted = delta_doc.get("targeted_watches")
            self.assertIsInstance(targeted, list)
            self.assertEqual(len(targeted), 1)
            row = targeted[0]
            self.assertEqual(row["label"], "victim")
            self.assertEqual(row["kind"], "erc20")
            self.assertEqual(row["token"], TOKEN)
            self.assertEqual(row["holder"], HOLDER)
            self.assertEqual(row["pre"], "50")
            self.assertEqual(row["post"], "75")
            self.assertEqual(row["delta"], "25")
            self.assertIsNone(row["error"])

    @REQUIRES_JQ
    def test_targeted_watch_erc20_balanceof_revert_emits_null_delta_and_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "fork_replay"
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            _, env = self._setup_targeted_env(tmp_path, fail_balance_of=True)

            proc = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch-erc20",
                    f"{TOKEN}:{HOLDER}=victim",
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            deltas = out_dir / f"{TX}_deltas.json"
            delta_doc = json.loads(deltas.read_text())
            targeted = delta_doc["targeted_watches"]
            self.assertEqual(len(targeted), 1)
            row = targeted[0]
            self.assertEqual(row["label"], "victim")
            self.assertIsNone(row["delta"])
            self.assertNotEqual(row["delta"], "0")
            self.assertIsInstance(row["error"], str)
            self.assertTrue(len(row["error"]) > 0)

    def test_invalid_watch_erc20_spec_exits_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_bin = tmp_path / "bin"
            fake_bin.mkdir()
            call_log = tmp_path / "cast_calls.log"
            # Tripwire cast: any invocation MUST log itself. If network was hit,
            # the log file will exist with content.
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
                """
                #!/usr/bin/env bash
                echo "anvil should not have been invoked" >&2
                exit 77
                """,
            )
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            out_dir = tmp_path / "fork_replay"

            # Case 1: missing ':' separator.
            proc1 = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch-erc20",
                    f"{TOKEN}{HOLDER}",  # no colon
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc1.returncode, 0)
            self.assertIn("watch-erc20", proc1.stderr)
            self.assertFalse(call_log.exists(), "cast was invoked despite invalid spec")

            # Case 2: bad token address (wrong length).
            proc2 = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch-erc20",
                    f"0xdeadbeef:{HOLDER}",
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc2.returncode, 0)
            self.assertIn("40 hex", proc2.stderr)
            self.assertFalse(call_log.exists(), "cast was invoked despite invalid token")

    @REQUIRES_JQ
    def test_targeted_watch_erc20_dedup_keeps_first_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            out_dir = tmp_path / "fork_replay"
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            _, env = self._setup_targeted_env(tmp_path)

            proc = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    "--watch-erc20",
                    f"{TOKEN}:{HOLDER}=victim",
                    "--watch-erc20",
                    f"{TOKEN}:{HOLDER}=protocol",
                    "--out-dir",
                    str(out_dir),
                    str(workspace),
                    TX,
                    "https://mock-rpc.local",
                ],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("duplicate targeted watch", proc.stderr)
            deltas = out_dir / f"{TX}_deltas.json"
            delta_doc = json.loads(deltas.read_text())
            targeted = delta_doc["targeted_watches"]
            self.assertEqual(len(targeted), 1)
            self.assertEqual(targeted[0]["label"], "victim")


if __name__ == "__main__":
    unittest.main()
