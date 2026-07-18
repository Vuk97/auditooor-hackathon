#!/usr/bin/env python3
"""Regression tests for the Wave-1/3/4 ETL miner wiring (PR #726 + EXEC-WAVE7).

Asserts:
* The new ``hackerman-etl-wave-1-3-4`` target exists and references all 17
  ETL miners shipped in PR #726.
* The target defaults to dry-run mode and switches when ``APPLY=1`` is set.
* ``hackerman-refresh`` depends on ``hackerman-etl-wave-1-3-4`` so the new
  miners auto-run on refresh.
* The two miners with required external inputs
  (``hackerman-etl-from-starknet-cairo.py`` / ``hackerman-etl-from-platforms.py``)
  print a ``SKIP`` line when their input env vars are absent.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]

WAVE_MINERS = (
    "hackerman-etl-from-vyper-cve.py",
    "hackerman-etl-from-starknet-cairo.py",
    "hackerman-etl-from-sui-move.py",
    "hackerman-etl-from-aptos-move.py",
    "hackerman-etl-from-eth-client-rust.py",
    "hackerman-etl-from-l2-zkrollup.py",
    "hackerman-etl-from-substrate-cosmwasm-frost.py",
    "hackerman-etl-from-mev-flashloan.py",
    "hackerman-etl-from-zkbugs-catalog.py",
    "hackerman-etl-from-zk-auditor-reports.py",
    "hackerman-etl-from-zk-contests.py",
    "hackerman-etl-from-evm-proxy-upgrade.py",
    "hackerman-etl-from-platforms.py",
    "hackerman-etl-from-bridge-attacks.py",
    "hackerman-etl-from-near-ink.py",
    "hackerman-go-cosmos-expand.py",
    "hackerman-etl-from-sig-extracts.py",
    # rank24-5-orphan-etls: 3 previously-orphaned miners that accept the
    # uniform --out-dir/--dry-run/--limit contract and join the loop directly.
    "hackerman-etl-from-substrate-fix-history.py",
    "hackerman-etl-from-substrate-cosmwasm.py",
    "hackerman-etl-from-vyper-compiler-fix-history.py",
)

# rank24-5-orphan-etls: 2 previously-orphaned miners with NON-uniform output
# flags (zkbugs-dataset uses --out-root/--dataset-root; zebra-advisories uses
# --corpus-dir) get dedicated, env-overridable blocks rather than the uniform
# --out-dir loop. They were built + registry-listed but never invoked by any
# corpus-refresh make target.
SPECIAL_FLAG_MINERS = (
    "hackerman-etl-from-zkbugs-dataset.py",
    "hackerman-etl-from-zebra-advisories.py",
)


def make_dry_run(target: str, *args: str, timeout: int = 15) -> str:
    result = subprocess.run(
        ["make", "-n", target, *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"make -n {target} failed with rc {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


class MakefileWaveEtlWiringTest(unittest.TestCase):
    def test_all_17_miner_files_exist(self) -> None:
        missing = [m for m in WAVE_MINERS if not (REPO / "tools" / m).is_file()]
        self.assertEqual(missing, [], f"missing miner files: {missing}")

    def test_wave_target_references_all_17_miners(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        for miner in WAVE_MINERS:
            self.assertIn(
                miner,
                output,
                f"hackerman-etl-wave-1-3-4 dry-run output missing miner {miner}",
            )

    def test_wave_target_defaults_to_dry_run(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn('dry_flag="--dry-run"', output)
        self.assertNotIn('dry_flag=""', output)

    def test_wave_target_apply_flips_off_dry_run(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4", "APPLY=1")
        self.assertIn('dry_flag=""', output)
        self.assertNotIn('dry_flag="--dry-run"', output)

    def test_wave_target_uses_default_out_dir(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn('out_dir="audit/corpus_tags/tags"', output)

    def test_wave_target_honors_out_dir_override(self) -> None:
        output = make_dry_run(
            "hackerman-etl-wave-1-3-4", "OUT_DIR=/tmp/override_out"
        )
        self.assertIn('out_dir="/tmp/override_out"', output)

    def test_wave_target_honors_limit_override(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4", "WAVE_ETL_LIMIT=3")
        self.assertIn("limit_flag=\"--limit 3\"", output)

    def test_hackerman_refresh_depends_on_wave_target(self) -> None:
        output = make_dry_run("hackerman-refresh")
        # The wave-1-3-4 dependency must run before the refresh body.
        # Its banner echo identifies it.
        self.assertIn("[hackerman-etl-wave-1-3-4] RUN tools/", output)
        # And we should also see the refresh orchestrator invocation.
        self.assertIn("tools/hackerman-etl-refresh.py", output)

    def test_starknet_miner_prints_skip_without_inputs(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn(
            "SKIP tools/hackerman-etl-from-starknet-cairo.py",
            output,
        )

    def test_platforms_miner_prints_skip_without_inputs(self) -> None:
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn(
            "SKIP tools/hackerman-etl-from-platforms.py",
            output,
        )

    def test_special_flag_miner_files_exist(self) -> None:
        missing = [
            m for m in SPECIAL_FLAG_MINERS
            if not (REPO / "tools" / m).is_file()
        ]
        self.assertEqual(missing, [], f"missing special-flag miner files: {missing}")

    def test_wave_target_references_special_flag_miners(self) -> None:
        # rank24-5-orphan-etls: the two non-uniform-flag miners must be invoked
        # by the wave target (in dedicated blocks), not left orphaned.
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        for miner in SPECIAL_FLAG_MINERS:
            self.assertIn(
                miner,
                output,
                f"hackerman-etl-wave-1-3-4 dry-run output missing miner {miner}",
            )

    def test_zkbugs_dataset_uses_out_root_flag(self) -> None:
        # zkbugs-dataset takes --out-root (not --out-dir); the wave block must
        # invoke it with the correct flag or it errors at runtime.
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn("hackerman-etl-from-zkbugs-dataset.py", output)
        self.assertIn("--out-root", output)

    def test_zebra_advisories_uses_corpus_dir_flag(self) -> None:
        # zebra-advisories takes --corpus-dir (presence-based dedup), not
        # --out-dir; the wave block must invoke it with the correct flag.
        output = make_dry_run("hackerman-etl-wave-1-3-4")
        self.assertIn("hackerman-etl-from-zebra-advisories.py", output)
        self.assertIn("--corpus-dir", output)

    def test_phony_includes_wave_target(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        # Find the .PHONY line that owns hackerman-refresh wiring.
        self.assertIn("hackerman-etl-wave-1-3-4", makefile)
        # Look for the .PHONY declaration including the new target name.
        phony_lines = [
            line for line in makefile.splitlines()
            if line.startswith(".PHONY:") and "hackerman-etl-wave-1-3-4" in line
        ]
        self.assertTrue(
            phony_lines,
            ".PHONY line for hackerman-etl-wave-1-3-4 missing from Makefile",
        )


if __name__ == "__main__":
    unittest.main()
