#!/usr/bin/env python3
"""Offline regression tests for ccia-rust tuning flags (iter12 T3).

New tests — DO NOT modify `tools/tests/test_ccia_rust.py` (iter10 T1's
5 tests are a hard-frozen baseline; iter12 T3 only ADDS coverage).

Flags exercised:
  - `--top-n <int>`
  - `--max-per-angle <int>`
  - `--confidence-floor medium` (behavior already existed; confirm filter
    still drops lows when the other tuning flags are in use).

Filter application order (documented in ccia-rust.py):
  confidence-floor → max-per-angle → top-n

Ranking used by max-per-angle + top-n: medium > low, then file path,
then line. Deterministic so `--top-n` output is reproducible.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "ccia-rust.py"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


def _make_fixture(root: Path, relpath: str, content: str) -> Path:
    full = root / relpath
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return full


# Fixture shared by top_n + max_per_angle tests — generates many A-AUTH
# findings (privileged-looking fn names without `require_auth`). Each
# distinct fn name produces its own medium-confidence A-AUTH finding.
def _many_auth_fixture(ws: Path, n: int) -> None:
    """Create `n` privileged-sounding functions in src/auth.rs."""
    lines = ["use soroban_sdk::{Env};\n", "\n"]
    for i in range(n):
        lines.append(
            f"pub fn admin_fn_{i}(env: Env, new_val: u64) {{\n"
            f"    env.storage().instance().set(&{i}u32, &new_val);\n"
            "}\n\n"
        )
    _make_fixture(ws, "src/auth.rs", "".join(lines))


class TestCciaRustTuning(unittest.TestCase):

    # ---- (1) --top-n limits total findings
    def test_top_n_limits_total_findings(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _many_auth_fixture(ws, 12)  # ≥10 findings
            # Baseline: no --top-n
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            baseline = json.loads(proc.stdout)
            baseline_count = len(baseline["angles"])
            self.assertGreaterEqual(
                baseline_count, 10,
                f"fixture should produce ≥10 findings; got {baseline_count}",
            )
            # --top-n 3 → exactly 3
            proc = _run(["--workspace", str(ws), "--top-n", "3"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            limited = json.loads(proc.stdout)
            self.assertEqual(
                len(limited["angles"]), 3,
                f"--top-n 3 should emit exactly 3 findings; got "
                f"{len(limited['angles'])}",
            )
            # Determinism: re-run produces byte-identical output
            proc2 = _run(["--workspace", str(ws), "--top-n", "3"])
            self.assertEqual(proc2.stdout, proc.stdout,
                             "--top-n output must be reproducible")

    # ---- (2) --max-per-angle caps findings per angle class
    def test_max_per_angle_caps_per_class(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # 5 distinct privileged fn names → 5 A-AUTH medium findings
            _many_auth_fixture(ws, 5)
            # Baseline: confirm ≥5 A-AUTH in the raw scan
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            baseline = json.loads(proc.stdout)
            auth_baseline = [a for a in baseline["angles"]
                             if a["angle"] == "A-AUTH"]
            self.assertGreaterEqual(
                len(auth_baseline), 5,
                f"fixture should produce ≥5 A-AUTH; got {len(auth_baseline)}",
            )
            # --max-per-angle 2 → exactly 2 A-AUTH remain
            proc = _run([
                "--workspace", str(ws), "--max-per-angle", "2",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            capped = json.loads(proc.stdout)
            auth_capped = [a for a in capped["angles"]
                           if a["angle"] == "A-AUTH"]
            self.assertEqual(
                len(auth_capped), 2,
                f"--max-per-angle 2 should emit exactly 2 A-AUTH; got "
                f"{len(auth_capped)}",
            )
            # Cap must not exceed for any other surfaced angle either
            from collections import Counter
            per_angle = Counter(a["angle"] for a in capped["angles"])
            for angle, count in per_angle.items():
                self.assertLessEqual(
                    count, 2,
                    f"angle {angle} exceeds cap 2: count={count}",
                )

    # ---- (3) --confidence-floor medium drops low-confidence findings
    def test_confidence_floor_filters_low(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Mix: one privileged fn w/o require_auth (medium A-AUTH) +
            # one fn with require_auth (low A-AUTH surface map finding).
            _make_fixture(ws, "src/mix.rs", (
                "use soroban_sdk::{Env, Address};\n"
                "\n"
                "pub fn admin_only(env: Env, x: u64) {\n"
                "    // no require_auth → medium\n"
                "    env.storage().instance().set(&1u32, &x);\n"
                "}\n"
                "\n"
                "pub fn user_action(env: Env, caller: Address, x: u64) {\n"
                "    caller.require_auth();\n"
                "    env.storage().instance().set(&2u32, &x);\n"
                "}\n"
            ))
            # Baseline: must have both a low and a medium
            proc = _run(["--workspace", str(ws)])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            baseline = json.loads(proc.stdout)
            confs = {a["confidence"] for a in baseline["angles"]}
            self.assertIn("low", confs,
                          f"fixture should produce at least one low; got {confs}")
            self.assertIn("medium", confs,
                          f"fixture should produce at least one medium; got {confs}")
            # --confidence-floor medium → zero lows survive
            proc = _run([
                "--workspace", str(ws), "--confidence-floor", "medium",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            filtered = json.loads(proc.stdout)
            self.assertTrue(filtered["angles"],
                            "medium-floor should keep medium findings")
            for a in filtered["angles"]:
                self.assertEqual(
                    a["confidence"], "medium",
                    f"only medium findings should survive floor; got {a}",
                )


if __name__ == "__main__":
    unittest.main()
