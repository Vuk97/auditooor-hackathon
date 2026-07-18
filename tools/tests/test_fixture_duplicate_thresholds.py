#!/usr/bin/env python3
"""Tests for tools/fixture-duplicate-detector.py warn/fail thresholds.

Item #11 burn-down (handover plan): the detector now emits a machine-readable
manifest at ``<workspace>/.auditooor/fixture_duplicate_manifest.json`` and
classifies the run as PASS / WARN / FAIL based on flagged-pair count.

Test matrix per the burn-down plan:

  pair count    expected status (with warn=25, fail=200)
       0        PASS   — empty / no near-duplicates
      25        WARN   — at-or-above warn threshold
      75        WARN   — well above warn, still below fail
     250        FAIL   — at-or-above fail threshold

Tests are stdlib-only and hermetic. No real ``patterns/fixtures/`` files are
read or written; each scenario scaffolds an isolated synthetic corpus under
a ``tempfile.TemporaryDirectory`` and uses ``--fixtures-dir`` /
``--manifest-out`` / ``--report-out`` to keep all writes inside the temp
tree. The repo's ``patterns/fixtures/`` and ``docs/`` are NEVER touched.
"""
from __future__ import annotations

import importlib.util
import io
import json
import math
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "fixture-duplicate-detector.py"


def _load_module():
    """Import the hyphenated script as ``fixture_duplicate_detector``."""
    spec = importlib.util.spec_from_file_location(
        "fixture_duplicate_detector", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Mirror the audit-closeout-check loader pattern: register before exec
    # so dataclass / type-hint machinery resolves the module name correctly
    # (Python 3.14 ``@dataclass`` hits ``sys.modules[cls.__module__]``).
    sys.modules["fixture_duplicate_detector"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


# ---- helpers --------------------------------------------------------------


_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DupSample {{
    uint256 public counter;
    address public owner;
    mapping(address => uint256) public balances;
    event Updated(address indexed who, uint256 amount);

    constructor() {{
        owner = msg.sender;
    }}

    function deposit(uint256 amount) external {{
        require(amount > 0, "zero amount");
        balances[msg.sender] += amount;
        counter += 1;
        emit Updated(msg.sender, amount);
    }}

    function withdraw(uint256 amount) external {{
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        // Marker line: {marker}
        counter -= 1;
        emit Updated(msg.sender, amount);
    }}
}}
"""


def _smallest_n_for_pairs(target: int) -> int:
    """Return smallest n such that n*(n-1)/2 >= target.

    The synthetic corpora are cliques: n identical fixtures with distinct
    detector stems produce exactly n*(n-1)/2 flagged pairs. For target=25
    we want n=8 (28 pairs). For target=75 we want n=13 (78 pairs). For
    target=250 we want n=23 (253 pairs). Tests assert >= target rather
    than exact equality so the counts cleanly cross the warn/fail line.
    """
    if target <= 0:
        return 0
    # n*(n-1)/2 >= target  =>  n >= (1 + sqrt(1 + 8*target)) / 2
    n = math.ceil((1 + math.sqrt(1 + 8 * target)) / 2)
    while n * (n - 1) // 2 < target:
        n += 1
    return n


def _scaffold_clique(fix_dir: Path, n: int) -> None:
    """Write n near-identical fixtures with DISTINCT detector stems.

    Each file's content is byte-identical except for a comment marker that
    is normalized away by ``fixture-duplicate-detector.normalize`` (it
    strips line comments). Distinct stems mean the script will not skip
    them as "expected vuln/clean siblings"; identical normalized content
    yields Jaccard = 1.0, so every cross-stem pair gets flagged.
    """
    fix_dir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        # Stems must be distinct. ``_detector_stem`` strips ``_vuln.sol``,
        # so naming each fixture ``cliqueNN_vuln.sol`` produces stems
        # ``clique00``, ``clique01``, ... — all unique.
        path = fix_dir / f"clique{i:03d}_vuln.sol"
        path.write_text(_TEMPLATE.format(marker=i), encoding="utf-8")


def _run_detector(
    *,
    fix_dir: Path,
    manifest_out: Path,
    report_out: Path,
    threshold_warn: int,
    threshold_fail: int,
    extra: list[str] | None = None,
) -> tuple[int, str, str]:
    """Invoke ``MOD.main`` with hermetic paths and capture stdout/stderr."""
    argv = [
        "--fixtures-dir", str(fix_dir),
        "--manifest-out", str(manifest_out),
        "--report-out", str(report_out),
        "--threshold-warn", str(threshold_warn),
        "--threshold-fail", str(threshold_fail),
    ]
    if extra:
        argv.extend(extra)
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = MOD.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _read_manifest(manifest_out: Path) -> dict:
    payload = json.loads(manifest_out.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


# ---- tests ----------------------------------------------------------------


class ClassifyStatusTest(unittest.TestCase):
    """Direct unit test of the threshold-classification helper.

    Exercises the four canonical pair counts (0, 25, 75, 250) at the
    item #11 burn-down thresholds (warn=25, fail=200).
    """

    def test_zero_pairs_is_pass(self) -> None:
        self.assertEqual(
            MOD._classify_status(0, threshold_warn=25, threshold_fail=200),
            MOD.STATUS_PASS,
        )

    def test_warn_threshold_inclusive_warn(self) -> None:
        # Exactly at warn -> WARN (not PASS): the threshold is "at or above".
        self.assertEqual(
            MOD._classify_status(25, threshold_warn=25, threshold_fail=200),
            MOD.STATUS_WARN,
        )

    def test_above_warn_below_fail_is_warn(self) -> None:
        self.assertEqual(
            MOD._classify_status(75, threshold_warn=25, threshold_fail=200),
            MOD.STATUS_WARN,
        )

    def test_at_or_above_fail_is_fail(self) -> None:
        self.assertEqual(
            MOD._classify_status(250, threshold_warn=25, threshold_fail=200),
            MOD.STATUS_FAIL,
        )

    def test_default_thresholds(self) -> None:
        # Defaults are warn=50, fail=200 per the burn-down plan.
        self.assertEqual(MOD.DEFAULT_THRESHOLD_WARN, 50)
        self.assertEqual(MOD.DEFAULT_THRESHOLD_FAIL, 200)


class EndToEndManifestTest(unittest.TestCase):
    """End-to-end: build a synthetic corpus, run the detector, parse manifest.

    Asserts the manifest schema, threshold echoing, and the four
    PASS/WARN/WARN/FAIL outcomes that the burn-down plan specifies.
    """

    def _scenario(self, target_pairs: int, expected_status: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="fix-dup-") as tmp:
            tmp_path = Path(tmp)
            fix_dir = tmp_path / "fixtures"
            manifest_out = tmp_path / ".auditooor" / "manifest.json"
            report_out = tmp_path / "report.md"
            n = _smallest_n_for_pairs(target_pairs)
            _scaffold_clique(fix_dir, n)
            rc, _stdout, _stderr = _run_detector(
                fix_dir=fix_dir,
                manifest_out=manifest_out,
                report_out=report_out,
                threshold_warn=25,
                threshold_fail=200,
            )
            self.assertEqual(rc, 0, _stderr)
            self.assertTrue(manifest_out.exists(), _stderr)
            doc = _read_manifest(manifest_out)
            self.assertEqual(doc["schema"], "auditooor.fixture_duplicate.v1")
            self.assertEqual(doc["threshold_warn"], 25)
            self.assertEqual(doc["threshold_fail"], 200)
            self.assertGreaterEqual(doc["duplicate_pairs"], target_pairs)
            self.assertEqual(doc["status"], expected_status)
            # by_pattern rollup must be a list and (when there are pairs)
            # every entry must reference a stem that exists in the corpus.
            self.assertIsInstance(doc["by_pattern"], list)
            if doc["duplicate_pairs"] > 0:
                stems = {row["pattern_stem"] for row in doc["by_pattern"]}
                for stem in stems:
                    self.assertTrue(stem.startswith("clique"), stem)
            # The Markdown report exists and echoes the burn-down status.
            self.assertTrue(report_out.exists())
            md = report_out.read_text(encoding="utf-8")
            self.assertIn(expected_status, md)
            return doc

    def test_zero_pairs_pass(self) -> None:
        # n=0 => no fixtures, no pairs. We scaffold n=1 instead to exercise
        # the "scanned 1 fixture, no pairs" path; flagged stays at 0.
        with tempfile.TemporaryDirectory(prefix="fix-dup-zero-") as tmp:
            tmp_path = Path(tmp)
            fix_dir = tmp_path / "fixtures"
            manifest_out = tmp_path / ".auditooor" / "manifest.json"
            report_out = tmp_path / "report.md"
            _scaffold_clique(fix_dir, 1)
            rc, _stdout, _stderr = _run_detector(
                fix_dir=fix_dir,
                manifest_out=manifest_out,
                report_out=report_out,
                threshold_warn=25,
                threshold_fail=200,
            )
            self.assertEqual(rc, 0, _stderr)
            doc = _read_manifest(manifest_out)
            self.assertEqual(doc["duplicate_pairs"], 0)
            self.assertEqual(doc["duplicate_groups"], 0)
            self.assertEqual(doc["status"], MOD.STATUS_PASS)

    def test_25_pairs_warn(self) -> None:
        doc = self._scenario(25, MOD.STATUS_WARN)
        # n=8 clique => 8*7/2 = 28 pairs.
        self.assertGreaterEqual(doc["duplicate_pairs"], 25)

    def test_75_pairs_warn(self) -> None:
        doc = self._scenario(75, MOD.STATUS_WARN)
        # n=13 clique => 13*12/2 = 78 pairs.
        self.assertGreaterEqual(doc["duplicate_pairs"], 75)

    def test_250_pairs_fail(self) -> None:
        doc = self._scenario(250, MOD.STATUS_FAIL)
        # n=23 clique => 23*22/2 = 253 pairs.
        self.assertGreaterEqual(doc["duplicate_pairs"], 250)


class PruneOptInTest(unittest.TestCase):
    """``--prune`` is gated by AUDITOOOR_FIXTURE_PRUNE_OPTIN=1 and never
    deletes fixtures. Even with the opt-in, only a JSON deletion *plan* is
    emitted."""

    def test_prune_without_optin_refuses(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fix-dup-prune-no-") as tmp:
            tmp_path = Path(tmp)
            fix_dir = tmp_path / "fixtures"
            manifest_out = tmp_path / ".auditooor" / "manifest.json"
            report_out = tmp_path / "report.md"
            plan_out = tmp_path / "plan.json"
            _scaffold_clique(fix_dir, 4)
            # Ensure the env var is NOT set.
            old = os.environ.pop(MOD.PRUNE_OPTIN_ENV, None)
            try:
                rc, _stdout, _stderr = _run_detector(
                    fix_dir=fix_dir,
                    manifest_out=manifest_out,
                    report_out=report_out,
                    threshold_warn=1,
                    threshold_fail=1000,
                    extra=["--prune", "--prune-plan-out", str(plan_out)],
                )
            finally:
                if old is not None:
                    os.environ[MOD.PRUNE_OPTIN_ENV] = old
            self.assertEqual(rc, 2, _stderr)
            self.assertFalse(plan_out.exists(), "plan must NOT be written without opt-in")
            # All scaffolded fixtures must still exist; no deletions.
            for i in range(4):
                self.assertTrue((fix_dir / f"clique{i:03d}_vuln.sol").exists())

    def test_prune_with_optin_writes_plan_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fix-dup-prune-yes-") as tmp:
            tmp_path = Path(tmp)
            fix_dir = tmp_path / "fixtures"
            manifest_out = tmp_path / ".auditooor" / "manifest.json"
            report_out = tmp_path / "report.md"
            plan_out = tmp_path / "plan.json"
            _scaffold_clique(fix_dir, 4)
            old = os.environ.get(MOD.PRUNE_OPTIN_ENV)
            os.environ[MOD.PRUNE_OPTIN_ENV] = "1"
            try:
                rc, _stdout, _stderr = _run_detector(
                    fix_dir=fix_dir,
                    manifest_out=manifest_out,
                    report_out=report_out,
                    threshold_warn=1,
                    threshold_fail=1000,
                    extra=["--prune", "--prune-plan-out", str(plan_out)],
                )
            finally:
                if old is None:
                    os.environ.pop(MOD.PRUNE_OPTIN_ENV, None)
                else:
                    os.environ[MOD.PRUNE_OPTIN_ENV] = old
            self.assertEqual(rc, 0, _stderr)
            self.assertTrue(plan_out.exists(), "plan must be written with opt-in")
            plan = json.loads(plan_out.read_text(encoding="utf-8"))
            self.assertEqual(plan["schema"], "auditooor.fixture_duplicate_prune_plan.v1")
            self.assertIn("warning", plan)
            self.assertIn("PROPOSAL ONLY", plan["warning"])
            # All 4 fixtures must still exist on disk — the plan does not
            # touch the filesystem beyond writing itself.
            for i in range(4):
                self.assertTrue((fix_dir / f"clique{i:03d}_vuln.sol").exists())
            # The plan should propose at least 1 deletion (clique of 4 has
            # 6 pairs, all in one connected component => 1 group of 4).
            self.assertEqual(len(plan["groups"]), 1)
            group = plan["groups"][0]
            self.assertEqual(group["size"], 4)
            self.assertEqual(len(group["proposed_delete"]), 3)
            # The kept entry must not also appear in proposed_delete.
            self.assertNotIn(group["keep"], group["proposed_delete"])


if __name__ == "__main__":
    unittest.main()
