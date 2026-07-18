#!/usr/bin/env python3
"""Tests for tools/cvl-spec-risk-scan.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "cvl-spec-risk-scan.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(TOOL), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class CvlSpecRiskScanTests(unittest.TestCase):
    def _workspace(self) -> tempfile.TemporaryDirectory[str]:
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        certora = root / "src" / "certora"
        (certora / "specs").mkdir(parents=True)
        (certora / "confs").mkdir()
        (certora / "README.md").write_text(
            "\n".join(
                [
                    "loops are modeled as bounded",
                    "multicall is removed",
                    "ERC20 tokens are assumed well-behaved",
                    "external calls are assumed not to re-enter Midnight",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (certora / "confs" / "Midnight.conf").write_text(
            '{\n  "verify": "Midnight:certora/specs/Midnight.spec",\n  "optimistic_loop": true\n}\n',
            encoding="utf-8",
        )
        (certora / "specs" / "Midnight.spec").write_text(
            """
methods {
    function multicall(bytes[]) external => HAVOC_ALL DELETE;
    function _.onBuy(bytes32) external => NONDET;
    function _.price() external => CVL_price() expect(uint256);
}

ghost balances(address) returns uint256;
persistent ghost flashloans(address) returns uint256 {
    axiom forall address token. flashloans(token) >= 0;
}

rule witnessOnly(env e) {
    satisfy true;
}

invariant bounded(address user)
    balances(user) >= 0
{
    preserved take() with (env e) {
        requireInvariant otherInvariant(user);
    }
}

rule filteredRule(method f, env e, calldataarg args) filtered { f -> !f.isView } {
    f(e, args);
    assert true;
}
""".lstrip(),
            encoding="utf-8",
        )
        return tmp

    def test_scans_workspace_src_certora_and_reports_obligations(self) -> None:
        with self._workspace() as workspace:
            proc = _run(workspace, "--json")

        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.cvl_spec_risk_scan.v1")
        self.assertEqual(data["verdict"], "review-obligations")
        self.assertEqual(data["spec_count"], 1)
        self.assertEqual(data["conf_count"], 1)
        for kind in (
            "satisfy_without_assert",
            "preserved_assumption",
            "require_invariant_dependency",
            "filtered_parametric_methods",
            "nondet_summary",
            "cvl_function_summary",
            "wildcard_external_summary",
            "havoc_all_delete",
            "multicall_deleted",
            "optimistic_loop",
            "erc20_well_behaved_assumption",
            "no_reentry_assumption",
            "readme_multicall_removed",
        ):
            self.assertIn(kind, data["summary_by_kind"], kind)

    def test_writes_output_artifact(self) -> None:
        with self._workspace() as workspace:
            out = Path(workspace) / ".auditooor" / "cvl_coverage_audit.json"
            proc = _run(workspace, "--out", str(out))

            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(out.exists())
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(data["verdict"], "review-obligations")
        self.assertIn("[cvl-spec-risk-scan] wrote", proc.stdout)

    def test_no_certora_directory_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            proc = _run(workspace, "--json")

        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "no-certora-dir")
        self.assertEqual(data["risk_count"], 0)


if __name__ == "__main__":
    unittest.main()
