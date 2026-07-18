from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-sidecar-refresh-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_sidecar_refresh_check", str(TOOL)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD = """
schema_version: auditooor.hackerman_record.v1.1
record_id: {rid}
source_audit_ref: test:audit:{n}
target_domain: lending
target_language: solidity
target_repo: test/repo
target_component: Vault.withdraw
function_shape:
  raw_signature: "function withdraw(uint256 assets) external"
  shape_tags:
    - withdraw
bug_class: {bug_class}
attack_class: {attack_class}
attacker_role: unprivileged
attacker_action_sequence: "Step 1: trigger bug."
required_preconditions:
  - precondition
impact_class: theft
impact_actor: users
impact_dollar_class: "$10K-$100K"
fix_pattern: apply guard
fix_anti_pattern_avoided: no guard
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
"""


class HackermanSidecarRefreshCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-sidecar-wrapper-")
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.tag_dir.mkdir()
        self.detector_sidecar = self.tmp_path / "derived" / "detector_relationship_records.jsonl"
        self.chain_sidecar = self.tmp_path / "derived" / "chain_candidates.jsonl"
        self.chain_unify_sidecar = self.tmp_path / "derived" / "chain_unify_payload.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(self, n: int, bug_class: str, attack_class: str) -> None:
        path = self.tag_dir / f"record{n}.yaml"
        path.write_text(
            textwrap.dedent(
                _RECORD.format(
                    rid=f"test/{n}",
                    n=n,
                    bug_class=bug_class,
                    attack_class=attack_class,
                )
            ).lstrip(),
            encoding="utf-8",
        )

    def test_check_mode_reports_stale_when_sidecars_missing(self) -> None:
        self._write_record(0, "reentrancy", "reentrancy-via-hook-or-callback")
        rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--detector-sidecar",
                str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--check",
            ]
        )
        self.assertEqual(rc, 1)

    def test_refresh_mode_rebuilds_all_targets_when_stale(self) -> None:
        self._write_record(0, "reentrancy", "reentrancy-via-hook-or-callback")
        self._write_record(1, "stale-oracle", "oracle-staleness")
        rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--detector-sidecar",
                str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--max-rebuilds",
                "3",
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(self.detector_sidecar.is_file())
        self.assertTrue(self.chain_sidecar.is_file())
        self.assertTrue(self.chain_unify_sidecar.is_file())

        check_rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--detector-sidecar",
                str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--check",
            ]
        )
        self.assertEqual(check_rc, 0)

    def test_refresh_is_bounded_by_max_rebuilds(self) -> None:
        self._write_record(0, "reentrancy", "reentrancy-via-hook-or-callback")
        self._write_record(1, "access-control", "access-control-missing-modifier")
        rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--detector-sidecar",
                str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--max-rebuilds",
                "1",
            ]
        )
        self.assertEqual(rc, 1)
        self.assertTrue(self.detector_sidecar.is_file() or self.chain_sidecar.is_file())
        self.assertFalse(self.detector_sidecar.is_file() and self.chain_sidecar.is_file())

    def test_check_detects_stale_after_corpus_change(self) -> None:
        self._write_record(0, "reentrancy", "reentrancy-via-hook-or-callback")
        self.assertEqual(
            self.tool.main(
                [
                    "--tag-dir",
                    str(self.tag_dir),
                    "--detector-sidecar",
                    str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--max-rebuilds",
                "3",
            ]
        ),
            0,
        )
        time.sleep(0.01)
        self._write_record(1, "stale-oracle", "oracle-staleness")
        self.assertEqual(
            self.tool.main(
                [
                    "--tag-dir",
                    str(self.tag_dir),
                    "--detector-sidecar",
                    str(self.detector_sidecar),
                "--chain-sidecar",
                str(self.chain_sidecar),
                "--chain-unify-sidecar",
                str(self.chain_unify_sidecar),
                "--check",
            ]
        ),
            1,
        )

    def test_json_output_emits_schema(self) -> None:
        self._write_record(0, "reentrancy", "reentrancy-via-hook-or-callback")
        # run_refresh is easier for structured assertions than intercepting stdout.
        rc, payload = self.tool.run_refresh(
            self.tool.argparse.Namespace(
                tag_dir=str(self.tag_dir),
                targets=["detector_relationship_records", "chain_candidates"],
                check=False,
                max_rebuilds=2,
                detector_sidecar=str(self.detector_sidecar),
                chain_sidecar=str(self.chain_sidecar),
                json=True,
            )
        )
        self.assertEqual(rc, 0)
        self.assertEqual(payload["schema"], self.tool.SCHEMA)
        self.assertTrue(payload["all_fresh"])
        raw = json.dumps(payload, sort_keys=True)
        self.assertIn("detector_relationship_records", raw)
        self.assertIn("chain_candidates", raw)


if __name__ == "__main__":
    unittest.main()
