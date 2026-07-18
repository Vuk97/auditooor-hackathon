from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-backfill-solodit-function-shapes.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanBackfillSoloditFunctionShapesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_backfill_solodit_function_shapes_test")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_function_shape_test")

    def test_backfills_weak_synthetic_solodit_signature_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-shape-backfill-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            spec_path = spec_dir / "pool0.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: pool0-finding
severity: HIGH
source: "Solodit #1000 (Code4rena/Example)"
wiki_title: "Pool0 finding"
wiki_description: "Detector guessed a function name but did not extract a source signature."
solodit_id: "1000"
vuln_fn_name: pool0
vuln_fn_params: ""
vuln_fn_mutability: internal
vuln_fn_mutability_clean: internal
vuln_fn_return: bool
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:1000:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:1000
target_domain: vault
target_language: solidity
target_repo: code4rena/example
target_component: Pool0Finding
function_shape:
  raw_signature: "function pool0() internal returns (bool)"
  shape_tags:
    - protocol-invariant-bypass
    - solidity-logic-error
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit weak function hint
required_preconditions:
  - detector match
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: add invariant proof
fix_anti_pattern_avoided: treating detector hints as source signatures
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            dry = self.tool.backfill_shapes(tag_dir, dry_run=True)
            self.assertEqual(dry["updated"], 1)
            self.assertIn("function pool0() internal returns (bool)", tag_path.read_text(encoding="utf-8"))

            summary = self.tool.backfill_shapes(tag_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["updated"], 1)
            record = self.validator.load_yaml(tag_path)
            self.assertEqual(record["function_shape"]["raw_signature"], "function-name-hint: pool0")
            self.assertIn("name_match_missing_call", record["function_shape"]["shape_tags"])
            self.assertIn("inferred-function-name", record["function_shape"]["shape_tags"])

            second = self.tool.backfill_shapes(tag_dir)
            self.assertEqual(second["updated"], 0)

    def test_preserves_explicit_source_signature_records(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-shape-backfill-explicit-", dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            tag_dir = root / "tags"
            spec_dir = root / "detectors" / "_specs" / "drafts_solodit"
            tag_dir.mkdir()
            spec_dir.mkdir(parents=True)
            spec_path = spec_dir / "explicit.yaml"
            spec_path.write_text(
                """
skeleton: name_match_missing_call
name: explicit-signature
severity: HIGH
solodit_id: "1001"
vuln_fn_name: pool0
vuln_fn_sig: "function pool0(uint256 amount) external returns (bool)"
""".lstrip(),
                encoding="utf-8",
            )
            tag_path = tag_dir / "record.yaml"
            tag_path.write_text(
                f"""
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:1001:abcdefabcdef
source_audit_ref: solodit-spec:{spec_path.relative_to(REPO_ROOT).as_posix()}:1001
target_domain: vault
target_language: solidity
target_repo: code4rena/example
target_component: Pool0Finding
function_shape:
  raw_signature: "function pool0(uint256 amount) external returns (bool)"
  shape_tags:
    - protocol-invariant-bypass
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit explicit function
required_preconditions:
  - detector match
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: add invariant proof
fix_anti_pattern_avoided: treating detector hints as source signatures
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
                encoding="utf-8",
            )

            summary = self.tool.backfill_shapes(tag_dir)

            self.assertEqual(summary["errors"], [])
            self.assertEqual(summary["updated"], 0)
            record = self.validator.load_yaml(tag_path)
            self.assertEqual(
                record["function_shape"]["raw_signature"],
                "function pool0(uint256 amount) external returns (bool)",
            )


if __name__ == "__main__":
    unittest.main()
