from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-record-quality.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_record_quality", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _record(
    record_id: str,
    source: str,
    *,
    repo: str = "example/repo",
    language: str = "solidity",
    verdict_class: str = "",
    year: int = 2024,
    raw_signature: str = "func (k Keeper) Msg(ctx context.Context) error",
) -> str:
    extra = f"verdict_class: {verdict_class}\n" if verdict_class else ""
    return f"""
schema_version: auditooor.hackerman_record.v1
record_id: {record_id}
source_audit_ref: {source}
target_domain: lending
target_language: {language}
target_repo: {repo}
target_component: Keeper
function_shape:
  raw_signature: "{raw_signature}"
  shape_tags:
    - access-control
bug_class: access-control
attack_class: admin-bypass
attacker_role: unprivileged
attacker_action_sequence: attacker calls a privileged path
required_preconditions:
  - funded protocol
impact_class: privilege-escalation
impact_actor: arbitrary-user
impact_dollar_class: "$100K-$1M"
fix_pattern: enforce signer authority
fix_anti_pattern_avoided: trusting caller supplied state
severity_at_finding: high
year: {year}
cross_language_analogues: []
related_records: []
{extra}""".lstrip()


class HackermanRecordQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_synthetic_candidate_scores_low(self) -> None:
        row = self.tool.score_record(
            {
                "record_id": "dsl/synthetic",
                "source_audit_ref": "dsl_pattern/synthetic",
                "target_language": "solidity",
                "target_repo": "patterns/dsl",
                "verdict_class": "CANDIDATE",
                "year": 2026,
            }
        )

        self.assertEqual(row["record_tier"], "public-corpus")
        self.assertEqual(row["source_extraction_method"], "dsl-synthetic")
        self.assertLessEqual(row["record_quality_score"], 1.5)

    def test_canonical_dsl_records_score_low_without_candidate_marker(self) -> None:
        row = self.tool.score_record(
            {
                "record_id": "dsl-pattern:go:cosmos-finalizeblock:abcd",
                "source_audit_ref": "canonical-dsl:reference/patterns.dsl.r94_solodit_go/finalizeblock.yaml:solodit:1",
                "target_language": "go",
                "target_repo": "unknown",
                "year": 2000,
            }
        )

        self.assertEqual(row["record_tier"], "public-corpus")
        self.assertEqual(row["source_extraction_method"], "dsl-synthetic")
        self.assertLessEqual(row["record_quality_score"], 1.5)

    def test_dydx_go_submission_scores_high(self) -> None:
        row = self.tool.score_record(
            {
                "record_id": "dydx-hunt-iter-1/cantina-311",
                "source_audit_ref": "dydx-hunt-iter-1/cantina-311",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "verdict_class": "FILED",
                "year": 2026,
            }
        )

        self.assertEqual(row["record_tier"], "dydx-filed")
        self.assertGreaterEqual(row["record_quality_score"], 4.5)
        self.assertGreaterEqual(row["source_extraction_confidence"], 0.9)

    def test_prior_audit_go_record_outranks_unknown_year_solodit(self) -> None:
        prior = self.tool.score_record(
            {
                "record_id": "prior/dydx/1",
                "source_audit_ref": "prior-audit:dydx:informal",
                "target_language": "go",
                "target_repo": "dydxprotocol/v4-chain",
                "year": 2025,
            }
        )
        solodit = self.tool.score_record(
            {
                "record_id": "solodit/1",
                "source_audit_ref": "solodit-spec:detectors/_specs/example.yaml:1",
                "target_language": "solidity",
                "target_repo": "example/repo",
                "year": 2000,
            }
        )

        self.assertGreater(prior["record_quality_score"], solodit["record_quality_score"])

    def test_function_name_hint_scores_below_source_extracted_signature(self) -> None:
        base_record = {
            "record_id": "solodit/shape",
            "source_audit_ref": "solodit-spec:detectors/_specs/example.yaml:1",
            "target_language": "solidity",
            "target_repo": "example/repo",
            "year": 2024,
        }
        precise = self.tool.score_record(
            {
                **base_record,
                "function_shape": {"raw_signature": "function withdraw(uint256 amount) external"},
            }
        )
        hint = self.tool.score_record(
            {
                **base_record,
                "function_shape": {"raw_signature": "function-name-hint: withdraw"},
            }
        )

        self.assertLess(hint["record_quality_score"], precise["record_quality_score"])
        self.assertLess(hint["source_extraction_confidence"], precise["source_extraction_confidence"])
        self.assertIn("function-name hint", hint["reason"])

    def test_cli_writes_sorted_jsonl(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-quality-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            out = root / "quality.jsonl"
            tags.mkdir()
            (tags / "synthetic.yaml").write_text(
                _record(
                    "dsl/synthetic",
                    "dsl_pattern/synthetic",
                    repo="patterns/dsl",
                    verdict_class="CANDIDATE",
                ),
                encoding="utf-8",
            )
            (tags / "dydx.yaml").write_text(
                _record(
                    "dydx-hunt-iter-1/cantina-311",
                    "dydx-hunt-iter-1/cantina-311",
                    repo="dydxprotocol/v4-chain",
                    language="go",
                    verdict_class="FILED",
                    year=2026,
                ),
                encoding="utf-8",
            )

            rc = self.tool.main(["--tag-dir", str(tags), "--out", str(out)])

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["record_id"], "dydx-hunt-iter-1/cantina-311")
            self.assertEqual(rows[1]["record_id"], "dsl/synthetic")

    def test_writeback_tags_adds_schema_native_quality_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-quality-writeback-") as tmp:
            root = Path(tmp)
            tags = root / "tags"
            out = root / "quality.jsonl"
            tag = tags / "dydx.yaml"
            tags.mkdir()
            tag.write_text(
                _record(
                    "dydx-hunt-iter-1/cantina-311",
                    "dydx-hunt-iter-1/cantina-311",
                    repo="dydxprotocol/v4-chain",
                    language="go",
                    verdict_class="FILED",
                    year=2026,
                ),
                encoding="utf-8",
            )

            rc = self.tool.main(["--tag-dir", str(tags), "--out", str(out), "--writeback-tags"])

            self.assertEqual(rc, 0)
            doc = self.tool.yaml_load(tag.read_text(encoding="utf-8"))
            self.assertEqual(doc["record_tier"], "dydx-filed")
            self.assertGreaterEqual(doc["record_quality_score"], 4.5)
            self.assertEqual(doc["source_extraction_method"], "human-curated")
            self.assertGreaterEqual(doc["source_extraction_confidence"], 0.9)


if __name__ == "__main__":
    unittest.main()
