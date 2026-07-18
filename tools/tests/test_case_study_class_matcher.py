"""
tests/test_case_study_class_matcher.py — unit tests for tools/case-study-class-matcher.py

Phase E (commit E1) of CORPUS_MINING_AND_CASE_STUDY_LOGIC_EXTRACTION_PLAN_2026-05-08.md.

Coverage:
  (a) frontmatter parse — valid, missing, partial
  (b) match positive — exact class, applicable_workspace_classes, partial substring
  (c) match negative — unrelated class yields no matches
  (d) multi-class workspace — aggregated results from a synthetic fixture set
"""

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# Load the hyphenated module via importlib (standard pattern for this repo)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOL = _REPO_ROOT / "tools" / "case-study-class-matcher.py"
_MCP_TOOL = _REPO_ROOT / "tools" / "vault-mcp-server.py"
_spec = importlib.util.spec_from_file_location("case_study_class_matcher", _TOOL)
if _spec is None or _spec.loader is None:
    raise RuntimeError(f"Could not load {_TOOL}")
_mod = importlib.util.module_from_spec(_spec)
sys.modules["case_study_class_matcher"] = _mod  # register before exec so dataclasses.__module__ resolves
_spec.loader.exec_module(_mod)

CaseMatch = _mod.CaseMatch
CaseStudyMeta = _mod.CaseStudyMeta
_parse_yaml_frontmatter = _mod._parse_yaml_frontmatter
_score = _mod._score
load_all_case_studies = _mod.load_all_case_studies
match_workspace = _mod.match_workspace

_mcp_spec = importlib.util.spec_from_file_location("vault_mcp_server_case_study_test", _MCP_TOOL)
if _mcp_spec is None or _mcp_spec.loader is None:
    raise RuntimeError(f"Could not load {_MCP_TOOL}")
_mcp_mod = importlib.util.module_from_spec(_mcp_spec)
sys.modules["vault_mcp_server_case_study_test"] = _mcp_mod
_mcp_spec.loader.exec_module(_mcp_mod)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_case_study(tmp: Path, filename: str, content: str) -> Path:
    p = tmp / filename
    p.write_text(textwrap.dedent(content))
    return p


FIXTURE_BRIDGE = """\
---
case_id: test-bridge-case
mechanism: invalid withdrawal proof accepted after partial-deployment window
class: bridge
severity_class: CRIT
applicable_workspace_classes:
  - bridge
  - consensus
grep_predicates:
  - "finalizeWithdrawal|proveWithdrawal"
runtime_predicates:
  - "forge test: fake proof accepted"
extracted_lesson: >
  Partial-deployment window exposes a cross-version consensus gap.
stop_criterion: >
  STOP closing bridge deployment-state findings until the live validator set has been checked.
workflow_signature: bridge_deployment_state_without_live_check
loop_back_phase: phase-3-live-state-check
---
# Test Bridge Case
Body content here.
"""

FIXTURE_LENDING = """\
---
case_id: test-lending-case
mechanism: oracle SCALE_FACTOR=0 causes silent division error
class: lending
severity_class: HIGH
applicable_workspace_classes:
  - lending
  - oracle
grep_predicates:
  - "SCALE_FACTOR|scaleFactor"
runtime_predicates:
  - "forge test: price returns 0"
extracted_lesson: >
  Cold-read surfaces oracle initialization bug missed by 4 prior audits.
---
# Test Lending Case
"""

FIXTURE_METHODOLOGY = """\
---
case_id: test-methodology-case
mechanism: 6 consecutive FPs = surface exhausted
class: workflow-methodology
severity_class: INFO
applicable_workspace_classes:
  - prediction-market
  - workflow-methodology
grep_predicates: []
runtime_predicates: []
extracted_lesson: >
  Stop criterion fires after 6 FPs on same surface.
---
# Test Methodology Case
"""

FIXTURE_NO_FRONTMATTER = """\
# Plain Case Study (no frontmatter)

Some content without YAML at the top.
"""

FIXTURE_PARTIAL = """\
---
case_id: partial-case
class: vault
---
# Partial frontmatter case
"""


# ---------------------------------------------------------------------------
# (a) Frontmatter parse tests
# ---------------------------------------------------------------------------

class TestFrontmatterParse(unittest.TestCase):

    def test_parse_full_frontmatter(self):
        """Full frontmatter block is parsed correctly."""
        fm = _parse_yaml_frontmatter(FIXTURE_BRIDGE)
        self.assertEqual(fm["case_id"], "test-bridge-case")
        self.assertEqual(fm["class"], "bridge")
        self.assertEqual(fm["severity_class"], "CRIT")
        self.assertIn("bridge", fm["applicable_workspace_classes"])
        self.assertIn("consensus", fm["applicable_workspace_classes"])
        self.assertEqual(len(fm["grep_predicates"]), 1)
        self.assertIn("finalizeWithdrawal", fm["grep_predicates"][0])
        self.assertIn("partial-deployment", fm.get("extracted_lesson", "").lower())

    def test_parse_no_frontmatter_returns_empty(self):
        """File without frontmatter returns empty dict."""
        fm = _parse_yaml_frontmatter(FIXTURE_NO_FRONTMATTER)
        self.assertEqual(fm, {})

    def test_parse_partial_frontmatter(self):
        """Partial frontmatter (only case_id + class) is parsed; missing keys default."""
        fm = _parse_yaml_frontmatter(FIXTURE_PARTIAL)
        self.assertEqual(fm["case_id"], "partial-case")
        self.assertEqual(fm["class"], "vault")
        # Missing keys not present in output
        self.assertNotIn("mechanism", fm)

    def test_parse_empty_list(self):
        """Empty list field (grep_predicates: []) parses as empty list."""
        fm = _parse_yaml_frontmatter(FIXTURE_METHODOLOGY)
        self.assertEqual(fm.get("grep_predicates", "NOT_FOUND"), [])

    def test_parse_info_severity(self):
        """INFO severity_class is parsed correctly."""
        fm = _parse_yaml_frontmatter(FIXTURE_METHODOLOGY)
        self.assertEqual(fm["severity_class"], "INFO")

    def test_load_case_study_from_file(self):
        """load_all_case_studies reads real case_study/ directory and finds frontmatter."""
        # Use the actual case_study directory — at least 10 files should have frontmatter now
        _CASE_STUDY_DIR = _mod._CASE_STUDY_DIR
        if not _CASE_STUDY_DIR.exists():
            self.skipTest("case_study/ dir not found")
        studies = load_all_case_studies(_CASE_STUDY_DIR)
        self.assertGreaterEqual(
            len(studies), 10,
            f"Expected >=10 case studies with frontmatter, got {len(studies)}",
        )
        for s in studies:
            self.assertIsInstance(s, CaseStudyMeta)
            self.assertTrue(s.case_id, f"case_id empty in {s.source_file}")


# ---------------------------------------------------------------------------
# (b) Match positive tests
# ---------------------------------------------------------------------------

class TestMatchPositive(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        _write_case_study(self.tmp_path, "bridge.md", FIXTURE_BRIDGE)
        _write_case_study(self.tmp_path, "lending.md", FIXTURE_LENDING)
        _write_case_study(self.tmp_path, "methodology.md", FIXTURE_METHODOLOGY)

    def tearDown(self):
        self.tmp.cleanup()

    def test_exact_class_match(self):
        """Exact class match on 'bridge' returns the bridge case study."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        self.assertTrue(len(results) >= 1)
        ids = [r.case_id for r in results]
        self.assertIn("test-bridge-case", ids)

    def test_exact_class_match_score(self):
        """Exact class match has higher score than applicable_workspace_classes match."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        bridge_match = next(r for r in results if r.case_id == "test-bridge-case")
        # Exact class (+3) * CRIT severity (1.5) = 4.5 minimum
        self.assertGreaterEqual(bridge_match.score, 4.0)

    def test_applicable_workspace_classes_match(self):
        """'oracle' matches the lending case via applicable_workspace_classes."""
        results = match_workspace("oracle", case_study_dir=self.tmp_path)
        ids = [r.case_id for r in results]
        self.assertIn("test-lending-case", ids)

    def test_prediction_market_matches_methodology(self):
        """'prediction-market' matches methodology case via applicable_workspace_classes."""
        results = match_workspace("prediction-market", case_study_dir=self.tmp_path)
        ids = [r.case_id for r in results]
        self.assertIn("test-methodology-case", ids)

    def test_results_sorted_by_score_descending(self):
        """Results are sorted by score descending."""
        results = match_workspace("lending", case_study_dir=self.tmp_path)
        scores = [r.score for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_grep_predicates_propagated(self):
        """grep_predicates from frontmatter are present in the match result."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        bridge_match = next(r for r in results if r.case_id == "test-bridge-case")
        self.assertIn("finalizeWithdrawal|proveWithdrawal", bridge_match.grep_predicates)

    def test_extracted_lesson_propagated(self):
        """extracted_lesson is propagated from frontmatter."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        bridge_match = next(r for r in results if r.case_id == "test-bridge-case")
        self.assertIn("cross-version", bridge_match.extracted_lesson)

    def test_case_study_enforcement_frontmatter_fields_propagated(self):
        """F2 enforcement frontmatter fields are preserved through match results."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        bridge_match = next(r for r in results if r.case_id == "test-bridge-case")
        self.assertIn("live validator set", bridge_match.stop_criterion)
        self.assertEqual(bridge_match.workflow_signature, "bridge_deployment_state_without_live_check")
        self.assertEqual(bridge_match.loop_back_phase, "phase-3-live-state-check")
        as_dict = bridge_match.as_dict()
        self.assertIn("stop_criterion", as_dict)
        self.assertEqual(as_dict["workflow_signature"], "bridge_deployment_state_without_live_check")
        self.assertEqual(as_dict["loop_back_phase"], "phase-3-live-state-check")


# ---------------------------------------------------------------------------
# (c) Match negative tests
# ---------------------------------------------------------------------------

class TestMatchNegative(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        _write_case_study(self.tmp_path, "bridge.md", FIXTURE_BRIDGE)
        _write_case_study(self.tmp_path, "no_fm.md", FIXTURE_NO_FRONTMATTER)

    def tearDown(self):
        self.tmp.cleanup()

    def test_unrelated_class_returns_empty(self):
        """An unrelated class ('nft') returns no matches from bridge-only fixture set."""
        results = match_workspace("nft", case_study_dir=self.tmp_path)
        self.assertEqual(results, [])

    def test_file_without_frontmatter_not_returned(self):
        """Files without frontmatter are not included in results."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        ids = [r.case_id for r in results]
        # no_fm.md has no frontmatter — should not appear
        for cid in ids:
            self.assertNotEqual(cid, "no_fm")

    def test_top_n_respected(self):
        """top_n limit is respected even when more matches exist."""
        _write_case_study(self.tmp_path, "bridge2.md", FIXTURE_BRIDGE.replace(
            "test-bridge-case", "test-bridge-case-2"
        ))
        results = match_workspace("bridge", top_n=1, case_study_dir=self.tmp_path)
        self.assertEqual(len(results), 1)

    def test_score_function_zero_for_no_match(self):
        """_score returns (0.0, '') for a case study with unrelated class."""
        meta = CaseStudyMeta(
            case_id="x",
            class_="bridge",
            severity_class="CRIT",
            applicable_workspace_classes=["consensus"],
        )
        score, reason = _score(meta, "nft")
        self.assertEqual(score, 0.0)
        self.assertEqual(reason, "")


# ---------------------------------------------------------------------------
# (d) Multi-class workspace tests
# ---------------------------------------------------------------------------

class TestMultiClassWorkspace(unittest.TestCase):
    """
    Tests for a workspace that spans multiple classes (e.g. a vault that uses an oracle).
    The caller can call match_workspace() multiple times, once per class, and merge results.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        _write_case_study(self.tmp_path, "bridge.md", FIXTURE_BRIDGE)
        _write_case_study(self.tmp_path, "lending.md", FIXTURE_LENDING)
        _write_case_study(self.tmp_path, "methodology.md", FIXTURE_METHODOLOGY)

    def tearDown(self):
        self.tmp.cleanup()

    def test_multi_class_aggregation(self):
        """Aggregating results across multiple workspace classes yields all relevant case studies."""
        classes = ["bridge", "oracle", "workflow-methodology"]
        seen: set[str] = set()
        all_results: list[CaseMatch] = []
        for wc in classes:
            for m in match_workspace(wc, case_study_dir=self.tmp_path):
                if m.case_id not in seen:
                    seen.add(m.case_id)
                    all_results.append(m)

        ids = {r.case_id for r in all_results}
        self.assertIn("test-bridge-case", ids)
        self.assertIn("test-lending-case", ids)  # oracle -> lending applicable
        self.assertIn("test-methodology-case", ids)

    def test_as_dict_serializable(self):
        """CaseMatch.as_dict() produces JSON-serializable output."""
        results = match_workspace("bridge", case_study_dir=self.tmp_path)
        self.assertTrue(len(results) > 0)
        dicts = [r.as_dict() for r in results]
        # Should not raise
        json_str = json.dumps(dicts)
        loaded = json.loads(json_str)
        self.assertEqual(len(loaded), len(dicts))

    def test_real_repo_bridge_class(self):
        """Real case_study/ dir returns at least 1 match for 'bridge'."""
        _CASE_STUDY_DIR = _mod._CASE_STUDY_DIR
        if not _CASE_STUDY_DIR.exists():
            self.skipTest("case_study/ dir not found")
        results = match_workspace("bridge", case_study_dir=_CASE_STUDY_DIR)
        self.assertGreaterEqual(len(results), 1, "Expected >=1 bridge match in real case_study/")

    def test_real_repo_prediction_market_class(self):
        """Real case_study/ dir returns at least 3 matches for 'prediction-market'."""
        _CASE_STUDY_DIR = _mod._CASE_STUDY_DIR
        if not _CASE_STUDY_DIR.exists():
            self.skipTest("case_study/ dir not found")
        results = match_workspace("prediction-market", case_study_dir=_CASE_STUDY_DIR)
        self.assertGreaterEqual(len(results), 3, "Expected >=3 prediction-market matches in real case_study/")

    def test_real_repo_lending_class(self):
        """Real case_study/ dir returns at least 1 match for 'lending'."""
        _CASE_STUDY_DIR = _mod._CASE_STUDY_DIR
        if not _CASE_STUDY_DIR.exists():
            self.skipTest("case_study/ dir not found")
        results = match_workspace("lending", case_study_dir=_CASE_STUDY_DIR)
        self.assertGreaterEqual(len(results), 1, "Expected >=1 lending match in real case_study/")


class TestResumeCaseStudyLogic(unittest.TestCase):
    def test_resume_case_study_logic_exposes_enforcement_fields(self):
        """vault_resume_context case_study_logic preserves F2 enforcement frontmatter."""
        rows = _mcp_mod._case_study_logic(None)
        self.assertTrue(rows)
        row = next((r for r in rows if r.get("workflow_signature")), rows[0])
        self.assertIn("stop_criterion", row)
        self.assertIn("workflow_signature", row)
        self.assertIn("loop_back_phase", row)


if __name__ == "__main__":
    unittest.main()
