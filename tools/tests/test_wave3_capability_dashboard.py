"""Tests for tools/wave3-capability-dashboard.py.

Synthetic fixtures only.  Each fixture workspace is marked
``synthetic_fixture: true`` per operator emphasis.  No corpus material
is created here; we exercise each dashboard section via fake workspaces.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave3-capability-dashboard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave3_capability_dashboard", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


DASH = _load_module()


def _make_fake_workspace(tmp: Path, *, with_dsl: int = 3, with_detectors: bool = True,
                        with_mcp: bool = True, with_followups_doc: bool = False,
                        with_lane_spec: bool = False,
                        with_cross_protocol_doc: bool = False) -> Path:
    """Synthetic fixture builder (synthetic_fixture: true).

    No corpus material is touched; we create empty placeholder files in
    the structure the dashboard expects.
    """
    ws = tmp / "fake_ws"
    ws.mkdir()
    # marker file
    (ws / "SYNTHETIC_FIXTURE.txt").write_text("synthetic_fixture: true\n")
    # corpus tags / dsl patterns
    if with_dsl > 0:
        tags = ws / "audit" / "corpus_tags" / "tags"
        tags.mkdir(parents=True)
        for i in range(with_dsl):
            (tags / f"dsl_pattern_synthetic_fixture_{i:03d}.yaml").write_text(
                "synthetic_fixture: true\nid: synthetic\n"
            )
    if with_detectors:
        det = ws / "detectors"
        det.mkdir(parents=True, exist_ok=True)
        # one rust language subdir + one wave subdir
        (det / "rust_wave1").mkdir(parents=True, exist_ok=True)
        for i in range(5):
            (det / "rust_wave1" / f"synthetic_detector_{i:02d}.py").write_text(
                "# synthetic_fixture: true\nclass D: pass\n"
            )
        (det / "wave12").mkdir(parents=True, exist_ok=True)
        for i in range(3):
            (det / "wave12" / f"synthetic_wave12_{i:02d}.py").write_text(
                "# synthetic_fixture: true\nclass D: pass\n"
            )
    if with_mcp:
        tools = ws / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        # MCP server with three callables.
        # Schema names live on their own line to match real
        # vault-mcp-server.py shape (TOOL_SCHEMAS entries spread across
        # multiple lines).
        (tools / "vault-mcp-server.py").write_text(textwrap.dedent('''
            # synthetic_fixture: true
            TOOL_SCHEMAS = [
                {
                    "name": "vault_alpha",
                },
                {
                    "name": "vault_beta",
                },
                {
                    "name": "vault_gamma",
                },
            ]
            class Server:
                def vault_alpha(self): pass
                def vault_beta(self): pass
                def vault_gamma(self): pass
                def dispatch(self, name):
                    if name == "vault_alpha":
                        return self.vault_alpha()
                    if name == "vault_beta":
                        return self.vault_beta()
                    if name == "vault_gamma":
                        return self.vault_gamma()
        ''').lstrip())
        tests = tools / "tests"
        tests.mkdir(parents=True, exist_ok=True)
        # Cover 2 of 3 callables (alpha + beta), leave gamma uncovered.
        (tests / "test_vault_alpha.py").write_text("# synthetic_fixture: true\n")
        (tests / "test_vault_beta.py").write_text("# synthetic_fixture: true\n")
    if with_followups_doc:
        docs = ws / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        (docs / "WAVE3_FOLLOWUPS_FROM_WAVE2_2026-05-16.md").write_text(textwrap.dedent("""
            # synthetic_fixture: true Wave-3 follow-ups

            - [ ] one open item
            - [ ] another open item
            - [x] one completed item
        """).lstrip())
    if with_lane_spec:
        docs = ws / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        (docs / "WAVE3_LANE_SETUP_SPEC_2026-05-16.md").write_text(textwrap.dedent("""
            # synthetic_fixture: true lane spec
            W3.01 first lane
            W3.02 second lane
            W3.03 third lane
        """).lstrip())
    if with_cross_protocol_doc:
        docs = ws / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        (docs / "WAVE3_CROSS_PROTOCOL_PATTERN_TRANSFER_2026-05-16.md").write_text(textwrap.dedent("""
            # synthetic_fixture: true

            ## Universal patterns
            - first universal
            - second universal
            - third universal

            ## Stack-specific patterns
            - first stack-specific
            - second stack-specific
        """).lstrip())
    return ws


class TestDetectorInventory(unittest.TestCase):

    def test_single_workspace_runs_clean(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t))
            section = DASH.section_a_detector_inventory(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["dsl_pattern_yaml_count"], 3)
            # 5 rust + 3 wave12
            self.assertEqual(section["metrics"]["abstract_detector_py_count"], 8)
            self.assertEqual(section["metrics"]["total_detectors"], 11)

    def test_missing_dirs_emits_diagnostics_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "empty_ws"
            ws.mkdir()
            section = DASH.section_a_detector_inventory(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["total_detectors"], 0)
            self.assertTrue(any("tags_dir_missing" in d for d in section["diagnostics"]))


class TestMCPCallableInventory(unittest.TestCase):

    def test_extracts_callables_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t))
            section = DASH.section_b_mcp_callable_inventory(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["total_callables"], 3)
            self.assertEqual(section["metrics"]["covered_callables"], 2)
            # 2/3 = 66.7%
            self.assertAlmostEqual(section["metrics"]["test_coverage_pct"], 66.7, delta=0.1)

    def test_missing_server_emits_skip(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "empty_ws"
            ws.mkdir()
            section = DASH.section_b_mcp_callable_inventory(ws)
            self.assertEqual(section["status"], "SKIP")


class TestPerWorkspace(unittest.TestCase):

    def test_missing_workspaces_handled(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            audits = Path(t) / "fake_audits_root"
            audits.mkdir()
            # One present, two missing
            (audits / "alpha").mkdir()
            (audits / "alpha" / "engage_report.md").write_text(textwrap.dedent("""
                # synthetic_fixture: true engage report
                - Total hits: **42**
                Distinct detectors: 7
                Analogical clusters: 5
            """).lstrip())
            section = DASH.section_c_per_workspace(
                ["alpha", "beta", "gamma"], audits_root=audits
            )
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["active_workspaces"], 1)
            self.assertEqual(
                section["metrics"]["workspaces"]["alpha"]["engage_report"]["total_hits"], 42
            )


class TestCrossProtocolTransfer(unittest.TestCase):

    def test_missing_doc_emits_skip(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t) / "ws"
            ws.mkdir()
            section = DASH.section_d_cross_protocol_transfer(ws)
            self.assertEqual(section["status"], "SKIP")

    def test_parses_doc_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t), with_cross_protocol_doc=True)
            section = DASH.section_d_cross_protocol_transfer(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["universal_patterns"], 3)
            self.assertEqual(section["metrics"]["stack_specific_patterns"], 2)
            self.assertEqual(section["metrics"]["total_patterns"], 5)


class TestFollowupsAndLaneProgress(unittest.TestCase):

    def test_followups_open_done_counts(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t), with_followups_doc=True)
            section = DASH.section_g_wave3_followups(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["open_followups"], 2)
            self.assertEqual(section["metrics"]["done_followups"], 1)

    def test_lane_spec_present(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t), with_lane_spec=True)
            section = DASH.section_f_wave3_lane_progress(ws)
            self.assertEqual(section["status"], "OK")
            self.assertEqual(section["metrics"]["lane_count"], 3)


class TestFullDashboard(unittest.TestCase):

    def test_json_output_schema_conformance(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(
                Path(t),
                with_followups_doc=True,
                with_lane_spec=True,
                with_cross_protocol_doc=True,
            )
            audits = Path(t) / "audits"
            audits.mkdir()
            dash = DASH.build_dashboard(
                ws,
                include_workspaces=["nonexistent"],
                audits_root=audits,
                include_test_failures=False,
            )
            self.assertEqual(dash["schema_id"], DASH.SCHEMA_ID)
            self.assertIn("generated_at", dash)
            self.assertIn("sections", dash)
            self.assertIn("headline_metrics", dash)
            for key in (
                "total_detectors",
                "mcp_callables",
                "mcp_test_coverage_pct",
                "total_tier6_seeds",
                "active_workspaces",
                "wave2_a_status",
                "wave2_b_status",
                "wave3_followups_remaining",
            ):
                self.assertIn(key, dash["headline_metrics"])
            # JSON-serializable check
            blob = json.dumps(dash)
            self.assertGreater(len(blob), 100)

    def test_markdown_renders_valid_table_format(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t), with_followups_doc=True)
            audits = Path(t) / "audits"
            audits.mkdir()
            dash = DASH.build_dashboard(
                ws,
                include_workspaces=["nope"],
                audits_root=audits,
                include_test_failures=False,
            )
            md = DASH.render_markdown(dash)
            self.assertIn("# Wave-3 capability dashboard", md)
            self.assertIn("## Headline metrics", md)
            # Headline must include each headline metric key.
            for key in dash["headline_metrics"]:
                self.assertIn(key, md)
            # GitHub table header presence
            self.assertIn("| metric | value |", md)
            self.assertIn("|---|---|", md)
            # No em-dashes or en-dashes (R-formatting)
            self.assertNotIn("—", md)
            self.assertNotIn("–", md)

    def test_headline_metric_math_consistency(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            ws = _make_fake_workspace(Path(t))
            audits = Path(t) / "audits"
            audits.mkdir()
            dash = DASH.build_dashboard(
                ws,
                include_workspaces=["nope"],
                audits_root=audits,
                include_test_failures=False,
            )
            # total_detectors equals A.total_detectors
            self.assertEqual(
                dash["headline_metrics"]["total_detectors"],
                dash["sections"]["A_detector_inventory"]["metrics"]["total_detectors"],
            )
            # Sum-of-by-language equals abstract_detector_py_count
            a = dash["sections"]["A_detector_inventory"]["metrics"]
            # DSL pattern subkey is folded into by_language separately.
            non_dsl = sum(v for k, v in a["by_language"].items() if k != "dsl_pattern_corpus")
            self.assertEqual(non_dsl, a["abstract_detector_py_count"])


if __name__ == "__main__":
    unittest.main()
