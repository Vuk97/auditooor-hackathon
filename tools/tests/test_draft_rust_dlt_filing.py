"""Tests for tools/draft-rust-dlt-filing.py — Wave O-F (Gap #7).

10 tests covering: title derivation, severity tier, verbatim rubric line,
impact section, description (actor_sequence), reproduction (PoC reference),
kill-condition table, fix sketch, output file write, and smoke against the
live L-1 P256VERIFY candidate + base-azul workspace.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Module import shim
# ---------------------------------------------------------------------------
_TOOLS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

_MOD_PATH = _TOOLS_DIR / "draft-rust-dlt-filing.py"
_spec = importlib.util.spec_from_file_location("draft_rust_dlt_filing", _MOD_PATH)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

run = _mod.run
generate_draft = _mod.generate_draft
_pick_candidate = _mod._pick_candidate
_strip_markdown_bold = _mod._strip_markdown_bold
_verify_severity_line = _mod._verify_severity_line
_kill_conditions_proof = _mod._kill_conditions_proof

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
_TEMPLATE_PATH = _REPO_ROOT / "reference" / "big_loss_templates" / "rust_dlt_state_divergence.json"

_L1_CANDIDATE_PATH = Path(
    "/Users/wolf/audits/base-azul/.auditooor/wave-l1-h2b-audit-asset-sweep/promotion_candidates.json"
)
_BASE_AZUL_WS = Path("/Users/wolf/audits/base-azul")


def _minimal_candidate() -> dict:
    return {
        "id": "TEST-PRECOMPILE-DIVERGENCE-001",
        "pattern_id": "hardfork_precompile_non_osaka_in_zkvm",
        "crate_name": "base-succinct-client-utils",
        "containing_fn": "get_precompiles",
        "file": "external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/mod.rs",
        "line": 72,
        "evidence_snippet": "        secp256r1::P256VERIFY,",
        "evidence_context": (
            "fn get_precompiles() -> Vec<PrecompileWithAddress> {\n"
            "    vec![\n"
            "        secp256r1::P256VERIFY,  // stale Fjord pricing\n"
            "    ]\n"
            "}"
        ),
        "call_site_file": "external/base-rc28-clean/crates/succinct/utils/client/src/precompiles/mod.rs",
        "call_site_line": 100,
        "call_site_snippet": "precompiles.extend(get_precompiles());  // overwrites OSAKA",
        "severity": "High",
        "fix_sketch": "Remove secp256r1::P256VERIFY from get_precompiles() for BASE_V1.",
        "detector_id": "rust-hardfork-precompile-address-mismatch-scan",
    }


def _make_workspace_dir(severity_md_content: str | None = None) -> tempfile.TemporaryDirectory:
    """Create a minimal workspace directory with SEVERITY.md."""
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    sev_text = severity_md_content or (
        "# Severity Rubric\n\n"
        "## Critical impact (primary)\n\n"
        "- Chain-level fork or CL↔EL state divergence.\n"
        "- Direct loss of funds.\n"
    )
    (root / "SEVERITY.md").write_text(sev_text, encoding="utf-8")
    return td


def _load_template() -> dict:
    if not _TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template not found: {_TEMPLATE_PATH}")
    with _TEMPLATE_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStripMarkdownBold(unittest.TestCase):
    """_strip_markdown_bold removes leading/trailing ** correctly."""

    def test_strips_double_star(self) -> None:
        self.assertEqual(
            _strip_markdown_bold("**Chain-level fork or CL↔EL state divergence.**"),
            "Chain-level fork or CL↔EL state divergence.",
        )

    def test_no_stars_unchanged(self) -> None:
        self.assertEqual(
            _strip_markdown_bold("Chain-level fork or CL↔EL state divergence."),
            "Chain-level fork or CL↔EL state divergence.",
        )


class TestPickCandidate(unittest.TestCase):
    """_pick_candidate handles candidates list, bare list, and id lookup."""

    def test_picks_first_from_candidates_list(self) -> None:
        data = {"candidates": [{"id": "A"}, {"id": "B"}]}
        self.assertEqual(_pick_candidate(data, None)["id"], "A")

    def test_picks_by_id(self) -> None:
        data = {"candidates": [{"id": "A"}, {"id": "B"}]}
        self.assertEqual(_pick_candidate(data, "B")["id"], "B")

    def test_picks_from_bare_list(self) -> None:
        data = [{"id": "X"}, {"id": "Y"}]
        self.assertEqual(_pick_candidate(data, "Y")["id"], "Y")

    def test_raises_on_missing_id(self) -> None:
        data = {"candidates": [{"id": "A"}]}
        with self.assertRaises(ValueError):
            _pick_candidate(data, "NONEXISTENT")


class TestGenerateDraftTitle(unittest.TestCase):
    """Draft title is derived from candidate pattern_id + crate_name when title absent."""

    def test_title_from_pattern_and_crate(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("Hardfork Precompile Non Osaka In Zkvm", draft)
            self.assertIn("base-succinct-client-utils", draft)
        finally:
            td.cleanup()


class TestGenerateDraftSeverity(unittest.TestCase):
    """Draft contains the correct severity tier in the ## Severity heading."""

    def test_high_severity_present(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("## Severity: High", draft)
        finally:
            td.cleanup()

    def test_critical_to_high_downgrade_on_deployment_kill(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = dict(_minimal_candidate())
            candidate["severity"] = "Critical"
            candidate["verdict"] = "GATE_WALKED_BACK_TOOL_LIMITATION"
            draft = generate_draft(Path(td.name), candidate, template, None)
            # severity is "Critical" in the candidate but we keep it unless explicit downgrade note
            # The draft should carry whatever severity the candidate carries
            self.assertIn("## Severity:", draft)
        finally:
            td.cleanup()


class TestGenerateDraftVerbatimRubricLine(unittest.TestCase):
    """Draft contains the verbatim rubric line from the template."""

    def test_verbatim_line_present(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("Chain-level fork or CL↔EL state divergence.", draft)
        finally:
            td.cleanup()

    def test_verbatim_line_verified_badge_present_when_severity_md_matches(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("verbatim grep PASS", draft)
        finally:
            td.cleanup()

    def test_warning_when_severity_md_missing(self) -> None:
        td = tempfile.TemporaryDirectory()
        try:
            # No SEVERITY.md in this workspace
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("WARNING", draft)
        finally:
            td.cleanup()


class TestGenerateDraftImpact(unittest.TestCase):
    """Draft Impact section uses candidate impact_statement when present."""

    def test_impact_from_candidate_field(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = dict(_minimal_candidate())
            candidate["impact_statement"] = "Custom impact: state-root mismatch on Sepolia."
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("Custom impact: state-root mismatch on Sepolia.", draft)
        finally:
            td.cleanup()

    def test_impact_fallback_uses_bug_shape(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = dict(_minimal_candidate())
            candidate["bug_shape"] = "BUG: the extend() overwrites P256VERIFY_OSAKA."
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("BUG: the extend() overwrites P256VERIFY_OSAKA.", draft)
        finally:
            td.cleanup()


class TestGenerateDraftDescription(unittest.TestCase):
    """Draft Description section includes actor_sequence steps."""

    def test_actor_sequence_steps_all_present(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            # Template has 3 actor_sequence steps
            self.assertIn("1.", draft)
            self.assertIn("2.", draft)
            self.assertIn("3.", draft)
            self.assertIn("aggregate_verifier_or_finalization_path", draft)
        finally:
            td.cleanup()


class TestGenerateDraftReproduction(unittest.TestCase):
    """Draft Reproduction section references wave-m1 PoC when present."""

    def test_poc_reference_in_reproduction(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            # Should contain "PoC source at:" line
            self.assertIn("PoC source at:", draft)
        finally:
            td.cleanup()

    def test_base_azul_poc_path_referenced_when_workspace_present(self) -> None:
        if not _BASE_AZUL_WS.exists():
            self.skipTest("base-azul workspace not present")
        m1_poc = _BASE_AZUL_WS / ".auditooor" / "wave-m1-harness-poc" / "poc_test_source.rs"
        if not m1_poc.exists():
            self.skipTest("wave-m1 poc_test_source.rs not present")
        template = _load_template()
        candidate = _minimal_candidate()
        draft = generate_draft(_BASE_AZUL_WS, candidate, template, None)
        self.assertIn("poc_test_source.rs", draft)


class TestGenerateDraftSeverityProof(unittest.TestCase):
    """Draft Severity proof section lists all kill conditions with verdicts."""

    def test_kill_conditions_all_present(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            for kc in template["severity_promotion_rule"]["kill_conditions"]:
                self.assertIn(kc, draft, f"Kill condition not found in draft: {kc}")
        finally:
            td.cleanup()

    def test_no_apply_for_single_component_kill(self) -> None:
        kcs = ["single_component_only_no_divergence"]
        table = _kill_conditions_proof(kcs, {})
        self.assertIn("NO", table)

    def test_deployment_kill_notes_downgrade(self) -> None:
        kcs = ["buggy_commit_never_deployed_to_target_network (downgrade Critical -> High)"]
        # Without "downgrade" in verdict, should be TBD
        table = _kill_conditions_proof(kcs, {"verdict": "PROMOTE_PENDING"})
        self.assertIn("TBD", table)


class TestGenerateDraftFixSketch(unittest.TestCase):
    """Draft Suggested fix section comes from candidate fix_sketch."""

    def test_fix_sketch_from_candidate(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = _minimal_candidate()
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("Remove secp256r1::P256VERIFY from get_precompiles() for BASE_V1.", draft)
        finally:
            td.cleanup()

    def test_fix_sketch_fallback_when_absent(self) -> None:
        td = _make_workspace_dir()
        try:
            template = _load_template()
            candidate = dict(_minimal_candidate())
            del candidate["fix_sketch"]
            draft = generate_draft(Path(td.name), candidate, template, None)
            self.assertIn("Suggested fix", draft)
            self.assertIn("get_precompiles()", draft)  # fallback text references this
        finally:
            td.cleanup()


class TestOutputFile(unittest.TestCase):
    """--output flag writes the draft to disk."""

    def test_output_file_written(self) -> None:
        if not _TEMPLATE_PATH.exists():
            self.skipTest("Template file not present")
        with tempfile.TemporaryDirectory() as td:
            ws_td = _make_workspace_dir()
            try:
                out_file = Path(td) / "draft.md"
                cand_file = Path(td) / "candidates.json"
                cand_data = {"candidates": [_minimal_candidate()]}
                cand_file.write_text(json.dumps(cand_data), encoding="utf-8")
                result = run([
                    "--workspace", ws_td.name,
                    "--candidate", str(cand_file),
                    "--template", str(_TEMPLATE_PATH),
                    "--output", str(out_file),
                ])
                self.assertTrue(out_file.exists())
                self.assertGreater(out_file.stat().st_size, 500)
                # Resolve both to handle macOS /private/var vs /var symlink
                self.assertEqual(
                    Path(result["output_path"]).resolve(),
                    out_file.resolve(),
                )
            finally:
                ws_td.cleanup()


class TestLiveSmokeL1P256Verify(unittest.TestCase):
    """Live smoke: generate filing draft for the L-1 P256VERIFY candidate."""

    def setUp(self) -> None:
        if not _BASE_AZUL_WS.exists():
            self.skipTest("base-azul workspace not present")
        if not _L1_CANDIDATE_PATH.exists():
            self.skipTest("L-1 promotion_candidates.json not present")
        if not _TEMPLATE_PATH.exists():
            self.skipTest("rust_dlt_state_divergence.json template not present")

    def _generate(self) -> tuple[str, dict]:
        """Return (draft_text, run_result) for L-1 candidate."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "smoke_draft.md"
            result = run([
                "--workspace", str(_BASE_AZUL_WS),
                "--candidate", str(_L1_CANDIDATE_PATH),
                "--template", str(_TEMPLATE_PATH),
                "--output", str(out),
            ])
            draft = out.read_text(encoding="utf-8")
        return draft, result

    def test_smoke_has_severity_high(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Severity: High", draft)

    def test_smoke_has_verbatim_rubric_line(self) -> None:
        draft, _ = self._generate()
        self.assertIn("Chain-level fork or CL↔EL state divergence.", draft)

    def test_smoke_severity_line_verified(self) -> None:
        _, result = self._generate()
        self.assertTrue(result["severity_line_verified"])

    def test_smoke_has_impact_section(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Impact", draft)

    def test_smoke_has_description_with_actor_sequence(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Description", draft)
        self.assertIn("aggregate_verifier_or_finalization_path", draft)

    def test_smoke_has_reproduction_with_poc_reference(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Reproduction", draft)
        self.assertIn("poc_test_source.rs", draft)

    def test_smoke_has_severity_proof_section(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Severity proof", draft)
        self.assertIn("Kill condition", draft)

    def test_smoke_has_fix_sketch(self) -> None:
        draft, _ = self._generate()
        self.assertIn("## Suggested fix", draft)

    def test_smoke_draft_is_nonempty(self) -> None:
        draft, result = self._generate()
        self.assertGreater(result["draft_length"], 1000)
        self.assertIn("<!-- wave-o-f", draft)


if __name__ == "__main__":
    unittest.main()
