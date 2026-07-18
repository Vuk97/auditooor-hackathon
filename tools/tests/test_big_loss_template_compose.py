"""Tests for tools/big-loss-template-compose.py — Wave C-1A P0-6a.

Foot-gun #1: inline tempfile strings, not patterns/fixtures/ directory.
Foot-gun #2: no // VULN / // missing comment markers.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Allow importing from tools/ directly when run via unittest discovery
_TOOLS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _TOOLS_DIR.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

import importlib.util
_COMPOSE_PATH = _TOOLS_DIR / "big-loss-template-compose.py"
_spec = importlib.util.spec_from_file_location("big_loss_template_compose", _COMPOSE_PATH)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
run = _mod.run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workspace(
    rows: list[dict],
    severity_md_content: str | None = None,
    impact_contracts: dict | None = None,
) -> tempfile.TemporaryDirectory:
    """Return a TemporaryDirectory with a minimal workspace layout."""
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    (root / ".auditooor").mkdir()

    # invariant_ledger.json
    ledger = {
        "schema_version": "auditooor.invariant_ledger.v1",
        "workspace": str(root),
        "rows": rows,
    }
    (root / ".auditooor" / "invariant_ledger.json").write_text(json.dumps(ledger))

    # SEVERITY.md
    if severity_md_content is None:
        # Use a realistic snippet matching what the real file contains
        severity_md_content = (
            "# Severity Rubric\n\n"
            "## 2. Base Azul — operator-brief Critical impacts (program-specific)\n\n"
            "- **Chain-level fork or CL↔EL state divergence.**\n\n"
            "## 3. Immunefi v2.3 — Blockchain / DLT\n\n"
            "### Critical\n\n"
            "- Network not being able to confirm new transactions (total network shutdown).\n"
            "- Unintended permanent chain split requiring hard fork.\n"
            "- Direct loss of funds.\n"
            "- Permanent freezing of funds (fix requires hardfork).\n"
        )
    (root / "SEVERITY.md").write_text(severity_md_content)

    # impact_contracts.json (optional)
    if impact_contracts is not None:
        (root / ".auditooor" / "impact_contracts.json").write_text(
            json.dumps(impact_contracts)
        )

    return td


_FN6_ROW = {
    "id": "BASE-SC-I01",
    "invariant_family": "BASE-SC-PROOF-DOMAIN",
    "production_path": "Proposer -> AggregateVerifier.verify(proofType, proofData, ...) -> multiproof/AggregateVerifier.sol",
    "severity": "Critical",
    "status": "executed_clean",
}

_GV01_ROW = {
    "id": "BASE-DLT-FN8",
    "invariant_family": "BASE-DLT-DEPOSITS-ONLY-CLASSIFIER",
    "production_path": "engine derivation -> AttributesWithParent -> consensus/derive/attributes.rs is_deposits_only -> seal/task",
    "severity": "Critical",
    "status": "killed",
}

_NO_MATCH_ROW = {
    "id": "POLYMARKET-XYZ-01",
    "invariant_family": "polymarket_clob_order_lifecycle",
    "production_path": "CTFExchange.fillOrder() -> orderbook",
    "severity": "Medium",
    "status": "missing_harness",
}


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestBridgeProofDomainMatch(unittest.TestCase):
    """Valid bridge_proof_domain match: FN6-shape ledger row -> composed manifest."""

    def test_fn6_shape_composes(self) -> None:
        td = _make_workspace([_FN6_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "BASE-SC-I01", "--print-json"])
        finally:
            td.cleanup()

        self.assertEqual(result["total_rows"], 1)
        self.assertEqual(result["composed"], 1)
        manifests = result["manifests"]
        self.assertEqual(len(manifests), 1)
        m = manifests[0]
        self.assertEqual(m["composed_status"], "composed")
        self.assertEqual(m["template_id"], "bridge_proof_domain")
        self.assertEqual(m["row_id"], "BASE-SC-I01")
        self.assertTrue(len(m["actor_sequence"]) >= 4)
        self.assertTrue(m["severity_promotion_rule_check"]["severity_md_line_verified"])
        self.assertIn("Direct loss of funds.", m["severity_promotion_rule_check"]["verbatim_severity_md_line"])
        self.assertIsNotNone(m["next_command"])
        self.assertIn("harness-scaffold", m["next_command"])


class TestConsensusParserDifferentialMatch(unittest.TestCase):
    """Valid consensus_parser_differential match: G-v01-shape row -> composed manifest."""

    def test_gv01_shape_composes(self) -> None:
        td = _make_workspace([_GV01_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "BASE-DLT-FN8"])
        finally:
            td.cleanup()

        self.assertEqual(result["total_rows"], 1)
        m = result["manifests"][0]
        self.assertEqual(m["composed_status"], "composed")
        self.assertEqual(m["template_id"], "consensus_parser_differential")
        self.assertEqual(m["row_id"], "BASE-DLT-FN8")
        self.assertTrue(len(m["actor_sequence"]) >= 5)
        self.assertTrue(m["severity_promotion_rule_check"]["severity_md_line_verified"])
        self.assertIn("Chain-level fork", m["severity_promotion_rule_check"]["verbatim_severity_md_line"])
        self.assertEqual(m["harness_blueprint"]["engine"], "cargo_test")


class TestNoMatch(unittest.TestCase):
    """No-match row -> composed_status=blocked_no_template."""

    def test_no_match_row(self) -> None:
        td = _make_workspace([_NO_MATCH_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "POLYMARKET-XYZ-01"])
        finally:
            td.cleanup()

        self.assertEqual(result["composed"], 0)
        self.assertEqual(result["blocked_no_template"], 1)
        m = result["manifests"][0]
        self.assertEqual(m["composed_status"], "blocked_no_template")
        self.assertIsNone(m["template_id"])


class TestM14TrapSeverityLineNotVerified(unittest.TestCase):
    """M14-trap: synthetic SEVERITY.md missing the cited line -> blocked_severity_line_not_verified."""

    def test_missing_severity_line_blocks(self) -> None:
        # SEVERITY.md that does NOT contain "Direct loss of funds." or the chain-fork line
        bad_sev = "# Severity Rubric\n\n- Some other impact.\n- Another impact.\n"
        td = _make_workspace([_FN6_ROW], severity_md_content=bad_sev)
        try:
            result = run(["--workspace", td.name, "--row", "BASE-SC-I01"])
        finally:
            td.cleanup()

        m = result["manifests"][0]
        self.assertEqual(m["composed_status"], "blocked_severity_line_not_verified")
        self.assertFalse(m["severity_promotion_rule_check"]["severity_md_line_verified"])

    def test_missing_chain_fork_line_blocks(self) -> None:
        bad_sev = "# Severity Rubric\n\n- Direct loss of funds.\n"
        td = _make_workspace([_GV01_ROW], severity_md_content=bad_sev)
        try:
            result = run(["--workspace", td.name, "--row", "BASE-DLT-FN8"])
        finally:
            td.cleanup()

        m = result["manifests"][0]
        self.assertEqual(m["composed_status"], "blocked_severity_line_not_verified")


class TestSchemaValidation(unittest.TestCase):
    """Composed manifest validates against auditooor.big_loss_template_composed.v1 shape."""

    REQUIRED_TOP = {
        "schema_version", "template_id", "row_id", "composed_status",
        "actor_sequence", "harness_blueprint", "severity_promotion_rule_check",
        "next_command",
    }
    REQUIRED_SPR = {"verbatim_severity_md_line", "severity_md_line_verified"}

    def test_composed_manifest_has_required_fields(self) -> None:
        td = _make_workspace([_FN6_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "BASE-SC-I01"])
        finally:
            td.cleanup()

        m = result["manifests"][0]
        self.assertTrue(self.REQUIRED_TOP.issubset(m.keys()), f"Missing: {self.REQUIRED_TOP - m.keys()}")
        self.assertEqual(m["schema_version"], "auditooor.big_loss_template_composed.v1")
        spr = m["severity_promotion_rule_check"]
        self.assertTrue(self.REQUIRED_SPR.issubset(spr.keys()), f"Missing: {self.REQUIRED_SPR - spr.keys()}")

    def test_actor_sequence_steps_have_required_fields(self) -> None:
        td = _make_workspace([_FN6_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "BASE-SC-I01"])
        finally:
            td.cleanup()

        steps = result["manifests"][0]["actor_sequence"]
        self.assertTrue(len(steps) > 0)
        for step in steps:
            for field in ("step", "actor", "action", "target", "prerequisite", "evidence_required"):
                self.assertIn(field, step, f"actor_sequence step missing: {field}")

    def test_blocked_manifest_has_required_fields(self) -> None:
        td = _make_workspace([_NO_MATCH_ROW])
        try:
            result = run(["--workspace", td.name, "--row", "POLYMARKET-XYZ-01"])
        finally:
            td.cleanup()

        m = result["manifests"][0]
        self.assertTrue(self.REQUIRED_TOP.issubset(m.keys()), f"Missing: {self.REQUIRED_TOP - m.keys()}")
        self.assertEqual(m["schema_version"], "auditooor.big_loss_template_composed.v1")


class TestMultipleRows(unittest.TestCase):
    """Multiple rows: correct counts emitted."""

    def test_mixed_rows(self) -> None:
        td = _make_workspace([_FN6_ROW, _GV01_ROW, _NO_MATCH_ROW])
        try:
            result = run(["--workspace", td.name])
        finally:
            td.cleanup()

        self.assertEqual(result["total_rows"], 3)
        self.assertEqual(result["composed"], 2)
        self.assertEqual(result["blocked_no_template"], 1)


class TestOOSRowSkipped(unittest.TestCase):
    """Row with scope_status=OOS is blocked_no_template immediately."""

    def test_oos_row_blocked(self) -> None:
        oos_row = dict(_FN6_ROW)
        oos_row["scope_status"] = "OOS"
        td = _make_workspace([oos_row])
        try:
            result = run(["--workspace", td.name])
        finally:
            td.cleanup()

        m = result["manifests"][0]
        self.assertEqual(m["composed_status"], "blocked_no_template")
        self.assertIn("OOS", m["blocked_reason"])


class TestStrictMode(unittest.TestCase):
    """--strict exits non-zero when any row is blocked."""

    def test_strict_exits_nonzero_on_blocked(self) -> None:
        td = _make_workspace([_NO_MATCH_ROW])
        try:
            with self.assertRaises(SystemExit) as ctx:
                run(["--workspace", td.name, "--strict"])
            self.assertEqual(ctx.exception.code, 1)
        finally:
            td.cleanup()

    def test_strict_passes_when_all_composed(self) -> None:
        td = _make_workspace([_FN6_ROW])
        try:
            # Should not raise
            result = run(["--workspace", td.name, "--strict"])
            self.assertEqual(result["composed"], 1)
        finally:
            td.cleanup()


class TestLiveSmokeBaseAzul(unittest.TestCase):
    """Live smoke against /Users/wolf/audits/base-azul (skip silently if not present)."""

    WS = Path("/Users/wolf/audits/base-azul")

    def setUp(self) -> None:
        if not self.WS.is_dir():
            self.skipTest("base-azul workspace not present")
        ledger = self.WS / ".auditooor" / "invariant_ledger.json"
        if not ledger.exists():
            self.skipTest("base-azul invariant_ledger.json not present")

    def test_live_compose_at_least_one_manifest(self) -> None:
        result = run(["--workspace", str(self.WS)])
        # Must compose at least 1 manifest from real ledger (158 rows, multiple match)
        self.assertGreaterEqual(
            result["composed"], 1,
            f"Expected >= 1 composed manifest from {self.WS}; got {result['composed']}",
        )
        self.assertGreater(result["total_rows"], 0)

    def test_live_bridge_proof_domain_appears(self) -> None:
        result = run(["--workspace", str(self.WS)])
        tids = [m["template_id"] for m in result["manifests"] if m["composed_status"] == "composed"]
        self.assertIn("bridge_proof_domain", tids)

    def test_live_consensus_parser_differential_appears(self) -> None:
        result = run(["--workspace", str(self.WS)])
        tids = [m["template_id"] for m in result["manifests"] if m["composed_status"] == "composed"]
        self.assertIn("consensus_parser_differential", tids)

    def test_live_all_severity_lines_verified(self) -> None:
        result = run(["--workspace", str(self.WS)])
        blocked_sev = [
            m for m in result["manifests"]
            if m["composed_status"] == "blocked_severity_line_not_verified"
        ]
        self.assertEqual(
            len(blocked_sev), 0,
            f"Unexpected M14-trap failures on live workspace: {[m['row_id'] for m in blocked_sev]}",
        )


if __name__ == "__main__":
    unittest.main()
