#!/usr/bin/env python3
"""Tests for tools/base-critical-candidate-matrix.py (PR #544 Lane H).

Stdlib-only. Synthetic workspaces under tempdir — no dependency on
~/audits/.

Coverage matrix (default-to-kill semantics):
  1. Candidate with no impact mapping -> kill_or_reframe.
  2. Candidate with Critical wording but no listed Critical impact
     -> kill_or_reframe (no silent promotion).
  3. Candidate with mock-only evidence -> blocked_real_component.
  4. Candidate with explicit rubric-matched impact + execution
     manifest -> executable.

Plus integration tests:
  5. JSON + Markdown outputs under <ws>/critical_hunt/ are written.
  6. JSON output schema is auditooor.base_critical_candidate_matrix.v1.
  7. --strict exits 1 when Critical-wording rows downgrade.
  8. Empty workspace produces zero rows but still writes both files.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-critical-candidate-matrix.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "base_critical_candidate_matrix", TOOL
    )
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["base_critical_candidate_matrix"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_module()


def _run(args: list, *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(cwd) if cwd else None,
    )


SEVERITY_TEMPLATE = textwrap.dedent(
    """\
    # Severity Rubric

    ## Critical

    - Permanent freeze of user funds
    - Direct theft of user funds without user interaction
    - Node resource consumption >=30%
    - Shutdown >=30% of nodes

    ## High

    - Theft of user funds requiring user interaction
    """
)


class TestCandidateMatrix(unittest.TestCase):
    def _make_workspace(self) -> Path:
        ws = Path(tempfile.mkdtemp(prefix="bcm_ws_"))
        (ws / "SEVERITY.md").write_text(SEVERITY_TEMPLATE, encoding="utf-8")
        (ws / "critical_hunt" / "candidates").mkdir(parents=True)
        return ws

    # ------------------------------------------------------------------
    # Test 1 — empty impact_mapping defaults to kill_or_reframe
    # ------------------------------------------------------------------
    def test_no_impact_defaults_kill_or_reframe(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C-NO-IMPACT",
            "scope_asset": "vault",
            "impact_mapping": "",  # <-- empty
            "production_path": "src/Vault.sol:42",
        }
        (ws / "critical_hunt" / "candidates" / "c1.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rows, _listed = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].candidate_status, "kill_or_reframe")
        self.assertTrue(
            any("empty impact_mapping" in n for n in rows[0].notes),
            f"expected default-to-kill note, got {rows[0].notes!r}",
        )

    # ------------------------------------------------------------------
    # Test 2 — Critical wording but no listed Critical impact -> kill_or_reframe
    # ------------------------------------------------------------------
    def test_critical_wording_without_rubric_match_downgrades(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C-CRIT-WORDS",
            "scope_asset": "settlement",
            "severity": "Critical",
            "impact_mapping": "Off-chain governance signature replay (theoretical)",
            "production_path": "src/Settle.sol:99",
            "required_proof": "fork replay",
        }
        (ws / "critical_hunt" / "candidates" / "c2.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rows, listed = _MOD.build_matrix(ws)
        self.assertTrue(listed, "fixture severity rubric should yield Critical bullets")
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].candidate_status,
            "kill_or_reframe",
            f"Critical wording without rubric must downgrade. Notes: {rows[0].notes!r}",
        )
        self.assertFalse(rows[0].matches_listed_critical)

    # ------------------------------------------------------------------
    # Test 3 — mock-only evidence -> blocked_real_component
    # ------------------------------------------------------------------
    def test_mock_only_evidence_blocked(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C-MOCK",
            "scope_asset": "bridge",
            # Matches "Permanent freeze of user funds" verbatim:
            "impact_mapping": "Permanent freeze of user funds",
            "production_path": "test/MockBridge.sol:10",
            "artifact_refs": ["test/mocks/MockVerifier.sol"],
            "notes": "uses mock verifier; no real component yet",
        }
        (ws / "critical_hunt" / "candidates" / "c3.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rows, _listed = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].candidate_status,
            "blocked_real_component",
            f"mock-only must block. Notes: {rows[0].notes!r}",
        )
        # Should also have flagged matches_listed_critical (rubric matched)
        self.assertTrue(rows[0].matches_listed_critical)

    # ------------------------------------------------------------------
    # Test 4 — execution manifest + explicit rubric-matched impact -> executable
    # ------------------------------------------------------------------
    def test_executable_when_manifest_and_rubric_match(self):
        ws = self._make_workspace()
        cand_id = "C-EXEC-1"
        cand = {
            "candidate_id": cand_id,
            "scope_asset": "vault",
            "impact_mapping": "Direct theft of user funds without user interaction",
            "listed_impact_selected": "Direct theft of user funds without user interaction",
            "listed_impact_proven": True,
            "production_path": "external/base-azul/src/Vault.sol:120",
            "required_proof": "forge test --match-test testDrainVault",
            "artifact_refs": ["external/base-azul/src/Vault.sol"],
        }
        (ws / "critical_hunt" / "candidates" / "c4.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        # Drop a real execution manifest with the candidate id inside.
        manifest_dir = ws / "poc_execution" / cand_id
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "execution_manifest.json").write_text(
            json.dumps(
                {
                    "candidate_id": cand_id,
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "schema": "auditooor.poc_execution.v1",
                }
            ),
            encoding="utf-8",
        )
        rows, _listed = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0].candidate_status,
            "executable",
            f"manifest + rubric match must promote to executable. Notes: {rows[0].notes!r}",
        )
        self.assertTrue(rows[0].has_execution_manifest)
        self.assertTrue(rows[0].matches_listed_critical)
        # And the manifest path should appear in artifact_refs.
        self.assertTrue(
            any(
                "poc_execution" in ref and ref.endswith("execution_manifest.json")
                for ref in rows[0].artifact_refs
            ),
            f"manifest must appear in artifact_refs: {rows[0].artifact_refs!r}",
        )

    # ------------------------------------------------------------------
    # Test 5 — outputs are written under <ws>/critical_hunt/
    # ------------------------------------------------------------------
    def test_outputs_written(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c.json").write_text(
            json.dumps({"candidate_id": "C5", "impact_mapping": ""}),
            encoding="utf-8",
        )
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").is_file()
        )
        self.assertTrue(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.md").is_file()
        )

    # ------------------------------------------------------------------
    # Test 6 — JSON schema
    # ------------------------------------------------------------------
    def test_json_schema(self):
        ws = self._make_workspace()
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            payload["schema"], "auditooor.base_critical_candidate_matrix.v1"
        )
        self.assertIn("rows", payload)
        self.assertIn("status_counts", payload)
        for status in _MOD.VALID_STATUSES:
            self.assertIn(status, payload["status_counts"])

    # ------------------------------------------------------------------
    # Test 7 — --strict fails when Critical wording downgrades
    # ------------------------------------------------------------------
    def test_strict_fails_on_critical_wording_downgrade(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C-STRICT",
            "severity": "Critical",
            "impact_mapping": "Theoretical critical loss",
        }
        (ws / "critical_hunt" / "candidates" / "c7.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rc = _run(["--workspace", str(ws), "--strict"]).returncode
        self.assertEqual(rc, 1, "--strict must fail on critical-wording downgrade")
        # Without --strict it must succeed.
        rc_ok = _run(["--workspace", str(ws)]).returncode
        self.assertEqual(rc_ok, 0)

    # ------------------------------------------------------------------
    # Test 8 — empty workspace still emits both files
    # ------------------------------------------------------------------
    def test_empty_workspace_emits_files(self):
        ws = Path(tempfile.mkdtemp(prefix="bcm_empty_"))
        rc = _run(["--workspace", str(ws)]).returncode
        self.assertEqual(rc, 0)
        self.assertTrue(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").is_file()
        )
        self.assertTrue(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.md").is_file()
        )
        payload = json.loads(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(payload["rows"], [])

    # ------------------------------------------------------------------
    # Test 9 — required fields are present on every row
    # ------------------------------------------------------------------
    def test_required_fields_present(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c9.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C9",
                    "scope_asset": "x",
                    "impact_mapping": "Permanent freeze of user funds",
                    "production_path": "src/X.sol:1",
                    "required_proof": "tbd",
                    "artifact_refs": ["src/X.sol"],
                }
            ),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        for fname in _MOD.REQUIRED_FIELDS:
            self.assertTrue(
                hasattr(rows[0], fname), f"row missing required field {fname}"
            )

    # ------------------------------------------------------------------
    # Test 10 — idempotent: running twice produces identical JSON
    # ------------------------------------------------------------------
    def test_idempotent(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c10.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C10",
                    "scope_asset": "x",
                    "impact_mapping": "Permanent freeze of user funds",
                    "artifact_refs": ["src/X.sol"],
                    "listed_impact_selected": "Permanent freeze of user funds",
                    "listed_impact_proven": True,
                }
            ),
            encoding="utf-8",
        )
        _run(["--workspace", str(ws)])
        first = (ws / "critical_hunt" / "base_critical_candidate_matrix.json").read_text(
            encoding="utf-8"
        )
        _run(["--workspace", str(ws)])
        second = (
            ws / "critical_hunt" / "base_critical_candidate_matrix.json"
        ).read_text(encoding="utf-8")
        self.assertEqual(first, second)

    # ------------------------------------------------------------------
    # Test 11 — help exits 0
    # ------------------------------------------------------------------
    def test_help_exits_zero(self):
        result = _run(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("--workspace", result.stdout)
        self.assertIn("--strict", result.stdout)

    # ------------------------------------------------------------------
    # Test 12 (Wave 6 Worker L) — new severity-claim-discipline fields
    # are populated on every row with conservative defaults. Legacy
    # candidate JSON without the fields must still produce valid rows.
    # ------------------------------------------------------------------
    def test_wave6L_default_discipline_fields(self):
        ws = self._make_workspace()
        # Legacy-shape candidate (no Wave 6 L fields).
        (ws / "critical_hunt" / "candidates" / "c12.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C12",
                    "scope_asset": "x",
                    "impact_mapping": "Permanent freeze of user funds",
                    "artifact_refs": ["src/X.sol"],
                }
            ),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # All four discipline fields present with conservative defaults:
        self.assertEqual(row.listed_impact_selected, "")
        self.assertFalse(row.listed_impact_proven)
        self.assertEqual(row.network_level_evidence, "absent")
        self.assertTrue(row.component_poc_only)

    # ------------------------------------------------------------------
    # Test 13 (Wave 6 Worker L) — explicit fields round-trip into the
    # row payload AND a Critical+unproven row gets a per-row warning
    # appended to notes.
    # ------------------------------------------------------------------
    def test_wave6L_critical_unproven_row_warning(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C13",
            "scope_asset": "node",
            "severity": "Critical",
            "impact_mapping": "Permanent freeze of user funds",
            "artifact_refs": ["src/X.sol"],
            "listed_impact_selected": "Permanent freeze of user funds",
            "listed_impact_proven": False,
            "network_level_evidence": "absent",
            "component_poc_only": True,
        }
        (ws / "critical_hunt" / "candidates" / "c13.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(
            row.listed_impact_selected, "Permanent freeze of user funds"
        )
        self.assertFalse(row.listed_impact_proven)
        self.assertTrue(
            any("wave6L" in n for n in row.notes),
            f"expected wave6L per-row warning, got {row.notes!r}",
        )
        self.assertTrue(
            any("listed_impact_proven=false" in n for n in row.severity_claim_warnings),
            f"expected listed_impact_proven=false warn, got {row.severity_claim_warnings!r}",
        )

    # ------------------------------------------------------------------
    # Test 14 (Wave 6 Worker L) — Critical+proven row produces NO
    # severity_claim_warnings entries.
    # ------------------------------------------------------------------
    def test_wave6L_critical_proven_no_warning(self):
        ws = self._make_workspace()
        cand = {
            "candidate_id": "C14",
            "scope_asset": "node",
            "severity": "Critical",
            "impact_mapping": "Permanent freeze of user funds",
            "artifact_refs": ["src/X.sol"],
            "listed_impact_selected": "Permanent freeze of user funds",
            "listed_impact_proven": True,
            "network_level_evidence": "poc_execution/net/manifest.json",
            "component_poc_only": False,
        }
        (ws / "critical_hunt" / "candidates" / "c14.json").write_text(
            json.dumps(cand), encoding="utf-8"
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(rows[0].severity_claim_warnings, [])

    # ------------------------------------------------------------------
    # Test 15 (Wave 6 Worker L) — JSON output schema exposes the new
    # fields so downstream tools (severity-claim-guard.py) can read them.
    # ------------------------------------------------------------------
    def test_wave6L_json_schema_round_trip(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c15.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C15",
                    "severity": "Critical",
                    "impact_mapping": "Permanent freeze of user funds",
                    "listed_impact_selected": "Permanent freeze of user funds",
                    "listed_impact_proven": True,
                    "network_level_evidence": "x.json",
                    "component_poc_only": False,
                }
            ),
            encoding="utf-8",
        )
        rc = _run(["--workspace", str(ws)]).returncode
        self.assertEqual(rc, 0)
        payload = json.loads(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(len(payload["rows"]), 1)
        emitted = payload["rows"][0]
        for fname in _MOD.WAVE6L_DISCIPLINE_FIELDS:
            self.assertIn(fname, emitted)

    # ------------------------------------------------------------------
    # Test 16 — partial/paraphrased impact text no longer grounds. Base
    # Azul severity must come from one exact listed impact sentence.
    # ------------------------------------------------------------------
    def test_partial_impact_sentence_kills(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c16.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C16",
                    "severity": "Critical",
                    "impact_mapping": "Direct theft of user funds",
                    "listed_impact_selected": "Direct theft of user funds",
                    "listed_impact_proven": True,
                    "artifact_refs": ["src/X.sol"],
                }
            ),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(rows[0].candidate_status, "kill_or_reframe")
        self.assertFalse(rows[0].matches_listed_critical)

    # ------------------------------------------------------------------
    # Test 17 — Snappy/gossip decode cannot be Critical/direct-ready from
    # component evidence or sub-threshold resource numbers.
    # ------------------------------------------------------------------
    def test_snappy_critical_without_threshold_kills(self):
        ws = self._make_workspace()
        cand_id = "C17-SNAPPY"
        (ws / "critical_hunt" / "candidates" / "c17.json").write_text(
            json.dumps(
                {
                    "candidate_id": cand_id,
                    "scope_asset": "base-reth gossip snappy decode",
                    "severity": "Critical",
                    "impact_mapping": "Node resource consumption >=30%",
                    "listed_impact_selected": "Node resource consumption >=30%",
                    "listed_impact_proven": True,
                    "network_level_evidence": "absent",
                    "component_poc_only": True,
                    "node_resource_consumption_pct": 12,
                    "realistic_non_bruteforce": False,
                    "artifact_refs": ["external/base/crates/consensus/gossip/src/config.rs"],
                }
            ),
            encoding="utf-8",
        )
        manifest_dir = ws / "poc_execution" / cand_id
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "execution_manifest.json").write_text(
            json.dumps({"candidate_id": cand_id, "final_result": "proved"}),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(rows[0].candidate_status, "kill_or_reframe")
        self.assertTrue(
            any("Snappy Critical claim lacks measured >=30%" in n for n in rows[0].notes)
        )

    def test_snappy_critical_with_threshold_can_execute(self):
        ws = self._make_workspace()
        cand_id = "C18-SNAPPY"
        (ws / "critical_hunt" / "candidates" / "c18.json").write_text(
            json.dumps(
                {
                    "candidate_id": cand_id,
                    "scope_asset": "base-reth gossip snappy decode",
                    "severity": "Critical",
                    "impact_mapping": "Node resource consumption >=30%",
                    "listed_impact_selected": "Node resource consumption >=30%",
                    "listed_impact_proven": True,
                    "network_level_evidence": "critical_hunt/node_resource_wave5/results.json",
                    "component_poc_only": False,
                    "node_resource_consumption_pct": 31,
                    "realistic_non_bruteforce": True,
                    "artifact_refs": ["external/base/crates/consensus/gossip/src/config.rs"],
                }
            ),
            encoding="utf-8",
        )
        manifest_dir = ws / "poc_execution" / cand_id
        manifest_dir.mkdir(parents=True)
        (manifest_dir / "execution_manifest.json").write_text(
            json.dumps({"candidate_id": cand_id, "final_result": "proved"}),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(rows[0].candidate_status, "executable")

    def test_snappy_mempool_impact_kills(self):
        ws = self._make_workspace()
        (ws / "critical_hunt" / "candidates" / "c19.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C19-SNAPPY",
                    "scope_asset": "base-reth gossip snappy decode",
                    "severity": "High",
                    "impact_mapping": "Node resource consumption >=30%",
                    "listed_impact_selected": "Node resource consumption >=30%",
                    "listed_impact_proven": True,
                    "notes": "mempool impact from gossip decode",
                }
            ),
            encoding="utf-8",
        )
        rows, _ = _MOD.build_matrix(ws)
        self.assertEqual(rows[0].candidate_status, "kill_or_reframe")
        self.assertTrue(
            any("mempool impact is not applicable" in n for n in rows[0].notes)
        )


if __name__ == "__main__":
    unittest.main()
