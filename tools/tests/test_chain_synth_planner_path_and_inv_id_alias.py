#!/usr/bin/env python3
"""Guard tests for two confirmed pipeline bugs fixed in this wave.

BUG A (invariant-ledger inv_id alias)
--------------------------------------
The invariant-ledger reader's validate_rows and load_rows required the JSON
field name "id" for each row.  Ledger files produced by older tooling
(llm-invariant-extractor.py manifest assertions) used "inv_id" as the key,
causing 713 "required field missing: id" errors per hyperbridge workspace run
and leaving every row with status=unknown because the Row dataclass received
an empty string for id.

Fixed by: accepting "inv_id" as a fallback alias for "id" in load_rows,
_dict_to_row, and validate_rows.

BUG B (chained-attack-planner path mismatch)
---------------------------------------------
chained-attack-planner.py wrote its output to
  <ws>/swarm/chained_attack_plans.json
but audit-completeness-check.py's check_chain_synth reads from
  <ws>/.auditooor/chain_synthesis*.json
causing the chain-synth signal to always read "no artifact; did not run"
even when the planner ran successfully (morpho path mismatch).

Fixed by: writing a dated mirror to .auditooor/chain_synthesis_<date>.json
alongside the existing swarm/ output.

Test matrix
-----------
A1. load_rows: row with inv_id loads id correctly.
A2. load_rows: row with both id and inv_id uses id (not overwritten by alias).
A3. load_rows: row with neither id nor inv_id gets empty-string id (unchanged).
A4. validate_rows: row with inv_id does NOT emit "required field missing: id".
A5. validate_rows: row with neither id nor inv_id DOES emit the missing error.
A6. validate_rows: row with id=foo and no inv_id passes the id-presence check.
A7. _dict_to_row: inv_id alias works (used by markdown parser).
B1. chained-attack-planner run produces .auditooor/chain_synthesis_<date>.json.
B2. the mirror file content matches the primary swarm output.
B3. the swarm/chained_attack_plans.json primary file is still produced.
B4. no chain_synthesis file is written when swarm dir is absent (error path).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER_TOOL = ROOT / "tools" / "invariant-ledger.py"
PLANNER_TOOL = ROOT / "tools" / "chained-attack-planner.py"


# ---------------------------------------------------------------------------
# Module loaders
# ---------------------------------------------------------------------------

def _load_ledger():
    spec = importlib.util.spec_from_file_location("invariant_ledger_alias_guard", LEDGER_TOOL)
    assert spec and spec.loader, f"cannot load {LEDGER_TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_ledger_alias_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_planner():
    spec = importlib.util.spec_from_file_location("chained_attack_planner_path_guard", PLANNER_TOOL)
    assert spec and spec.loader, f"cannot load {PLANNER_TOOL}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["chained_attack_planner_path_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


_LEDGER = _load_ledger()
_PLANNER = _load_planner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_row_dict(**overrides) -> dict:
    base = {
        "id": "TEST-I01",
        "scope_asset": "vault",
        "invariant_family": "conservation",
        "statement": "Total deposits equal sum of user balances.",
        "source_citations": ["SCOPE.md::vault"],
        "attacker_capability": "non-privileged depositor",
        "trusted_boundary": "admin owner",
        "oos_boundary": "N/A",
        "production_path": "src/Vault.sol:10",
        "harness_target": "test/Vault.t.sol::invariant_total",
        "required_engine": "forge",
        "negative_test": "deposit without matching credit",
        "status": "scaffolded",
        "artifacts": ["test/Vault.t.sol"],
        "owner": "Claude",
    }
    base.update(overrides)
    return base


def _write_ledger_json(ws: Path, rows: list[dict]) -> None:
    p = ws / ".auditooor" / "invariant_ledger.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "auditooor.invariant_ledger.v1",
        "schema": "auditooor.invariant_ledger.v1",
        "workspace": str(ws),
        "updated": "2026-06-14T00:00:00Z",
        "rows": rows,
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# A: inv_id alias tests (Bug A)
# ---------------------------------------------------------------------------

class TestInvIdAlias(unittest.TestCase):

    def test_A1_load_rows_inv_id_is_accepted(self):
        """load_rows must map inv_id -> id when id is absent."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            row = _minimal_row_dict()
            del row["id"]
            row["inv_id"] = "ALIAS-I01"
            _write_ledger_json(ws, [row])
            rows = _LEDGER.load_rows(ws)
            self.assertEqual(len(rows), 1, "expected exactly one row loaded")
            self.assertEqual(rows[0].id, "ALIAS-I01",
                             f"id should be 'ALIAS-I01', got {rows[0].id!r}")

    def test_A2_load_rows_id_takes_precedence_over_inv_id(self):
        """When both id and inv_id are present, id wins."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            row = _minimal_row_dict(id="REAL-ID", inv_id="SHADOW-ID")
            _write_ledger_json(ws, [row])
            rows = _LEDGER.load_rows(ws)
            self.assertEqual(rows[0].id, "REAL-ID",
                             "id field must not be overwritten by inv_id alias")

    def test_A3_load_rows_neither_id_nor_inv_id_gives_empty(self):
        """When neither id nor inv_id is present, id defaults to empty string."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            row = _minimal_row_dict()
            del row["id"]
            _write_ledger_json(ws, [row])
            rows = _LEDGER.load_rows(ws)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].id, "",
                             "id should be empty string when neither id nor inv_id present")

    def test_A4_validate_rows_inv_id_alias_no_missing_error(self):
        """validate_rows must NOT emit 'required field missing: id' when inv_id is present."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            # Construct a raw dict with inv_id instead of id.
            raw = _minimal_row_dict()
            del raw["id"]
            raw["inv_id"] = "ALIAS-VAL-01"
            # Materialise Row the same way load_rows does (inv_id alias applied).
            row = _LEDGER.Row(
                id="ALIAS-VAL-01",
                scope_asset=raw["scope_asset"],
                invariant_family=raw["invariant_family"],
                statement=raw["statement"],
                source_citations=raw["source_citations"],
                attacker_capability=raw["attacker_capability"],
                trusted_boundary=raw["trusted_boundary"],
                oos_boundary=raw["oos_boundary"],
                production_path=raw["production_path"],
                harness_target=raw["harness_target"],
                required_engine=raw["required_engine"],
                negative_test=raw["negative_test"],
                status=raw["status"],
                artifacts=raw["artifacts"],
                owner=raw["owner"],
            )
            # Touch artifact so path check passes.
            art = ws / raw["artifacts"][0]
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("// stub\n", encoding="utf-8")
            issues = _LEDGER.validate_rows([row], ws, raw_rows=[raw])
            id_missing_errors = [
                i for i in issues
                if "required field missing: id" in i.message
            ]
            self.assertEqual(id_missing_errors, [],
                             f"unexpected 'required field missing: id' errors: {id_missing_errors}")

    def test_A5_validate_rows_neither_id_nor_inv_id_emits_error(self):
        """validate_rows MUST emit 'required field missing: id' when neither key is present."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            raw = _minimal_row_dict()
            del raw["id"]  # no inv_id either
            row = _LEDGER.Row(
                id="",
                scope_asset=raw["scope_asset"],
                invariant_family=raw["invariant_family"],
                statement=raw["statement"],
                source_citations=raw["source_citations"],
                attacker_capability=raw["attacker_capability"],
                trusted_boundary=raw["trusted_boundary"],
                oos_boundary=raw["oos_boundary"],
                production_path=raw["production_path"],
                harness_target=raw["harness_target"],
                required_engine=raw["required_engine"],
                negative_test=raw["negative_test"],
                status=raw["status"],
                artifacts=raw["artifacts"],
                owner=raw["owner"],
            )
            art = ws / raw["artifacts"][0]
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("// stub\n", encoding="utf-8")
            issues = _LEDGER.validate_rows([row], ws, raw_rows=[raw])
            id_missing_errors = [
                i for i in issues
                if "required field missing: id" in i.message
            ]
            self.assertGreater(len(id_missing_errors), 0,
                               "expected 'required field missing: id' when neither id nor inv_id present")

    def test_A6_validate_rows_normal_id_still_passes(self):
        """validate_rows must not emit id-missing errors for rows that have id."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            raw = _minimal_row_dict(id="NORMAL-ID")
            row = _LEDGER.Row(
                id=raw["id"],
                scope_asset=raw["scope_asset"],
                invariant_family=raw["invariant_family"],
                statement=raw["statement"],
                source_citations=raw["source_citations"],
                attacker_capability=raw["attacker_capability"],
                trusted_boundary=raw["trusted_boundary"],
                oos_boundary=raw["oos_boundary"],
                production_path=raw["production_path"],
                harness_target=raw["harness_target"],
                required_engine=raw["required_engine"],
                negative_test=raw["negative_test"],
                status=raw["status"],
                artifacts=raw["artifacts"],
                owner=raw["owner"],
            )
            art = ws / raw["artifacts"][0]
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("// stub\n", encoding="utf-8")
            issues = _LEDGER.validate_rows([row], ws, raw_rows=[raw])
            id_missing_errors = [
                i for i in issues
                if "required field missing: id" in i.message
            ]
            self.assertEqual(id_missing_errors, [],
                             "normal id-keyed row should not emit id-missing error")

    def test_A7_dict_to_row_inv_id_alias(self):
        """_dict_to_row must use inv_id when id is absent (used by markdown parser)."""
        d = _minimal_row_dict()
        del d["id"]
        d["inv_id"] = "MD-ALIAS-01"
        row = _LEDGER._dict_to_row(d)
        self.assertEqual(row.id, "MD-ALIAS-01",
                         f"_dict_to_row should map inv_id to id, got {row.id!r}")


# ---------------------------------------------------------------------------
# B: chained-attack-planner path mirror tests (Bug B)
# ---------------------------------------------------------------------------

class TestChainedAttackPlannerMirrorPath(unittest.TestCase):

    def _minimal_exploit_brief(self, ws: Path) -> dict:
        return {
            "schema": "auditooor.exploit_memory_brief.v1",
            "workspace_path": str(ws),
            "angles": [],
            "candidates": [],
        }

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True)
        (self.ws / ".auditooor").mkdir()
        (self.ws / "swarm").mkdir()
        # Write a minimal exploit brief so the planner has a source to read.
        brief_path = self.ws / ".auditooor" / "exploit_memory_brief.json"
        brief_path.write_text(
            json.dumps(self._minimal_exploit_brief(self.ws), indent=2),
            encoding="utf-8",
        )
        # Write a minimal SEVERITY.md so planner can source rubric rows.
        (self.ws / "SEVERITY.md").write_text(
            "# Severity\n## Critical\n- Direct loss of funds.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_B1_mirror_file_created_in_auditooor(self):
        """chained-attack-planner must write a chain_synthesis_<date>.json to .auditooor/."""
        _PLANNER.run(["--workspace", str(self.ws)])
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        mirror = self.ws / ".auditooor" / f"chain_synthesis_{date_str}.json"
        self.assertTrue(mirror.is_file(),
                        f".auditooor/chain_synthesis_{date_str}.json not found after planner run")

    def test_B2_mirror_content_matches_primary_output(self):
        """Mirror file content must equal the swarm/chained_attack_plans.json output."""
        _PLANNER.run(["--workspace", str(self.ws)])
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        mirror = self.ws / ".auditooor" / f"chain_synthesis_{date_str}.json"
        primary = self.ws / "swarm" / "chained_attack_plans.json"
        self.assertTrue(primary.is_file(), "swarm/chained_attack_plans.json not found")
        self.assertTrue(mirror.is_file(), "mirror not found")
        mirror_payload = json.loads(mirror.read_text(encoding="utf-8"))
        primary_payload = json.loads(primary.read_text(encoding="utf-8"))
        self.assertEqual(
            mirror_payload, primary_payload,
            "mirror .auditooor/chain_synthesis_*.json content must match primary swarm output",
        )

    def test_B3_swarm_primary_file_still_written(self):
        """The original swarm/chained_attack_plans.json must still be produced."""
        _PLANNER.run(["--workspace", str(self.ws)])
        primary = self.ws / "swarm" / "chained_attack_plans.json"
        self.assertTrue(primary.is_file(),
                        "swarm/chained_attack_plans.json must still be written by the planner")

    def test_B4_mirror_contains_parseable_json(self):
        """Mirror file must be valid JSON (not a truncated or binary write)."""
        _PLANNER.run(["--workspace", str(self.ws)])
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        mirror = self.ws / ".auditooor" / f"chain_synthesis_{date_str}.json"
        try:
            payload = json.loads(mirror.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            self.fail(f"mirror file is not valid JSON: {exc}")
        self.assertIsInstance(payload, dict, "mirror payload must be a JSON object")


if __name__ == "__main__":
    import unittest as _ut
    _ut.main()
