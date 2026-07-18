"""Regression tests for tools/impact-family-worklist.py (T1-PRIORITY-2).

Three tests:
  1. ``test_schema_valid`` — generated JSON conforms to
     ``auditooor.impact_family_worklist.v1`` shape (top-level keys + per-row
     fields).
  2. ``test_spark_three_impact_families_parsed`` — the canonical Spark
     SEVERITY.md / RUBRIC_COVERAGE.md fixture yields exactly three impact
     classes (CRIT-1, CRIT-2, HIGH-1) with the correct family labels.
  3. ``test_update_status_mutation`` — ``--update <family> --status <new>``
     mutates the targeted row in place without touching other rows.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-family-worklist.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("impact_family_worklist", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


# Verbatim Spark rubric fragment — keeps the test hermetic vs. ``~/audits/spark``.
SPARK_SEVERITY_MD = """# Severity rubric — Spark (Lightspark) Immunefi bounty

**Source:** https://immunefi.com/bug-bounty/spark-lightspark/
**Asset class:** Blockchain/DLT

## Rubric (verbatim from bounty page)

### Critical (Blockchain/DLT)

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| CRIT-1 | Direct loss of funds | 10% of funds-at-risk capped at USD 100,000; minimum USD 30,000 (Primacy of Impact applies) |
| CRIT-2 | Permanent freezing of funds (fix requires hardfork) | USD 30,000 flat |

Listed-impact sentences (verbatim, bullet form for rubric grounding):

- Direct loss of funds
- Permanent freezing of funds (fix requires hardfork)

### High (Blockchain/DLT)

| ID | Listed-impact sentence (verbatim) | Reward |
|---|---|---|
| HIGH-1 | RPC API crash affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer (excluding DoS-related attack vector) | USD 25,000 flat |

Listed-impact sentences (verbatim, bullet form for rubric grounding):

- RPC API crash affecting projects with greater than or equal to 25% of the market capitalization on top of the respective layer (excluding DoS-related attack vector)

## Severity rationale & cap rules

- Attack must work with HONEST Spark Operators (per OOS-SPK-2).
- Attack must not depend on RBF replacement of unconfirmed Spark broadcasts (per OOS-SPK-1).
- DoS attack vectors are EXPLICITLY excluded (per OOS-DOS).
"""


def _seed_spark_workspace(tmp_root: Path) -> Path:
    ws = tmp_root / "spark"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "SEVERITY.md").write_text(SPARK_SEVERITY_MD, encoding="utf-8")
    return ws


class ImpactFamilyWorklistTests(unittest.TestCase):
    def test_schema_valid(self) -> None:
        with TemporaryDirectory() as td:
            ws = _seed_spark_workspace(Path(td))
            payload = MOD.build_worklist(ws)
            for key in (
                "schema_version",
                "workspace",
                "generated_at",
                "rows",
                "counts",
            ):
                self.assertIn(key, payload, f"top-level key {key!r} missing")
            self.assertEqual(payload["schema_version"], "auditooor.impact_family_worklist.v1")
            self.assertIsInstance(payload["rows"], list)
            self.assertGreater(len(payload["rows"]), 0)
            for row in payload["rows"]:
                for field in (
                    "rubric_id",
                    "family",
                    "listed_impact",
                    "tier",
                    "reward_formula",
                    "OOS_clauses_to_rebut",
                    "assigned_to_lead",
                    "status",
                ):
                    self.assertIn(field, row, f"per-row field {field!r} missing")
                self.assertIn(
                    row["status"],
                    {"open", "scaffolded", "submitted", "oos"},
                    f"unexpected status {row['status']!r}",
                )
                self.assertIsInstance(row["OOS_clauses_to_rebut"], list)

    def test_spark_three_impact_families_parsed(self) -> None:
        with TemporaryDirectory() as td:
            ws = _seed_spark_workspace(Path(td))
            payload = MOD.build_worklist(ws)
            rubric_ids = [r["rubric_id"] for r in payload["rows"]]
            self.assertEqual(
                rubric_ids,
                ["CRIT-1", "CRIT-2", "HIGH-1"],
                f"expected the canonical Spark rubric IDs, got {rubric_ids}",
            )
            families = {r["rubric_id"]: r["family"] for r in payload["rows"]}
            self.assertEqual(families["CRIT-1"], "Direct loss")
            self.assertEqual(families["CRIT-2"], "Permanent freeze")
            self.assertEqual(families["HIGH-1"], "RPC crash")
            tiers = {r["rubric_id"]: r["tier"] for r in payload["rows"]}
            self.assertEqual(tiers["CRIT-1"], "Critical")
            self.assertEqual(tiers["CRIT-2"], "Critical")
            self.assertEqual(tiers["HIGH-1"], "High")
            # OOS clauses scraped from the rubric body.
            for r in payload["rows"]:
                self.assertIn("OOS-DOS", r["OOS_clauses_to_rebut"])
            # No staging submissions in the seeded workspace -> all unmatched.
            self.assertEqual(payload["counts"]["matched"], 0)
            self.assertEqual(payload["counts"]["unmatched"], 3)
            self.assertEqual(payload["counts"]["total"], 3)

    def test_update_status_mutation(self) -> None:
        with TemporaryDirectory() as td:
            ws = _seed_spark_workspace(Path(td))
            MOD._write_worklist(ws, MOD.build_worklist(ws))
            updated = MOD.update_status(ws, "CRIT-2", "scaffolded")
            statuses = {r["rubric_id"]: r["status"] for r in updated["rows"]}
            self.assertEqual(statuses["CRIT-2"], "scaffolded")
            # Other rows untouched.
            self.assertEqual(statuses["CRIT-1"], "open")
            self.assertEqual(statuses["HIGH-1"], "open")
            # JSON is round-trippable.
            on_disk = json.loads(
                (ws / ".auditooor" / "impact_family_worklist.json").read_text(encoding="utf-8")
            )
            self.assertEqual(on_disk["rows"][1]["status"], "scaffolded")


if __name__ == "__main__":
    unittest.main()
