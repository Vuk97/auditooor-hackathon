from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "invariant-adoption-fresh-metrics.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("invariant_adoption_fresh_metrics", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["invariant_adoption_fresh_metrics"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_fresh_ws(root: Path, name: str, *, adopted: int = 3, total: int = 3, ledger: bool = True) -> Path:
    ws = root / name
    aud = ws / ".auditooor"
    aud.mkdir(parents=True)
    units = []
    for idx in range(total):
        if idx < adopted:
            units.append({
                "unit_id": f"INV-DISC-{idx}",
                "review_state": "blocked_project_source_missing",
                "next_commands": ["make project-source-root-readiness WS=<workspace> JSON=1"],
            })
        else:
            units.append({"unit_id": f"INV-DISC-{idx}", "review_state": "queued"})
    _write_json(aud / "invariant_discovery_adoption.json", {
        "schema": "auditooor.invariant_discovery_adoption.v1",
        "adopted_to_canonical_invariant_ledger": True,
        "promotion_allowed": False,
        "generated_review": {"terminal_review_count": 2, "unreviewed_missing_count": 0},
        "route_family_units": units,
    })
    if ledger:
        _write_json(aud / "invariant_ledger.json", {"rows": [{"id": "INV-DISC-0"}]})
    return ws


class InvariantAdoptionFreshMetricsTests(unittest.TestCase):
    def test_three_valid_fresh_engagements_make_metrics_ready(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            sources = [(_write_fresh_ws(root, f"fresh-{idx}"), None) for idx in range(3)]
            payload = MOD.run(target, sources)
            self.assertEqual(payload["status"], "fresh_engagement_adoption_metrics_ready")
            self.assertEqual(payload["valid_fresh_engagement_count"], 3)
            self.assertEqual(payload["missing_fresh_engagement_count"], 0)
            self.assertTrue((target / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.json").is_file())
            self.assertTrue((target / ".auditooor" / "invariant_adoption_fresh_engagement_metrics.md").is_file())

    def test_invalid_rows_are_reasoned_without_closing_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            good = _write_fresh_ws(root, "good")
            low = _write_fresh_ws(root, "low", adopted=1, total=3)
            no_ledger = _write_fresh_ws(root, "no-ledger", ledger=False)
            payload = MOD.run(target, [(good, None), (low, None), (no_ledger, None)])
            self.assertEqual(payload["status"], "fresh_engagement_adoption_metrics_insufficient")
            self.assertEqual(payload["valid_fresh_engagement_count"], 1)
            blockers = {row["engagement_id"]: row["blockers"] for row in payload["rows"]}
            self.assertIn("adoption_rate_below_threshold", blockers["low"])
            self.assertIn("invariant_ledger_check_not_passed", blockers["no-ledger"])

    def test_manifest_import_resolves_relative_workspaces(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            _write_fresh_ws(root, "fresh-a")
            manifest = root / "manifest.json"
            _write_json(manifest, {"workspaces": [{"engagement_id": "A", "workspace": "fresh-a"}]})
            sources = MOD._manifest_workspaces(manifest)
            payload = MOD.run(target, sources)
            self.assertEqual(payload["rows"][0]["engagement_id"], "A")
            self.assertEqual(payload["rows"][0]["status"], "fresh_engagement_adoption_metric_valid")


if __name__ == "__main__":
    unittest.main()
