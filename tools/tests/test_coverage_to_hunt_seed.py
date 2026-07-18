# <!-- r36-rebuttal: lane-coverage-seed-finite registered; only this test file -->
"""Tests for tools/coverage-to-hunt-seed.py - the ACT half of the swept-surface
measure->act loop.

Asserts the four invariants the lane requires:
  (a) seed set == FULL uncovered set (no truncation, no first-N subset),
  (b) covered units are NOT re-seeded,
  (c) seed rows carry NO bug-class / severity / claim field (honest-target
      invariant - a seed is a TARGET, not a hypothesis-with-a-claim),
  (d) generic: no target/workspace literal in the tool logic.

Plus the end-to-end loop-closure: seed -> real heatmap re-run -> covered climbs.

Both tools have hyphenated names so they are loaded via importlib.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
SEED_TOOL = TOOLS / "coverage-to-hunt-seed.py"
HEATMAP_TOOL = TOOLS / "workspace-coverage-heatmap.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_SEED = _load("_coverage_to_hunt_seed_under_test", SEED_TOOL)


def _make_ws(tmp: Path) -> Path:
    """Fixture workspace: 5 Solidity units, exactly ONE pre-covered."""
    ws = tmp / "fixws"
    (ws / "src").mkdir(parents=True)
    (ws / ".auditooor").mkdir(parents=True)
    (ws / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function deposit(uint256 a) external {}\n"
        "    function withdraw(uint256 a) external {}\n"
        "    function transfer(address to, uint256 a) external {}\n"
        "}\n",
        encoding="utf-8",
    )
    (ws / "src" / "Pool.sol").write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Pool {\n"
        "    function addLiquidity(uint256 a) external {}\n"
        "    function removeLiquidity(uint256 a) external {}\n"
        "}\n",
        encoding="utf-8",
    )
    # pre-cover exactly ONE unit via an existing (foreign) exploit_queue row
    (ws / ".auditooor" / "exploit_queue.json").write_text(
        json.dumps({
            "schema": "auditooor.exploit_queue.v1",
            "workspace": "fixws",
            "queue": [
                {"lead_id": "PRE-1", "source": "real-hunt",
                 "contract": "Vault.sol", "function": "deposit",
                 "proof_status": "open"},
            ],
        }),
        encoding="utf-8",
    )
    return ws


def _make_ws_without_queue(tmp: Path) -> Path:
    ws = _make_ws(tmp)
    (ws / ".auditooor" / "exploit_queue.json").write_text(
        json.dumps({
            "schema": "auditooor.exploit_queue.v1",
            "workspace": "fixws",
            "queue": [],
        }),
        encoding="utf-8",
    )
    return ws


def _build_report(ws: Path, cap: int) -> dict:
    subprocess.run(
        [sys.executable, str(HEATMAP_TOOL), "--coverage-report",
         "--workspace-path", str(ws), "--uncovered-list-cap", str(cap)],
        check=True, capture_output=True, text=True,
    )
    return json.loads((ws / ".auditooor" / "coverage_report.json").read_text())


class TestCoverageToHuntSeed(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_ws(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    # ---- (a) seed set == full uncovered set (no truncation) ----------------
    def test_a_seed_set_equals_full_uncovered_set(self):
        report = _build_report(self.ws, cap=-1)
        self.assertFalse(report["uncovered_units_truncated"])
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        self.assertEqual(set(result["seeded_units"]),
                         set(report["uncovered_units"]))
        self.assertEqual(result["seed_rows_total"], report["uncovered"])

    def test_a_truncated_report_is_regenerated_not_silently_subset(self):
        # Build a TRUNCATED report (cap=1 => only 1 of 4 uncovered inlined).
        report = _build_report(self.ws, cap=1)
        self.assertTrue(report["uncovered_units_truncated"])
        self.assertEqual(len(report["uncovered_units"]), 1)
        self.assertEqual(report["uncovered"], 4)
        # The tool must regenerate at full cap and seed ALL 4, not just 1.
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        self.assertEqual(result["seed_rows_total"], 4)
        self.assertEqual(len(set(result["seeded_units"])), 4)

    def test_a_legacy_freshness_shape_is_regenerated(self):
        report = _build_report(self.ws, cap=-1)
        self.assertIsInstance(report.get("source_freshness"), dict)
        self.assertIsInstance(report.get("numerator_freshness"), dict)
        legacy = dict(report)
        legacy.pop("source_freshness", None)
        legacy.pop("numerator_freshness", None)
        (self.ws / ".auditooor" / "coverage_report.json").write_text(
            json.dumps(legacy),
            encoding="utf-8",
        )

        loaded = _SEED.load_coverage_report(self.ws, rebuild=False)

        self.assertIsInstance(loaded.get("source_freshness"), dict)
        self.assertIsInstance(loaded.get("numerator_freshness"), dict)
        self.assertFalse(loaded["uncovered_units_truncated"])
        self.assertEqual(len(set(loaded["uncovered_units"])), 4)

    # ---- (b) covered units are NOT re-seeded -------------------------------
    def test_b_covered_unit_not_reseeded(self):
        _build_report(self.ws, cap=-1)
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        # Vault.sol::deposit is pre-covered and MUST NOT be a seeded target.
        self.assertNotIn("Vault.sol::deposit", result["seeded_units"])
        self.assertEqual(len(result["seeded_units"]), 4)

    def test_b_detector_only_row_not_counted_as_covered(self):
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_ws_without_queue(Path(self._tmp.name))
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "workspace": "fixws",
                "queue": [
                    {"lead_id": "DET-1", "source": "detector-only",
                     "file": "src/Vault.sol", "function": "deposit",
                     "proof_status": "open"},
                ],
            }),
            encoding="utf-8",
        )
        report = _build_report(self.ws, cap=-1)
        # The report producer still sees the detector row, so the seeder must
        # correct that and seed the detector-only unit too.
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        self.assertIn("Vault.sol::deposit", result["seeded_units"])
        target = {
            t["unit_id"]: t for t in result["seeded_targets"]
        }["Vault.sol::deposit"]
        self.assertEqual(target["skip_reason"],
                         _SEED.DETECTOR_ONLY_REASON)

    def test_b_stale_queue_row_not_counted_as_covered(self):
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_ws_without_queue(Path(self._tmp.name))
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "workspace": "fixws",
                "queue": [
                    {"lead_id": "STALE-1", "source": "real-hunt",
                     "file": "src/Vault.sol", "function": "deposit",
                     "proof_status": "stale"},
                ],
            }),
            encoding="utf-8",
        )
        report = _build_report(self.ws, cap=-1)
        self.assertNotIn("Vault.sol::deposit", report["uncovered_units"])
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        self.assertIn("Vault.sol::deposit", result["seeded_units"])
        target = {
            t["unit_id"]: t for t in result["seeded_targets"]
        }["Vault.sol::deposit"]
        self.assertEqual(target["skip_reason"], _SEED.STALE_ROW_REASON)

    def test_b_reviewed_source_artifact_prevents_reseeding_stale_row(self):
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = _make_ws_without_queue(Path(self._tmp.name))
        (self.ws / ".auditooor" / "exploit_queue.json").write_text(
            json.dumps({
                "schema": "auditooor.exploit_queue.v1",
                "workspace": "fixws",
                "queue": [
                    {"lead_id": "STALE-1", "source": "real-hunt",
                     "file": "src/Vault.sol", "function": "deposit",
                     "proof_status": "stale"},
                ],
            }),
            encoding="utf-8",
        )
        source_artifacts = self.ws / ".auditooor" / "source_artifacts"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        (source_artifacts / "deposit-reviewed.json").write_text(
            json.dumps({
                "scanned_units": [
                    {
                        "source_unit": "Vault.sol::deposit",
                        "source_ref": "src/Vault.sol:1",
                    }
                ]
            }),
            encoding="utf-8",
        )

        _build_report(self.ws, cap=-1)
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)

        self.assertNotIn("Vault.sol::deposit", result["seeded_units"])

    # ---- (c) honest-target invariant: NO claim fields ----------------------
    def test_c_seed_rows_carry_no_claim_field(self):
        _build_report(self.ws, cap=-1)
        _SEED.run(self.ws, rebuild=False, dry_run=False,
                  queue_path_override=None)
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text())["queue"]
        us_rows = [r for r in queue if r.get("source") == "unhunted-surface"]
        self.assertEqual(len(us_rows), 4)
        for r in us_rows:
            for forbidden in _SEED.FORBIDDEN_CLAIM_FIELDS:
                self.assertNotIn(
                    forbidden, r,
                    msg="seed row leaked claim field %r: %r" % (forbidden, r))
            # positive: it carries only neutral target identity + bookkeeping
            self.assertEqual(r["reason"], _SEED.NEUTRAL_REASON)
            self.assertEqual(r["source"], "unhunted-surface")
            self.assertIn("unit_id", r)
            self.assertIn("file", r)
            self.assertIn("skip_reason", r)
            self.assertIn("source_path", r)

    def test_c_build_seed_row_rejects_claim_injection(self):
        # The row-builder itself asserts the invariant.
        row = _SEED.build_seed_row("fixws", "X.sol::f", "/src/X.sol")
        for forbidden in _SEED.FORBIDDEN_CLAIM_FIELDS:
            self.assertNotIn(forbidden, row)

    def test_c_seed_snapshot_and_rows_carry_run_id(self):
        _build_report(self.ws, cap=-1)
        result = _SEED.run(
            self.ws,
            rebuild=False,
            dry_run=False,
            queue_path_override=None,
            run_id="auditrun-current",
        )
        self.assertEqual(result["run_id"], "auditrun-current")
        snapshot = json.loads(
            (self.ws / ".auditooor" / "hunt_coverage_seed_snapshot.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(snapshot["run_id"], "auditrun-current")
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text(
                encoding="utf-8"
            )
        )["queue"]
        rows = [row for row in queue if row.get("source") == "unhunted-surface"]
        self.assertTrue(rows)
        self.assertTrue(all(row.get("run_id") == "auditrun-current" for row in rows))

    def test_c_build_seed_row_lead_id_preserves_long_unit_uniqueness(self):
        prefix = "src/hyperbridge/modules/pallets/intents-coprocessor/src/lib.rs"
        row_a = _SEED.build_seed_row("fixws", f"{prefix}::offchain_bid_key", prefix)
        row_b = _SEED.build_seed_row("fixws", f"{prefix}::offchain_bid_key_raw", prefix)

        self.assertNotEqual(row_a["lead_id"], row_b["lead_id"])
        self.assertTrue(row_a["lead_id"].startswith("F-UNHUNTED-"))
        self.assertTrue(row_b["lead_id"].startswith("F-UNHUNTED-"))

    def test_c_queue_upsert_preserves_long_unit_uniqueness(self):
        self._tmp.cleanup()
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "long-unit-ws"
        (self.ws / ".auditooor").mkdir(parents=True)
        prefix = "src/hyperbridge/modules/pallets/intents-coprocessor/src/lib.rs"
        unit_a = f"{prefix}::offchain_bid_key"
        unit_b = f"{prefix}::offchain_bid_key_raw"
        report = {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace": str(self.ws),
            "workspace_name": "long-unit-ws",
            "uncovered": 2,
            "uncovered_units": [unit_a, unit_b],
            "uncovered_units_truncated": False,
            "source_freshness": {"ok": True},
            "numerator_freshness": {"ok": True},
            "enumeration": {"source_root": str(self.ws / "src")},
        }
        (self.ws / ".auditooor" / "coverage_report.json").write_text(
            json.dumps(report),
            encoding="utf-8",
        )

        _SEED.run(self.ws, rebuild=False, dry_run=False, queue_path_override=None)
        _SEED.run(self.ws, rebuild=False, dry_run=False, queue_path_override=None)

        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text(encoding="utf-8")
        )["queue"]
        rows = [row for row in queue if row.get("source") == "unhunted-surface"]
        self.assertEqual({row["unit_id"] for row in rows}, {unit_a, unit_b})
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["lead_id"] for row in rows}), 2)

    def test_c_skip_log_reason_is_carried_into_seed_row(self):
        _build_report(self.ws, cap=-1)
        (self.ws / ".auditooor" / "hunt_coverage_skips.txt").write_text(
            "Vault.sol::withdraw accepted-risk\n",
            encoding="utf-8",
        )
        _SEED.run(self.ws, rebuild=False, dry_run=False,
                  queue_path_override=None)
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text())["queue"]
        row = next(
            r for r in queue
            if r.get("source") == "unhunted-surface"
            and r.get("unit_id") == "Vault.sol::withdraw"
        )
        self.assertEqual(row["file"], "Vault.sol")
        self.assertEqual(row["function"], "withdraw")
        self.assertEqual(row["skip_reason"], "accepted-risk")

    def test_c_report_skipped_function_is_seeded_with_reason(self):
        queue_path = self.ws / ".auditooor" / "manual_queue.json"
        report = {
            "schema": "auditooor.workspace_coverage_report.v1",
            "workspace": str(self.ws),
            "workspace_name": "fixws",
            "uncovered": 0,
            "uncovered_units": [],
            "uncovered_units_truncated": False,
            "enumeration": {"source_root": str(self.ws / "src")},
            "skipped_in_scope_functions": [
                {"file": "src/Vault.sol", "function": "withdraw",
                 "skip_reason": "parser skipped function"}
            ],
        }
        result = _SEED.seed_from_report(
            report, queue_path, dry_run=True, workspace_path=self.ws,
        )
        self.assertEqual(result["seeded_units"], ["Vault.sol::withdraw"])
        self.assertEqual(
            result["seeded_targets"][0]["skip_reason"],
            "parser skipped function",
        )

    # ---- (d) generic: no target/workspace literal in tool logic ------------
    def test_d_no_target_literal_in_logic(self):
        src = SEED_TOOL.read_text(encoding="utf-8")
        # Strip the module docstring (its RELATED-TOOLS / anchor / usage lines
        # legitimately name example targets like dydx/hyperbridge); the
        # EXECUTABLE logic must carry no target/workspace literal. The module
        # docstring is the first triple-quoted block in the file.
        first = src.find('"""')
        close = src.find('"""', first + 3)
        body = src[:first] + src[close + 3:] if first != -1 and close != -1 else src
        # Whole-word match so we don't false-positive on substrings like
        # "mezo" inside "timezone".
        import re as _re
        for literal in ("dydx", "hyperbridge", "superearn", "mezo",
                        "spark", "polymarket"):
            self.assertIsNone(
                _re.search(r"\b" + literal + r"\b", body.lower()),
                msg="target literal %r found in tool logic" % literal)

    # ---- end-to-end loop closure: covered climbs ---------------------------
    def test_loop_closes_covered_climbs(self):
        before = _build_report(self.ws, cap=-1)
        self.assertEqual(before["covered"], 1)
        self.assertEqual(before["uncovered"], 4)
        _SEED.run(self.ws, rebuild=False, dry_run=False,
                  queue_path_override=None)
        after = _build_report(self.ws, cap=-1)
        self.assertGreater(after["covered"], before["covered"])
        self.assertLess(after["uncovered"], before["uncovered"])
        self.assertEqual(after["covered"], 5)
        self.assertEqual(after["uncovered"], 0)

    # ---- idempotency: reseeding the SAME report refreshes, never duplicates -
    def test_idempotent_refresh_no_duplicate(self):
        _build_report(self.ws, cap=-1)
        r1 = _SEED.run(self.ws, rebuild=False, dry_run=False,
                       queue_path_override=None)
        self.assertEqual(r1["rows_written"], 4)
        self.assertEqual(r1["rows_updated"], 0)
        # Reseed against the SAME (un-refreshed) report: the 4 rows already
        # exist, so they refresh in place (update), nothing new is written.
        r2 = _SEED.run(self.ws, rebuild=False, dry_run=False,
                       queue_path_override=None)
        self.assertEqual(r2["rows_written"], 0)
        self.assertEqual(r2["rows_updated"], 4)
        # exactly 4 unhunted rows total (no duplication across reruns).
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text())["queue"]
        us = [r for r in queue if r.get("source") == "unhunted-surface"]
        self.assertEqual(len(us), 4)

    # ---- foreign-row preservation -----------------------------------------
    def test_preserves_foreign_rows(self):
        _build_report(self.ws, cap=-1)
        _SEED.run(self.ws, rebuild=False, dry_run=False,
                  queue_path_override=None)
        queue = json.loads(
            (self.ws / ".auditooor" / "exploit_queue.json").read_text())["queue"]
        self.assertTrue(any(r.get("source") == "real-hunt" for r in queue),
                        "foreign real-hunt row must be preserved")

    def test_writes_seed_snapshot_sidecar(self):
        _build_report(self.ws, cap=-1)
        result = _SEED.run(self.ws, rebuild=False, dry_run=False,
                           queue_path_override=None)
        self.assertTrue(result["seed_snapshot_written"])
        snapshot_path = self.ws / ".auditooor" / "hunt_coverage_seed_snapshot.json"
        self.assertEqual(
            Path(result["seed_snapshot_path"]).resolve(strict=False),
            snapshot_path.resolve(strict=False),
        )
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        self.assertEqual(
            snapshot["schema"],
            "auditooor.coverage_to_hunt_seed_snapshot.v1",
        )
        self.assertEqual(snapshot["seed_rows_total"], 4)
        self.assertEqual(set(snapshot["seeded_units"]), set(result["seeded_units"]))

    def test_dry_run_does_not_write_seed_snapshot_sidecar(self):
        _build_report(self.ws, cap=-1)
        result = _SEED.run(self.ws, rebuild=False, dry_run=True,
                           queue_path_override=None)
        self.assertFalse(result["seed_snapshot_written"])
        self.assertEqual(result["seed_snapshot_path"], "")
        snapshot_path = self.ws / ".auditooor" / "hunt_coverage_seed_snapshot.json"
        self.assertFalse(snapshot_path.exists())


if __name__ == "__main__":
    unittest.main()


# P2b: per-flow hunt seeding for undriven cross-module business flows.
import json as _json_bf
import tempfile as _tf_bf
import unittest as _ut_bf
from pathlib import Path as _P_bf


class TestUndrivenFlowSeeding(_ut_bf.TestCase):
    def _ws(self, units):
        ws = _P_bf(_tf_bf.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            "".join(_json_bf.dumps(u) + "\n" for u in units), encoding="utf-8")
        q = ws / ".auditooor" / "exploit_queue.json"
        q.write_text(_json_bf.dumps({"schema": "auditooor.exploit_queue.v1", "queue": []}))
        return ws, q

    def test_undriven_flow_seeds_member_tasks_idempotently(self):
        ws, q = self._ws([
            {"file": "src/Vault.sol", "function": "deposit"},
            {"file": "src/Router.sol", "function": "deposit"},
        ])
        r = _SEED.seed_undriven_flows(ws, q)
        self.assertEqual(r["undriven_flows"], 1)
        self.assertEqual(r["flow_seed_rows"], 2)
        rows = _json_bf.loads(q.read_text())["queue"]
        self.assertTrue(all("flow_context" in x for x in rows))
        self.assertEqual(rows[0]["flow_context"]["flow_id"], "BF-asset-lifecycle-deposit")
        # idempotent: a second run adds nothing
        self.assertEqual(_SEED.seed_undriven_flows(ws, q)["flow_seed_rows"], 0)

    def test_no_flows_noop(self):
        ws, q = self._ws([{"file": "a.sol", "function": "getConfig"}])
        self.assertEqual(_SEED.seed_undriven_flows(ws, q)["flow_seed_rows"], 0)
