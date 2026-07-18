"""Tests for cosmos-production-harness-plan."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cosmos_production_harness_plan",
    ROOT / "tools" / "cosmos-production-harness-plan.py",
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)  # type: ignore[union-attr]


def _case(go_body: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="cosmos_harness_plan_"))
    (root / "poc_test.go").write_text(go_body, encoding="utf-8")
    return root


def _by_id(payload: dict, req_id: str) -> dict:
    return {req["id"]: req for req in payload["requirements"]}[req_id]


class CosmosProductionHarnessPlanTests(unittest.TestCase):
    def test_ready_single_validator_production_path(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestProductionPath() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    db2, _ := dbm.NewGoLevelDB("app", t.TempDir())
    _ = db2
}
"""
        )
        payload = mod.build_plan(poc, claim_text="single-validator state-machine proof")
        self.assertEqual(payload["verdict"], "ready")
        self.assertEqual(_by_id(payload, "real_db_backend")["status"], "satisfied")
        self.assertEqual(_by_id(payload, "finalize_block_commit")["status"], "satisfied")
        self.assertEqual(_by_id(payload, "restart_behavior")["status"], "satisfied")
        self.assertEqual(_by_id(payload, "multi_validator_if_claimed")["status"], "not_applicable")

    def test_memdb_private_injection_and_missing_block_driver_are_blocking(self):
        poc = _case(
            """
package poc

import (
    dbm "github.com/cosmos/cosmos-db"
    "reflect"
    "unsafe"
)

func TestWeakProfile() {
    db := dbm.NewMemDB()
    nodeDB := any(db)
    _ = unsafe.Pointer(nil)
    reflect.ValueOf(nodeDB).Elem().FieldByName("legacyLatestVersion").SetInt(48)
}
"""
        )
        payload = mod.build_plan(poc)
        self.assertEqual(payload["verdict"], "needs_work")
        self.assertEqual(_by_id(payload, "real_db_backend")["status"], "violated")
        self.assertEqual(_by_id(payload, "no_private_state_injection")["status"], "violated")
        self.assertEqual(_by_id(payload, "finalize_block_commit")["status"], "missing")

    def test_advance_to_block_helper_satisfies_block_driver(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestDydxHelper() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    testApp.AdvanceToBlock(10, nil)
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
        )
        payload = mod.build_plan(poc)
        self.assertEqual(_by_id(payload, "finalize_block_commit")["status"], "satisfied")

    def test_rocksdb_signal_is_not_v1_production_backend(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestRocksDBProfile() {
    db, _ := dbm.NewRocksDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewRocksDB("app", t.TempDir())
}
"""
        )
        payload = mod.build_plan(poc)
        self.assertEqual(payload["verdict"], "needs_work")
        self.assertEqual(_by_id(payload, "real_db_backend")["status"], "missing")

    def test_network_claim_requires_multivalidator_signal(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestSingleNode() {
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
        )
        payload = mod.build_plan(poc, claim_text="network-level consensus halt")
        self.assertEqual(payload["verdict"], "needs_work")
        self.assertTrue(payload["claim_signals"]["network_claim"])
        self.assertEqual(_by_id(payload, "multi_validator_if_claimed")["status"], "missing")

    def test_network_claim_passes_with_multivalidator_signal(self):
        poc = _case(
            """
package poc

import dbm "github.com/cosmos/cosmos-db"

func TestMultiVal() {
    cfg.NumValidators = 4
    network.New(t, cfg)
    client.BroadcastTxSync(ctx, tx)
    db, _ := dbm.NewGoLevelDB("app", t.TempDir())
    app.FinalizeBlock(req)
    app.Commit()
    db.Close()
    _, _ = dbm.NewGoLevelDB("app", t.TempDir())
}
"""
        )
        payload = mod.build_plan(poc, claim_text="AppHash divergence between validators")
        self.assertEqual(payload["verdict"], "ready")
        self.assertEqual(_by_id(payload, "multi_validator_if_claimed")["status"], "satisfied")


if __name__ == "__main__":
    unittest.main()
