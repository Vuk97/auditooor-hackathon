#!/usr/bin/env python3
"""Offline tests for tools/fork-replay-assert.py (PR 104).

No forge, no network — fixtures are hand-crafted manifest + deltas JSON
files that include both existing per-address rows and fake
`targeted_watches` rows (as if PR 103 had produced them).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "fork-replay-assert.py"
sys.path.insert(0, str(ROOT / "tools"))


TX = "0x" + "ab" * 32
TX_FROM = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
VICTIM = "0x1111111111111111111111111111111111111111"
ATTACKER = "0x2222222222222222222222222222222222222222"
TOKEN = "0x3333333333333333333333333333333333333333"


def make_fixture(tmp: Path) -> tuple[Path, Path]:
    """Write manifest + deltas pair into tmp and return their paths."""
    manifest = {
        "schema_version": 1,
        "status": "executed",
        "tx": TX,
        "rpc": "https://mock-rpc.local",
        "block": 101,
        "fork_block": 100,
        "from": TX_FROM,
        "to": VICTIM,
        "artifacts": {},
    }
    deltas = {
        "schema_version": 1,
        "pre_block_number": "100",
        "post_block_number": "101",
        "addresses": {
            # Normal per-address rows.
            VICTIM: {
                "nativeWei": {"pre": "100", "post": "50", "delta": "-50"},
                "erc20": {
                    TOKEN: {
                        "pre": "1000000",
                        "post": "750000",
                        "delta": "-250000",
                    },
                },
            },
            ATTACKER: {
                "nativeWei": {"pre": "10", "post": "200", "delta": "190"},
                "erc20": {
                    TOKEN: {"pre": "0", "post": "250000", "delta": "250000"},
                },
            },
            # Sender row — must trip gas-aware semantics guard.
            TX_FROM: {
                "nativeWei": {"pre": "5000", "post": "4980", "delta": "-20"},
                "erc20": {},
            },
            # Reverted balanceOf — observed delta is null.
            "0x4444444444444444444444444444444444444444": {
                "nativeWei": {"pre": "0", "post": "0", "delta": "0"},
                "erc20": {
                    TOKEN: {"pre": None, "post": None, "delta": None},
                },
            },
        },
        # PR 103-style targeted rows. A label we can select by, and a
        # deliberately-null-delta row for the nonnumeric test.
        "targeted_watches": [
            {
                "label": "victim",
                "kind": "erc20",
                "token": TOKEN,
                "holder": VICTIM,
                "pre": "1000000",
                "post": "750000",
                "delta": "-250000",
                "error": None,
            },
            {
                "label": "attacker",
                "kind": "erc20",
                "token": TOKEN,
                "holder": ATTACKER,
                "pre": "0",
                "post": "250000",
                "delta": "250000",
                "error": None,
            },
            {
                "label": "broken",
                "kind": "erc20",
                "token": TOKEN,
                "holder": "0x4444444444444444444444444444444444444444",
                "pre": None,
                "post": None,
                "delta": None,
                "error": "balanceOf reverted",
            },
        ],
    }
    manifest_path = tmp / f"{TX}_manifest.json"
    deltas_path = tmp / f"{TX}_deltas.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    deltas_path.write_text(json.dumps(deltas, indent=2, sort_keys=True))
    return manifest_path, deltas_path


def run_tool(manifest: Path, deltas: Path, *specs: str) -> dict:
    """Invoke fork-replay-assert.py and return the updated manifest dict."""
    args = [sys.executable, str(TOOL), "--manifest", str(manifest), "--deltas", str(deltas)]
    for s in specs:
        args += ["--assert-delta", s]
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        raise AssertionError(
            f"fork-replay-assert.py crashed: {proc.returncode}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return json.loads(manifest.read_text())


class ForkReplayAssertTest(unittest.TestCase):
    # ---------------------------------------------------------------------
    # PR 104 required cases
    # ---------------------------------------------------------------------
    def test_pass_case_label_selector(self) -> None:
        """Observed delta (-250000) < -1000 → PASS."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, "victim:lt:-1000")
            (a,) = manifest["assertions"]
            self.assertEqual(a["selector"], "victim")
            self.assertEqual(a["op"], "lt")
            self.assertEqual(a["status"], "PASS")
            self.assertEqual(a["observed_delta"], "-250000")
            self.assertIsNone(a["reason"])
            # matched row carries label through
            self.assertEqual(a["matched_row"]["label"], "victim")
            # Also persisted into deltas.json
            deltas_doc = json.loads(dp.read_text())
            self.assertEqual(len(deltas_doc["assertions"]), 1)
            self.assertEqual(deltas_doc["assertions"][0]["status"], "PASS")

    def test_pass_case_erc20_selector(self) -> None:
        """erc20:<token>:<holder> path."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, f"erc20:{TOKEN}:{ATTACKER}:eq:250000")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "PASS")
            self.assertEqual(a["matched_row"]["kind"], "erc20")

    def test_pass_case_native_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, f"native:{ATTACKER}:gt:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "PASS")
            self.assertEqual(a["observed_delta"], "190")

    def test_fail_case(self) -> None:
        """Observed delta (-250000) is NOT > 0 → FAIL."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, "victim:gt:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "FAIL")
            self.assertEqual(a["observed_delta"], "-250000")
            self.assertIsNone(a["reason"])

    def test_missing_selector_is_inconclusive(self) -> None:
        """A label that matches nothing → INCONCLUSIVE / 'no matching row'."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, "does_not_exist:gt:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertEqual(a["reason"], "no matching row")
            self.assertIsNone(a["matched_row"])
            self.assertIsNone(a["observed_delta"])

    def test_missing_native_address_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(
                mp, dp, "native:0x9999999999999999999999999999999999999999:eq:0"
            )
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertEqual(a["reason"], "no matching row")

    def test_null_observed_delta_is_inconclusive(self) -> None:
        """balanceOf reverted ⇒ delta is null ⇒ INCONCLUSIVE."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, "broken:eq:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertEqual(a["reason"], "observed delta is null")
            self.assertIsNone(a["observed_delta"])
            # matched_row is still reported so callers see the error string.
            self.assertIsNotNone(a["matched_row"])
            self.assertEqual(a["matched_row"].get("error"), "balanceOf reverted")

    def test_null_observed_delta_via_erc20_selector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(
                mp,
                dp,
                f"erc20:{TOKEN}:0x4444444444444444444444444444444444444444:eq:0",
            )
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertEqual(a["reason"], "observed delta is null")

    def test_native_sender_is_inconclusive_gas_aware(self) -> None:
        """native:<tx.from> must NOT claim a delta — gas math is hard."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(mp, dp, f"native:{TX_FROM}:lt:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertIn("gas", a["reason"].lower())
            self.assertIsNone(a["matched_row"])

    # ---------------------------------------------------------------------
    # operator coverage
    # ---------------------------------------------------------------------
    def test_operator_variants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            manifest = run_tool(
                mp,
                dp,
                "victim:eq:-250000",
                "victim:gte:-250000",
                "victim:lte:-250000",
                "victim:nonzero:0",
                "attacker:nonzero:0",
            )
            statuses = [a["status"] for a in manifest["assertions"]]
            self.assertEqual(statuses, ["PASS"] * 5)

    def test_nonzero_fails_when_zero(self) -> None:
        """Per-address row with delta "0" → nonzero ⇒ FAIL (not inconclusive)."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            # address 0x4444… has nativeWei.delta="0" — we can target it via
            # native:<address> (not tx.from, so gas guard does not trip).
            manifest = run_tool(
                mp,
                dp,
                "native:0x4444444444444444444444444444444444444444:nonzero:0",
            )
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "FAIL")

    # ---------------------------------------------------------------------
    # smoke: manifest and deltas both get the `assertions` array.
    # ---------------------------------------------------------------------
    def test_results_persisted_to_both_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            run_tool(mp, dp, "victim:lt:0", "attacker:gt:0")
            m = json.loads(mp.read_text())
            d = json.loads(dp.read_text())
            self.assertEqual(len(m["assertions"]), 2)
            self.assertEqual(len(d["assertions"]), 2)
            self.assertEqual(
                [r["status"] for r in m["assertions"]],
                [r["status"] for r in d["assertions"]],
            )


# Importable-module alias: the filename has a dash, so load for parse tests.
def _load_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("fr_assert", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class FailedReplayGateTest(unittest.TestCase):
    """Codex PR-102 blocker 5: any manifest.status outside {executed, success}
    must yield INCONCLUSIVE for every assertion, regardless of delta content.
    """

    def _write_fixture_with_status(self, tmp: Path, status: str) -> tuple[Path, Path]:
        mp, dp = make_fixture(tmp)
        # Override the status in the existing manifest
        payload = json.loads(mp.read_text())
        payload["status"] = status
        mp.write_text(json.dumps(payload, indent=2, sort_keys=True))
        return mp, dp

    def test_failed_status_forces_inconclusive_even_when_deltas_would_pass(self) -> None:
        """This is the exact scenario Codex called out: the cast-run replay
        failed, but the deltas file still happens to contain numbers. Without
        the gate, --fail-on-fail would mark everything PASS."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = self._write_fixture_with_status(Path(tmp), "failed")
            manifest = run_tool(mp, dp, "victim:lt:-1000")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")
            self.assertIn("manifest.status", a["reason"])
            self.assertIn("'failed'", a["reason"])

    def test_unknown_status_forces_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = self._write_fixture_with_status(Path(tmp), "partial")
            manifest = run_tool(mp, dp, "victim:nonzero:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")

    def test_missing_status_forces_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = make_fixture(Path(tmp))
            payload = json.loads(mp.read_text())
            payload.pop("status", None)
            mp.write_text(json.dumps(payload, indent=2, sort_keys=True))
            manifest = run_tool(mp, dp, "victim:lt:0")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "INCONCLUSIVE")

    def test_executed_status_accepted_and_evaluates_normally(self) -> None:
        """Codex PR-102 blocker 4: 'executed' is the real success status."""
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = self._write_fixture_with_status(Path(tmp), "executed")
            manifest = run_tool(mp, dp, "victim:lt:-1000")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "PASS")

    def test_success_status_accepted_and_evaluates_normally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mp, dp = self._write_fixture_with_status(Path(tmp), "success")
            manifest = run_tool(mp, dp, "victim:lt:-1000")
            (a,) = manifest["assertions"]
            self.assertEqual(a["status"], "PASS")


class ParseSpecTest(unittest.TestCase):
    def test_parse_label_selector(self) -> None:
        mod = _load_module()
        p = mod.parse_assertion_spec("victim:lt:-1000")
        self.assertEqual(p, {"selector": "victim", "op": "lt", "amount": "-1000"})

    def test_parse_erc20_selector_with_colons(self) -> None:
        mod = _load_module()
        p = mod.parse_assertion_spec(f"erc20:{TOKEN}:{VICTIM}:eq:-250000")
        self.assertEqual(p["selector"], f"erc20:{TOKEN}:{VICTIM}")
        self.assertEqual(p["op"], "eq")
        self.assertEqual(p["amount"], "-250000")

    def test_parse_rejects_bad_op(self) -> None:
        mod = _load_module()
        with self.assertRaises(ValueError):
            mod.parse_assertion_spec("victim:xx:0")

    def test_parse_rejects_missing_amount(self) -> None:
        mod = _load_module()
        with self.assertRaises(ValueError):
            mod.parse_assertion_spec("victim")


if __name__ == "__main__":
    unittest.main()
