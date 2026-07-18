"""Tests for tools/per-function-attack-worklist.py.

Covers: multi-line Solidity signatures, scope exclusion (test/lib/mock/
interface/script/certora-helpers), library-pure inclusion vs contract-view
exclusion, attack-topic taxonomy, emit/ingest round-trip, idempotent re-emit,
and the Rust/Go language paths. The morpho-midnight smoke anchor lives ONLY in
the dedicated smoke test (no morpho hardcoding leaks into the tool body)."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "per-function-attack-worklist.py"
SIDECAR_REL = ".auditooor/per_function_attack_worklist.jsonl"
MORPHO = Path("/Users/wolf/audits/morpho-midnight")


def run(args):
    return subprocess.run(
        ["python3", str(TOOL), *args],
        capture_output=True, text=True,
    )


def read_rows(ws: Path):
    rows = []
    for line in (ws / SIDECAR_REL).read_text().splitlines():
        obj = json.loads(line)
        if obj.get("schema") == "auditooor.per_function_attack_worklist.v1" and "function" not in obj:
            continue
        rows.append(obj)
    return rows


SOL_FIXTURE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct Market { address loanToken; uint256 lltv; }

contract Vault {
    uint256 public total;

    // multi-line signature with a struct arg and calldata bytes
    function repay(Market memory market, uint256 units, address onBehalf, bytes calldata data)
        external
        returns (uint256)
    {
        total += units;
        return total;
    }

    function setFee(uint256 newFee) public {
        total = newFee;
    }

    // view getter in a contract -> NOT an attack surface
    function balanceOf(address who) external view returns (uint256) {
        return total;
    }

    constructor() {}
    receive() external payable {}
}

library TickMath {
    // internal pure math IS the rounding/arithmetic attack surface
    function wExp(int256 x) internal pure returns (uint256) {
        return uint256(x);
    }
}

interface IOracle {
    function price() external view returns (uint256);
}
"""


class EmitSolidityTest(unittest.TestCase):
    def test_emit_parses_multiline_and_scopes_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(SOL_FIXTURE)
            r = run(["--workspace", str(ws), "--emit", "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            rows = read_rows(ws)
            fns = {row["function"]: row for row in rows}
            # multi-line state-mutating external function captured
            self.assertIn("repay", fns)
            self.assertIn("Market memory market", fns["repay"]["signature"])
            self.assertIn("bytes calldata data", fns["repay"]["signature"])
            # public state setter captured
            self.assertIn("setFee", fns)
            # library internal pure math captured (rounding surface)
            self.assertIn("wExp", fns)
            # contract view getter NOT captured
            self.assertNotIn("balanceOf", fns)
            # interface function NOT captured
            self.assertNotIn("price", fns)
            # constructor/receive NOT captured
            self.assertNotIn("constructor", fns)
            self.assertNotIn("receive", fns)

    def test_attack_topics_present_and_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            self.assertTrue(rows)
            for row in rows:
                self.assertEqual(row["status"], "pending")
                for topic in [
                    "auth/access", "oracle/price", "rounding/arithmetic",
                    "reentrancy/CEI", "economic/conservation",
                    "cross-function-composition",
                ]:
                    self.assertIn(topic, row["attack_topics"])
                self.assertIn(":", row["file_line"])


class ScopeExclusionTest(unittest.TestCase):
    def test_excludes_test_lib_mock_interface_script_certora(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for sub in ["src", "test", "lib", "src/mocks", "script",
                        "src/interfaces", "src/certora/helpers"]:
                (ws / sub).mkdir(parents=True, exist_ok=True)
            real = "contract Real { function poke() external { } }\n"
            (ws / "src" / "Real.sol").write_text(real)
            for excl_path, body in [
                ("test/RealTest.t.sol", "contract RealTest { function tt() external {} }"),
                ("lib/Dep.sol", "contract Dep { function dd() external {} }"),
                ("src/mocks/MockToken.sol", "contract MockToken { function mm() external {} }"),
                ("script/Deploy.s.sol", "contract Deploy { function run() external {} }"),
                ("src/interfaces/IThing.sol", "interface IThing { function ii() external; }"),
                ("src/certora/helpers/Havoc.sol", "contract Havoc { function havocAll() external {} }"),
            ]:
                (ws / excl_path).write_text(body)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            fns = {row["function"] for row in rows}
            self.assertEqual(fns, {"poke"},
                             f"only the real in-scope fn should survive; got {fns}")


class IngestRoundTripTest(unittest.TestCase):
    def test_ingest_folds_verdicts_and_reemit_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            repay = next(r for r in rows if r["function"] == "repay")

            verdicts = ws / "verdicts.jsonl"
            verdicts.write_text(
                json.dumps({
                    "file_line": repay["file_line"],
                    "function": "repay",
                    "contract": repay["contract"],
                    "status": "real-attack",
                    "verdict_detail": "drove all topics; holds",
                    "poc_path": "poc-tests/repay.t.sol",
                }) + "\n"
                # second verdict matched by file_line+function only (no contract)
                + json.dumps({
                    "file_line": next(r["file_line"] for r in rows if r["function"] == "wExp"),
                    "function": "wExp",
                    "status": "finding",
                    "severity": "MEDIUM",
                }) + "\n"
            )
            r = run(["--workspace", str(ws), "--ingest", str(verdicts), "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            summary = json.loads(r.stdout)
            self.assertEqual(summary["applied"], 2)
            self.assertEqual(summary["unmatched"], 0)

            after = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after["repay"]["status"], "real-attack")
            self.assertEqual(after["repay"]["poc_path"], "poc-tests/repay.t.sol")
            self.assertEqual(after["wExp"]["status"], "finding")
            self.assertEqual(after["wExp"]["severity"], "MEDIUM")

            # re-emit must preserve terminal verdicts
            run(["--workspace", str(ws), "--emit"])
            after2 = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after2["repay"]["status"], "real-attack")
            self.assertEqual(after2["wExp"]["status"], "finding")
            # pending functions remain pending
            self.assertEqual(after2["setFee"]["status"], "pending")

    def test_ingest_ignores_non_terminal_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            repay = next(r for r in rows if r["function"] == "repay")
            verdicts = ws / "v.jsonl"
            verdicts.write_text(json.dumps({
                "file_line": repay["file_line"], "function": "repay",
                "contract": repay["contract"], "status": "pending",
            }) + "\n")
            r = run(["--workspace", str(ws), "--ingest", str(verdicts), "--json"])
            self.assertEqual(json.loads(r.stdout)["applied"], 0)

    def test_ingest_normalizes_evidence_backed_clean_terminal_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            repay = next(r for r in rows if r["function"] == "repay")
            verdicts = ws / "clean.jsonl"
            verdicts.write_text(json.dumps({
                "file_line": repay["file_line"],
                "function": "repay",
                "contract": repay["contract"],
                "status": "CLEAN-NO-CONFIRMED-FINDING",
                "source_refs": [repay["file_line"]],
                "verdict_detail": "repay source-traced with no exploitable path",
            }) + "\n")
            r = run(["--workspace", str(ws), "--ingest", str(verdicts), "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["applied"], 1)
            after = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after["repay"]["status"], "clean")
            self.assertIn("source_refs", after["repay"])

            run(["--workspace", str(ws), "--emit"])
            after2 = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after2["repay"]["status"], "clean")

    def test_ingest_rejects_clean_terminal_verdict_without_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            repay = next(r for r in rows if r["function"] == "repay")
            verdicts = ws / "clean.jsonl"
            verdicts.write_text(json.dumps({
                "file_line": repay["file_line"],
                "function": "repay",
                "contract": repay["contract"],
                "status": "clean",
                "verdict_detail": "done",
            }) + "\n")
            r = run(["--workspace", str(ws), "--ingest", str(verdicts), "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["applied"], 0)
            after = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after["repay"]["status"], "pending")

    def test_ingest_rejects_clean_reason_with_function_but_no_source_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text(SOL_FIXTURE)
            run(["--workspace", str(ws), "--emit"])
            rows = read_rows(ws)
            repay = next(r for r in rows if r["function"] == "repay")
            verdicts = ws / "clean.jsonl"
            verdicts.write_text(json.dumps({
                "file_line": repay["file_line"],
                "function": "repay",
                "contract": repay["contract"],
                "status": "clean",
                "verdict_detail": "repay was reviewed and no exploitable path was found in this function",
            }) + "\n")
            r = run(["--workspace", str(ws), "--ingest", str(verdicts), "--json"])
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout)["applied"], 0)
            after = {r["function"]: r for r in read_rows(ws)}
            self.assertEqual(after["repay"]["status"], "pending")


class LanguageAwareTest(unittest.TestCase):
    def test_rust_pub_fns(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "lib.rs").write_text(
                "impl Vault {\n"
                "    pub fn deposit(&mut self, amount: u128) -> u128 { amount }\n"
                "    fn internal_helper(&self) {}\n"
                "    pub async fn withdraw(\n        &mut self,\n        amount: u128,\n    ) {}\n"
                "}\n"
            )
            run(["--workspace", str(ws), "--emit"])
            fns = {r["function"] for r in read_rows(ws)}
            self.assertIn("deposit", fns)
            self.assertIn("withdraw", fns)  # multi-line rust sig
            self.assertNotIn("internal_helper", fns)  # non-pub

    def test_go_exported_methods(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "keeper.go").write_text(
                "package keeper\n"
                "func (k Keeper) Deposit(ctx Context, amt int64) error { return nil }\n"
                "func (k Keeper) unexported() {}\n"
            )
            run(["--workspace", str(ws), "--emit"])
            fns = {r["function"] for r in read_rows(ws)}
            self.assertIn("Deposit", fns)
            self.assertNotIn("unexported", fns)  # lowercase -> not exported


class MorphoSmokeTest(unittest.TestCase):
    """The smoke anchor: the morpho-midnight surface must show MidnightBundles
    + TickLib + the fee setters as in-scope (and certora helpers excluded)."""

    @unittest.skipUnless(MORPHO.exists(), "morpho-midnight workspace not present")
    def test_morpho_surface(self):
        r = run(["--workspace", str(MORPHO), "--emit", "--json"])
        self.assertEqual(r.returncode, 0, r.stderr)
        summary = json.loads(r.stdout)
        per = summary["per_contract"]
        # the barely-touched surface must be enumerated
        self.assertGreaterEqual(per.get("MidnightBundles", 0), 1)
        self.assertGreaterEqual(per.get("TickLib", 0), 1)
        self.assertGreaterEqual(per.get("Midnight", 0), 1)
        # certora helpers must NOT leak into the surface
        self.assertNotIn("FlashLiquidateCallback", per)
        self.assertNotIn("Havoc", per)
        # the fee setters live on Midnight and must be present
        rows = read_rows(MORPHO)
        fns = {row["function"] for row in rows}
        for setter in ["setMarketContinuousFee", "setDefaultContinuousFee",
                       "setMarketSettlementFee", "setDefaultSettlementFee"]:
            self.assertIn(setter, fns)


if __name__ == "__main__":
    unittest.main()
