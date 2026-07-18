#!/usr/bin/env python3
"""Unit tests for tools/sibling-path-guard-diff.py.

Covers (>=6 cases):
 1. symmetric naming-convention pair (deposit/withdraw, same guard) -> no flag
 2. asymmetric naming-convention pair (withdraw missing a require) -> flagged
 3. Solidity modifier asymmetry (onlyOwner on one arm only) -> flagged
 4. Rust variant-arm pair (FDG-vs-L2Oracle shape, one impl missing ensure!) -> flagged
 5. Go sibling method asymmetry (Validate on one type only) -> flagged
 6. no in-scope source -> pass-no-source
 7. test files are excluded from the sweep -> no flag from test-only asymmetry
 8. JSONL record shape conforms to schema fields
 10. shared helper excludes vendored (@openzeppelin / interchaintest) surface,
     in-scope src/ surface still swept
 11. manifest-authoritative: unlisted file excluded, listed file swept
 12. tool-specific I<Name>.sol interface filter kept on top of the helper
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "sibling-path-guard-diff.py"
_spec = importlib.util.spec_from_file_location("sibling_path_guard_diff", _MOD_PATH)
spgd = importlib.util.module_from_spec(_spec)
# Register before exec so dataclass type resolution can see the module.
sys.modules["sibling_path_guard_diff"] = spgd
_spec.loader.exec_module(spgd)


def _mkws(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="spgd_test_"))
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


class TestSiblingPathGuardDiff(unittest.TestCase):

    def test_1_symmetric_pair_no_flag(self):
        ws = _mkws({"src/Vault.sol": """
contract Vault {
    function deposit(uint256 a) external onlyOwner {
        require(a > 0);
    }
    function withdraw(uint256 a) external onlyOwner {
        require(a > 0);
    }
}
"""})
        res = spgd.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-asymmetry", res)
        self.assertEqual(res["count"], 0)

    def test_2_asymmetric_naming_pair_flagged(self):
        ws = _mkws({"src/Vault.sol": """
contract Vault {
    function deposit(uint256 a) external {
        require(validAmount);
        onlyOwnerCheck();
    }
    function withdraw(uint256 a) external {
        // missing the require present on deposit
        balances[msg.sender] -= a;
    }
}
"""})
        res = spgd.evaluate(ws)
        self.assertTrue(res["verdict"].startswith("found-asymmetries"), res)
        self.assertGreaterEqual(res["count"], 1)
        rec = res["asymmetries"][0]
        self.assertEqual(rec["pair"], "deposit|withdraw")
        self.assertEqual(rec["pair_kind"], "naming-convention")
        # deposit has guards that withdraw lacks
        self.assertTrue(rec["guard_on_a_missing_on_b"])

    def test_2b_cross_module_name_match_is_not_a_sibling_pair(self):
        ws = _mkws({
            "src/a/Claim.sol": """
contract Claim {
    function reduceBytecodeClaims(uint256 a) external {
        require(a > 0);
    }
}
""",
            "src/b/Finalize.sol": """
contract Finalize {
    function finalizeRound(uint256 a) external {
        a;
    }
}
""",
        })
        res = spgd.evaluate(ws)
        naming = [r for r in res["asymmetries"] if r["pair_kind"] == "naming-convention"]
        self.assertFalse(naming, res["asymmetries"])

    def test_3_solidity_modifier_asymmetry_flagged(self):
        ws = _mkws({"src/Token.sol": """
contract Token {
    function mint(address to, uint256 amt) external onlyMinter {
        _balances[to] += amt;
    }
    function burn(address from, uint256 amt) external {
        _balances[from] -= amt;
    }
}
"""})
        res = spgd.evaluate(ws)
        self.assertTrue(res["verdict"].startswith("found-asymmetries"), res)
        rec = next(r for r in res["asymmetries"] if r["pair"] == "mint|burn")
        # onlyminter is on mint (path_a) but missing on burn
        self.assertIn("onlyminter", rec["guard_on_a_missing_on_b"])

    def test_4_rust_variant_arm_fdg_shape_flagged(self):
        ws = _mkws({
            "external/ismp/fdg.rs": """
impl Verifier for FaultDisputeGame {
    fn verify_proof(&self, p: Proof) -> Result<()> {
        ensure!(verify_not_challenged(p));
        Ok(())
    }
}
""",
            "external/ismp/oracle.rs": """
impl Verifier for L2OutputOracle {
    fn verify_proof(&self, p: Proof) -> Result<()> {
        // accepts unfinalized output with zero analogous guard
        Ok(())
    }
}
""",
        })
        res = spgd.evaluate(ws)
        self.assertTrue(res["verdict"].startswith("found-asymmetries"), res)
        variant = [r for r in res["asymmetries"] if r["pair_kind"] == "variant-arm"]
        self.assertTrue(variant, res["asymmetries"])
        rec = variant[0]
        self.assertEqual(rec["path_a"]["name"].lower(), "verify_proof")
        # one arm enforces a guard the other lacks
        self.assertTrue(rec["guard_on_a_missing_on_b"] or rec["guard_on_b_missing_on_a"])

    def test_4b_rust_inherent_same_name_constructors_are_not_variant_arms(self):
        ws = _mkws({
            "src/a.rs": """
struct A;
impl A {
    pub fn new(x: usize) -> Self {
        assert!(x > 0);
        A
    }
}
""",
            "src/b.rs": """
struct B;
impl B {
    pub fn new() -> Self {
        B
    }
}
""",
        })
        res = spgd.evaluate(ws)
        variant = [r for r in res["asymmetries"] if r["pair_kind"] == "variant-arm"]
        self.assertFalse(variant, res["asymmetries"])

    def test_5_go_sibling_method_asymmetry_flagged(self):
        ws = _mkws({
            "src/sender.go": """
package x
func (s *Sender) Process(msg Msg) error {
    if err := ValidateLeaf(msg); err != nil {
        return err
    }
    return nil
}
""",
            "src/receiver.go": """
package x
func (r *Receiver) Process(msg Msg) error {
    // missing ValidateLeaf guard the sender applies
    return nil
}
""",
        })
        res = spgd.evaluate(ws)
        self.assertTrue(res["verdict"].startswith("found-asymmetries"), res)
        variant = [r for r in res["asymmetries"] if r["pair_kind"] == "variant-arm"]
        self.assertTrue(variant, res["asymmetries"])
        rec = variant[0]
        guards = rec["guard_on_a_missing_on_b"] + rec["guard_on_b_missing_on_a"]
        self.assertTrue(any("validateleaf" in g for g in guards), rec)

    def test_6_no_source_pass(self):
        ws = _mkws({"README.md": "# nothing to scan\n", "docs/notes.txt": "x"})
        res = spgd.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-source", res)
        self.assertEqual(res["count"], 0)

    def test_7_test_files_excluded(self):
        # An asymmetry that exists ONLY inside a test tree must not be flagged.
        ws = _mkws({"src/tests/Vault.t.sol": """
contract VaultTest {
    function deposit(uint256 a) external onlyOwner { require(a > 0); }
    function withdraw(uint256 a) external { }
}
"""})
        res = spgd.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-source", res)

    def test_8_jsonl_record_shape_and_written(self):
        ws = _mkws({"src/Pool.sol": """
contract Pool {
    function lock(uint256 a) external onlyAdmin { require(a > 0); }
    function unlock(uint256 a) external { }
}
"""})
        res = spgd.evaluate(ws)
        out_path = spgd._write_jsonl(ws, res["asymmetries"])
        self.assertTrue(out_path.exists())
        lines = out_path.read_text().strip().splitlines()
        self.assertGreaterEqual(len(lines), 1)
        rec = json.loads(lines[0])
        for key in ("schema", "candidate_gap_id", "pair", "pair_kind", "shared_invariant_hint",
                    "path_a", "path_b", "guard_on_a_missing_on_b",
                    "guard_on_b_missing_on_a", "file_lines", "verdict"):
            self.assertIn(key, rec)
        self.assertEqual(rec["schema"], "auditooor.sibling_path_guard_diff.v1")
        self.assertEqual(rec["verdict"], "asymmetry-candidate")
        self.assertEqual(len(rec["file_lines"]), 2)

    def test_9_error_on_missing_workspace(self):
        res = spgd.evaluate(Path("/nonexistent/ws/path/xyz123"))
        self.assertEqual(res["verdict"], "error", res)

    # -- shared-helper wiring (tools/lib/scope_exclusion.py) -----------------
    def test_10_shared_helper_excludes_vendored_surface(self):
        """An @openzeppelin / interchaintest vendored surface (which the legacy
        in-file _NON_IMPL_SEGMENTS did NOT cover) is now dropped by the shared
        scope_exclusion helper, while the in-scope src/ surface is still swept.
        Proves: OOS surface excluded AND in-scope surface present."""
        ws = _mkws({
            # in-scope production surface with a genuine asymmetry
            "src/Vault.sol": """
contract Vault {
    function deposit(uint256 a) external onlyOwner { require(a > 0); }
    function withdraw(uint256 a) external { }
}
""",
            # vendored OZ copy with the SAME asymmetry - must NOT be paired/flagged
            "contracts/@openzeppelin/token/Vault.sol": """
contract Vault {
    function deposit(uint256 a) external onlyOwner { require(a > 0); }
    function withdraw(uint256 a) external { }
}
""",
            # Cosmos/IBC integration-test harness dir - must NOT be swept
            "x/interchaintest/relayer.go": """
package x
func (s *Sender) Process(msg Msg) error { return ValidateLeaf(msg) }
func (r *Receiver) Process(msg Msg) error { return nil }
""",
        })
        res = spgd.evaluate(ws)
        self.assertTrue(res["verdict"].startswith("found-asymmetries"), res)
        files = set()
        for rec in res["asymmetries"]:
            files.add(rec["path_a"]["file"])
            files.add(rec["path_b"]["file"])
        # in-scope surface IS present
        self.assertTrue(any("src/Vault.sol" in f for f in files), files)
        # OOS surfaces are ABSENT (no @openzeppelin / interchaintest anywhere)
        self.assertFalse(any("@openzeppelin" in f for f in files), files)
        self.assertFalse(any("interchaintest" in f for f in files), files)

    def test_11_manifest_authoritative_excludes_unlisted_file(self):
        """When <ws>/.auditooor/inscope_units.jsonl is present, membership is
        manifest-authoritative: a source file NOT enumerated in the manifest is
        excluded from the sweep, while a listed file is still swept and flagged.
        Proves the is_in_scope(rel, workspace=ws) wiring is honoured."""
        ws = _mkws({
            "src/InScope.sol": """
contract C {
    function lock(uint256 a) external onlyAdmin { require(a > 0); }
    function unlock(uint256 a) external { }
}
""",
            # identical asymmetry, but this file is absent from the manifest
            "src/OutScope.sol": """
contract D {
    function lock(uint256 a) external onlyAdmin { require(a > 0); }
    function unlock(uint256 a) external { }
}
""",
        })
        manifest = ws / ".auditooor" / "inscope_units.jsonl"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({
            "file": "src/InScope.sol", "function": "lock",
            "file_line": "src/InScope.sol:3", "lang": "solidity",
        }) + "\n", encoding="utf-8")
        res = spgd.evaluate(ws)
        files = set()
        for rec in res["asymmetries"]:
            files.add(rec["path_a"]["file"])
            files.add(rec["path_b"]["file"])
        # listed file IS swept (its lock/unlock asymmetry is flagged)
        self.assertTrue(any("InScope.sol" in f for f in files), (res["verdict"], files))
        # unlisted file is EXCLUDED by the manifest-authoritative decision
        self.assertFalse(any("OutScope.sol" in f for f in files), files)

    def test_12_sol_interface_by_name_still_excluded(self):
        """TOOL-SPECIFIC filter kept on top of the shared helper: a top-level
        I<Name>.sol interface (body-less, guard-less) is excluded even though it
        is not in an interfaces/ dir and is not generically OOS."""
        self.assertTrue(spgd._is_out_of_scope("src/IVault.sol", ws=None))
        self.assertTrue(spgd._is_sol_interface_name("src/IVault.sol"))
        # a normal contract whose name merely starts with I + lowercase is NOT
        # an interface by convention and stays in scope
        self.assertFalse(spgd._is_sol_interface_name("src/Inventory.sol"))


class TestSiblingGuardGroupBound(unittest.TestCase):
    """The O(group^2) pairwise heuristics must be bounded so a boilerplate name
    (String/Read/Write across thousands of Go files) cannot explode memory."""

    def test_large_name_group_is_skipped_at_cap(self):
        # 200 arms sharing one name, all distinct files/types -> would be ~20k
        # pairs unbounded. With the cap (50) the whole group is skipped.
        arms = [
            spgd.FnArm(name="String", file=f"src/bor/p{i}/x.go", line=10,
                       guards=set(), ctx_type=f"T{i}")
            for i in range(200)
        ]
        old = spgd._MAX_ARMS_PER_NAME_GROUP
        try:
            spgd._MAX_ARMS_PER_NAME_GROUP = 50
            self.assertEqual(
                spgd._pair_variant_arms(arms), [],
                "a 200-arm boilerplate group must be skipped at cap=50",
            )
        finally:
            spgd._MAX_ARMS_PER_NAME_GROUP = old

    def test_small_sibling_pair_still_flagged_under_cap(self):
        # A genuine 2-arm sibling variant with asymmetric guards is unaffected
        # by the cap.
        arms = [
            spgd.FnArm(name="verifyProof", file="src/a/x.go", line=10,
                       guards={"require:auth"}, ctx_type="A"),
            spgd.FnArm(name="verifyProof", file="src/b/y.go", line=20,
                       guards=set(), ctx_type="B"),
        ]
        old = spgd._MAX_ARMS_PER_NAME_GROUP
        try:
            spgd._MAX_ARMS_PER_NAME_GROUP = 50
            res = spgd._pair_variant_arms(arms)
            self.assertEqual(len(res), 1, "small asymmetric sibling pair must still flag")
        finally:
            spgd._MAX_ARMS_PER_NAME_GROUP = old

    def test_naming_pair_product_is_bounded(self):
        # deposit x withdraw with thousands on each side -> bounded.
        arms = (
            [spgd.FnArm(name="deposit", file=f"src/a{i}.go", line=1, guards=set())
             for i in range(80)]
            + [spgd.FnArm(name="withdraw", file=f"src/b{i}.go", line=1, guards=set())
               for i in range(80)]
        )
        old = spgd._MAX_ARMS_PER_NAME_GROUP
        try:
            spgd._MAX_ARMS_PER_NAME_GROUP = 50
            # 80 > 50 on each side -> the naming pair is skipped, no explosion.
            self.assertEqual(spgd._pair_naming_convention(arms), [])
        finally:
            spgd._MAX_ARMS_PER_NAME_GROUP = old


if __name__ == "__main__":
    unittest.main()
