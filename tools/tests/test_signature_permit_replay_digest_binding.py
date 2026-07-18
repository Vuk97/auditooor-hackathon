#!/usr/bin/env python3
"""Regression tests for
tools/signature-permit-replay-digest-binding-set-difference.py.

Proves the EIP-712 / ECDSA permit-replay set-difference query
RECOVER, MISSING(F)=REQUIRED\\PRESENT(F) is:
  - a SET relation that DISCRIMINATES (a recover fn whose digest binds
    {chainid, verifyingContract, consumed-nonce} is KEPT; dropping ANY one
    element flips it to a survivor) - i.e. NOT the trivial "all recover fns"
    answer;
  - TRANSITIVE / not a shape (chainid bound in a _getDomainSeparator helper
    reached through the recover fn's forward call closure - even in another file -
    correctly BINDS the fn; a same-body regex would false-flag it);
  - a DEF/USE relation for the nonce (a used-hash slot READ but never WRITTEN is a
    distinct survivor class - unlimited replay - that a token-present test cannot
    express);
  - scope-aware (a vendored / OOS recover fn carries no obligation);
  - honest on a degraded substrate.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "signature-permit-replay-digest-binding-set-difference.py"
_spec = importlib.util.spec_from_file_location("sig_replay", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class NodePredicateTest(unittest.TestCase):
    def test_recover_node_positive(self):
        for t in ("ECDSA.recover(hash, sig)", "ecrecover(h, v, r, s)",
                  "SignatureChecker.isValidSignatureNow(signer, h, sig)",
                  "signer.isValidSignatureNow(h, sig)",
                  "ECDSA.tryRecover(hash, sig)",
                  "crypto.SigToPub(digest, sig)",
                  "secp256k1.RecoverPubkey(msg, sig)"):
            self.assertTrue(mod.has_recover_node(t), t)

    def test_recover_node_negative(self):
        # 'recover' as a word / a variable named recoveredSigner / a comment is
        # NOT a recovery CALL node.
        for t in ("address recoveredSigner;", "// recover the signer later",
                  "function recoverFunds() external {}", "self.recovery_mode"):
            self.assertFalse(mod.has_recover_node(t), t)

    def test_binding_elements(self):
        self.assertTrue(mod.binding_chainid("block.chainid"))
        self.assertTrue(mod.binding_chainid("uint256 chainId,"))
        self.assertTrue(mod.binding_verifying_contract("address(this)"))
        self.assertTrue(mod.binding_verifying_contract("address verifyingContract"))
        self.assertFalse(mod.binding_chainid("uint256 amount"))
        self.assertFalse(mod.binding_verifying_contract("address(signer)"))

    def test_nonce_read_vs_write(self):
        self.assertTrue(mod.nonce_read("if (usedSignatures[h]) revert();"))
        self.assertTrue(mod.nonce_read("nonces[user]"))
        self.assertFalse(mod.nonce_write("if (usedSignatures[h]) revert();"))
        self.assertTrue(mod.nonce_write("usedSignatures[h] = true;"))
        self.assertTrue(mod.nonce_write("nonces[user]++;"))


# --------------------------------------------------------------------------
# End-to-end set-difference over a synthetic Solidity workspace. The MUTATION
# case: the base contract's _getDomainSeparator binds chainid + address(this);
# dropping address(this) from it (a one-line mutation) MUST flip the recover fn
# from KEPT to a survivor - proving the answer tracks the binding SET, not a
# shape.
# --------------------------------------------------------------------------
_BASE = """// SPDX-License-Identifier: MIT
contract Base {
    function _getDomainSeparator(string memory _name) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(_name)),
            block.chainid,
            %ADDR%
        ));
    }
}
"""

_VERIFIER = """// SPDX-License-Identifier: MIT
import "./Base.sol";
contract Verifier is Base {
    mapping(bytes32 => bool) public usedSignatures;
    address public amlSigner;
    function _verifyAML(string memory _name, bytes32 messageHash, bytes calldata sig, uint256 deadline) private {
        if (block.timestamp > deadline) revert();
        if (usedSignatures[messageHash]) revert();
        bytes32 h = MessageHashUtils.toTypedDataHash(_getDomainSeparator(_name), messageHash);
        address rec = ECDSA.recover(h, sig);
        if (rec != amlSigner) revert();
        %NONCEWRITE%
    }
}
"""


def _rec(fn, file, line, lang="solidity"):
    return {
        "schema": "dataflow_path.v1",
        "language": lang,
        "source": {"kind": "param-entrypoint", "fn": fn, "var": "sig",
                   "file": str(file), "line": line},
        "sink": {"kind": "state_var_read", "fn": fn, "callee": "amlSigner",
                 "file": str(file), "line": line},
        "guard_nodes": [],
        "degraded": False,
    }


class SetDifferenceE2ETest(unittest.TestCase):
    def _run(self, addr_expr, nonce_write=True):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "Base.sol").write_text(_BASE.replace("%ADDR%", addr_expr))
            nw = "usedSignatures[messageHash] = true;" if nonce_write else "// no consume"
            (src / "Verifier.sol").write_text(
                _VERIFIER.replace("%NONCEWRITE%", nw))
            au = ws / ".auditooor"
            au.mkdir()
            df = au / "dataflow_paths.jsonl"
            recs = [
                _rec("Verifier._verifyAML(string,bytes32,bytes,uint256)",
                     src / "Verifier.sol", 6),
                _rec("Base._getDomainSeparator(string)", src / "Base.sol", 3),
            ]
            df.write_text("\n".join(json.dumps(r) for r in recs))
            # fresh source cache per run (the tool caches file contents globally)
            mod._SRC_CACHE.clear()
            return mod.run(["--workspace", str(ws), "--json"])

    def test_fully_bound_is_kept(self):
        s = self._run("address(this)", nonce_write=True)
        self.assertEqual(s["size_RECOVER"], 1)
        self.assertEqual(s["size_survivors"], 0, s)
        self.assertEqual(s["size_KEPT_fully_bound"], 1)

    def test_mutation_drop_verifying_contract_flips_to_survivor(self):
        # the load-bearing non-vacuity mutation: drop address(this) from the
        # domain separator helper (a BEHAVIOR-CHANGING edit that removes the
        # cross-contract replay binding). The recover fn MUST become a survivor
        # missing exactly 'verifyingContract' - proving the set-difference is
        # not the trivial constant.
        s = self._run("amlSigner", nonce_write=True)  # a non-binding address expr
        self.assertEqual(s["size_RECOVER"], 1)
        self.assertEqual(s["size_survivors"], 1, s)
        surv = s["survivors"][0]
        self.assertIn("verifyingContract", surv["missing"])
        self.assertNotIn("chainid", surv["missing"])
        self.assertNotIn("consumed-nonce", surv["missing"])

    def test_transitive_closure_binds_across_file(self):
        # chainid + address(this) live in Base._getDomainSeparator (a DIFFERENT
        # file reached through the recover fn's forward call closure); the recover
        # fn is still KEPT - a same-file/same-body scan would miss it.
        s = self._run("address(this)", nonce_write=True)
        surv_fns = [x["fn"] for x in s["survivors"]]
        self.assertNotIn("_verifyAML", surv_fns)
        self.assertEqual(s["size_KEPT_fully_bound"], 1)

    def test_nonce_read_not_written_is_survivor(self):
        # the DEF/USE arm: the used-hash slot is READ (the guard) but the write
        # is removed -> unlimited replay. Survivor missing 'consumed-nonce' with
        # the nonce_read_not_written flag set.
        s = self._run("address(this)", nonce_write=False)
        self.assertEqual(s["size_survivors"], 1, s)
        surv = s["survivors"][0]
        self.assertIn("consumed-nonce", surv["missing"])
        self.assertTrue(surv["nonce_read_not_written"])


class ScopeAndDegradeTest(unittest.TestCase):
    def test_vendored_recover_carries_no_obligation(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            vend = ws / "vendor" / "lib"
            vend.mkdir(parents=True)
            (vend / "V.sol").write_text(
                "contract V { function f(bytes calldata s) external { "
                "address a = ECDSA.recover(h, s); } }")
            au = ws / ".auditooor"
            au.mkdir()
            (au / "dataflow_paths.jsonl").write_text(json.dumps(
                _rec("V.f(bytes)", vend / "V.sol", 1)))
            mod._SRC_CACHE.clear()
            s = mod.run(["--workspace", str(ws), "--json"])
            self.assertEqual(s["size_RECOVER"], 0)

    def test_all_degraded_is_honest(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            au = ws / ".auditooor"
            au.mkdir()
            r = _rec("C.f(bytes)", ws / "C.sol", 1)
            r["degraded"] = True
            (au / "dataflow_paths.jsonl").write_text(json.dumps(r))
            mod._SRC_CACHE.clear()
            s = mod.run(["--workspace", str(ws), "--json"])
            self.assertTrue(s["substrate_degraded"])
            self.assertEqual(s["size_RECOVER"], 0)


if __name__ == "__main__":
    unittest.main()
