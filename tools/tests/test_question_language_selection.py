"""Regression: language-aware question selection. A Rust/crypto target must
prefer rust + crypto + agnostic questions and (with exclude) drop EVM-only
ones; a Solidity target the reverse. The promoted bank is untagged, so language
is inferred from text. Generic-fix anchor: monero-oxide (rust) was fed the full
EVM-heavy bank and got 0 signal.
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "mimo-harness-batch-gen.py"


def _load():
    spec = importlib.util.spec_from_file_location("mhbg", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["mhbg"] = m
    spec.loader.exec_module(m)
    return m


M = _load()


class TestLanguageSelection(unittest.TestCase):
    def test_infer(self):
        self.assertEqual(M._infer_question_language(
            "Does the fiat-shamir transcript absorb all public inputs before the scalar challenge?"), "crypto")
        self.assertEqual(M._infer_question_language(
            "Can msg.sender bypass the onlyOwner modifier via delegatecall in this ERC20?"), "solidity")
        self.assertEqual(M._infer_question_language(
            "Does the function unwrap() an Option<T> on attacker bytes in unsafe code?"), "rust")
        self.assertEqual(M._infer_question_language("generic logic question about ordering"), "")

    def test_fit(self):
        self.assertGreater(M._language_fit("rust", "rust"), M._language_fit("solidity", "rust"))
        self.assertGreater(M._language_fit("crypto", "rust"), M._language_fit("", "rust"))
        self.assertLess(M._language_fit("solidity", "rust"), 0)  # hard mismatch penalized
        self.assertEqual(M._language_fit("anything", ""), 0)     # no target -> neutral

    def test_rust_target_prefers_crypto_drops_evm(self):
        with tempfile.TemporaryDirectory() as td:
            bank = Path(td) / "bank.jsonl"
            qs = [
                {"question_id": "evm1", "statement": "Can msg.sender drain via reentrancy in the ERC20 transferFrom approve flow with delegatecall and uint256 overflow on payable?"},
                {"question_id": "evm2", "statement": "Does onlyOwner modifier guard the selfdestruct path while msg.sender controls slippage in this solidity vault?"},
                {"question_id": "cry1", "statement": "Does the CLSAG signing path reuse a nonce across two messages, leaking the private scalar (key recovery, fiat-shamir transcript)?"},
                {"question_id": "neu1", "statement": "Is there an off-by-one in the loop bound that lets one extra element be processed before the terminating condition fires here?"},
            ]
            bank.write_text("\n".join(json.dumps(q) for q in qs), encoding="utf-8")
            # rust target, exclude mismatch -> EVM questions dropped, crypto first
            out = M.load_questions(bank, n=10, target_language="rust", exclude_mismatch=True)
            ids = [q["question_id"] for q in out]
            self.assertNotIn("evm1", ids)
            self.assertNotIn("evm2", ids)
            self.assertIn("cry1", ids)
            self.assertEqual(ids[0], "cry1")  # crypto ranked first
            self.assertIn("neu1", ids)        # agnostic kept

    def test_extra_seed_merged_and_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            bank = Path(td) / "bank.jsonl"
            bank.write_text(json.dumps({"question_id": "b1", "statement": "A generic question that is long enough to pass the eighty character minimum length filter here."}), encoding="utf-8")
            seed = Path(td) / "seed.jsonl"
            seed.write_text(json.dumps({"question_id": "s1", "target_language": "rust", "statement": "Does the bulletproof verifier enforce every inner-product constraint so a value outside the range cannot be proven (soundness)?"}), encoding="utf-8")
            out = M.load_questions(bank, n=10, target_language="rust", extra_paths=[seed])
            ids = [q["question_id"] for q in out]
            self.assertIn("s1", ids)
            self.assertIn("b1", ids)


if __name__ == "__main__":
    unittest.main()
