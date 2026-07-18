"""Guard: A2b - per-function hunter brief re-ranks by attack-class affinity, so two
different functions in the SAME workspace get DIFFERENT top questions (was a
workspace-constant collapse: all legacy rows scored 1 -> question_id tiebreak -> identical
top-5 for every function).

Builds a corpus of legacy workspace-scope rows (no target_function_patterns) with distinct
attack_class_anchors, then queries function=deposit vs function=setOwner and asserts the
top-ranked question differs (deposit -> inflation/accounting anchor; setOwner ->
access-control anchor).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # register BEFORE exec (frozen dataclass self-reference)
    spec.loader.exec_module(mod)
    return mod


vault_mcp_server = _load_module("vault_mcp_server_a2b", MODULE_PATH)


def _make_minimal_vault(vault_dir: Path) -> None:
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- e\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- i\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n\n## S\n- i\n", encoding="utf-8")
    g = vault_dir / "goals"; g.mkdir(exist_ok=True)
    (g / "current.md").write_text("---\nobjective: s\n---\n# g\n", encoding="utf-8")


# legacy workspace-scope rows: no target_function_patterns, distinct anchors
_ANCHORS = [
    "share-inflation", "accounting-rounding", "access-control-bypass",
    "ownership-takeover", "oracle-manipulation", "reentrancy-drain",
    "slippage-mev", "governance-timelock",
]
_CORPUS = [
    {"question_id": f"q{i:02d}", "question_text": f"legacy q {i} for {a}",
     "attack_class_anchor": a, "scope_specificity": "workspace",
     "grep_patterns": [], "target_function_patterns": [], "linked_invariant_ids": []}
    for i, a in enumerate(_ANCHORS)
]


class TestA2bRerank(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="a2b-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        self.hq = self.root / "hq.jsonl"
        self.hq.write_text("\n".join(json.dumps(r) for r in _CORPUS), encoding="utf-8")
        self.ws = self.root / "ws"; (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _top_qids(self, fn):
        res = self.query.vault_per_function_hunter_brief(
            workspace_path=str(self.ws),
            contract_path="src/Vault.sol",
            function_name=fn,
            hacker_questions_corpus_path=str(self.hq),
        )
        qs = (res.get("matched_hacker_questions") or res.get("hacker_questions")
              or (res.get("hacker_questions_response") or {}).get("questions") or [])
        return [q.get("question_id") for q in qs[:5] if isinstance(q, dict)]

    def test_top5_differs_across_functions_same_workspace(self):
        deposit_top = self._top_qids("deposit")
        setowner_top = self._top_qids("setOwner")
        self.assertTrue(deposit_top, "deposit brief returned no questions")
        self.assertTrue(setowner_top, "setOwner brief returned no questions")
        self.assertNotEqual(
            deposit_top, setowner_top,
            f"A2b: top-5 must differ across functions; both were {deposit_top}")
        # deposit should surface an inflation/accounting anchor at the very top
        self.assertNotEqual(deposit_top[0], setowner_top[0],
                            "top-ranked question must differ by function affinity")

    def test_affinity_discriminates_at_scope_tier(self):
        # The cosmetic +4 bonus was DROWNED by the +20 scope tier. With affinity as a
        # sort TIEBREAK, two functions must still get different top-ranked rows even when
        # every row is scope=function (all share the high base score).
        rows = [
            {"question_id": f"s{i:02d}", "question_text": f"scoped q for {a}",
             "attack_class_anchor": a, "scope_specificity": "function",
             "grep_patterns": [], "target_function_patterns": [], "linked_invariant_ids": []}
            for i, a in enumerate(_ANCHORS)
        ]
        hq = self.root / "hq_scope.jsonl"
        hq.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

        def top1(fn):
            res = self.query.vault_per_function_hunter_brief(
                workspace_path=str(self.ws), contract_path="src/Vault.sol",
                function_name=fn, hacker_questions_corpus_path=str(hq))
            qs = (res.get("matched_hacker_questions") or res.get("hacker_questions")
                  or (res.get("hacker_questions_response") or {}).get("questions") or [])
            return qs[0].get("question_id") if qs and isinstance(qs[0], dict) else None

        d, s = top1("deposit"), top1("setOwner")
        self.assertTrue(d and s)
        self.assertNotEqual(
            d, s, f"A2b fix: affinity must discriminate even at the scope tier; both top1={d}")


if __name__ == "__main__":
    unittest.main()
