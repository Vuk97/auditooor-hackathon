"""Regression: the executed-refutation-honesty gate must credit a value-mover NEGATIVE
when a GENUINELY mutation-verified mvc_sidecar campaign covers its unit (serving-join),
but NOT a vacuous campaign, and NEVER via a generic/path-leaked token (anti-over-credit).
Root-caused 2026-07-14 (NUVA: 592 value-mover NEGATIVEs had real mutation-verified fuzz
that collect_poc_records never scanned)."""
import importlib.util, json, pathlib, sys, tempfile, unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "executed-refutation-negative-gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("_erg", _TOOL)
    m = importlib.util.module_from_spec(spec); sys.modules["_erg"] = m
    spec.loader.exec_module(m); return m


_G = _load()


class TestMvcJoin(unittest.TestCase):
    def _ws(self, mvc):
        d = pathlib.Path(tempfile.mkdtemp()); (d / ".auditooor" / "mvc_sidecar").mkdir(parents=True)
        (d / ".auditooor" / "mvc_sidecar" / "m.json").write_text(json.dumps(mvc))
        return d

    def test_genuine_mutation_verified_credits(self):
        d = self._ws({"function": "SwapIn", "source_file": "src/vault/keeper/vault.go",
                      "mutants_killed": "1", "non_vacuous": True})
        recs = _G.collect_poc_records(str(d))
        self.assertTrue(any("vault.go" in r["tokens"] or "swapin" in r["tokens"] for r in recs), recs)
        self.assertTrue(all(r["executed"] and r["guard_neutralized"] for r in recs))

    def test_vacuous_campaign_not_credited(self):
        d = self._ws({"function": "SwapIn", "source_file": "src/vault/keeper/vault.go",
                      "mutants_killed": "0", "non_vacuous": False})
        self.assertEqual(_G.collect_poc_records(str(d)), [])

    def test_generic_tokens_stopworded(self):
        d = self._ws({"function": "SwapIn",
                      "source_file": "/Users/wolf/audits/nuva/src/vault/keeper/vault.go",
                      "mutants_killed": "2", "non_vacuous": True})
        recs = _G.collect_poc_records(str(d))
        toks = set().union(*(r["tokens"] for r in recs)) if recs else set()
        for g in ("users", "wolf", "audits", "nuva", "vault", "keeper"):
            self.assertNotIn(g, toks, f"generic token {g} must be stopworded")
        self.assertIn("vault.go", toks)


if __name__ == "__main__":
    unittest.main()
