"""Regression: Oscript AA (declarative-language) coverage credit in
function-coverage-completeness.py.

Capability (obyte 2026-07-09): the inscope-manifest enumerator emits lang="oscript"
units (Obyte Autonomous Agents; .oscript / .aa) that have NO ``function NAME(``
source-regex extractor, so the source-walk yielded ZERO units for them and the whole
Oscript hunt was uncredited. The fix (a) SEEDS declarative-language units directly from
the manifest and (b) credits a seeded unit real-attack/hollow from a hunt sidecar via a
tolerant FILE + fn-name match (line-span is impossible - AA units carry no decl line).

These tests pin:
  - only declarative (no-_FN_RE) langs are manifest-seeded; sol/go/rs are NOT (byte-identical);
  - a unit NAMED by a source-cited applies=no sidecar -> real-attack (covered);
  - a unit named by an applies=yes-without-PoC sidecar -> hollow;
  - a unit NOT named by any sidecar -> untouched (NO over-credit);
  - the tolerant matcher: case_N<-messages.cases[N]; $getter<-bare identifier; init<-segment;
  - the line-span passes do NOT over-credit line=0 declarative units.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "fcc_oscript", str(_TOOLS / "function-coverage-completeness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["fcc_oscript"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestOscriptDeclarativeCredit(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    # ---- workspace builder -------------------------------------------------
    def _ws(self, manifest_rows, sidecars):
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True)
        with (ws / ".auditooor" / "inscope_units.jsonl").open("w") as fh:
            for r in manifest_rows:
                fh.write(json.dumps(r) + "\n")
        # materialize the cited source files so they are "recognized" on disk.
        for r in manifest_rows:
            fp = ws / r["file"]
            fp.parent.mkdir(parents=True, exist_ok=True)
            if not fp.exists():
                fp.write_text("// oscript AA stub\n", encoding="utf-8")
        for name, obj in sidecars.items():
            (ws / ".auditooor" / "hunt_findings_sidecars" / name).write_text(
                json.dumps(obj), encoding="utf-8")
        return ws

    def _classify_map(self, ws):
        rep = self.m.evaluate(ws)
        return {(f["file"].split("/")[-1], f["name"]): f["classification"]
                for f in rep.get("functions", [])}

    # ---- language registration --------------------------------------------
    def test_seed_langs_and_exts(self):
        self.assertIn("oscript", self.m._MANIFEST_SEED_LANGS)
        # sol/rs/go MUST NOT be manifest-seed langs (they have _FN_RE extractors).
        for extractable in ("sol", "rs", "go", "move", "cairo"):
            self.assertNotIn(extractable, self.m._MANIFEST_SEED_LANGS)
        self.assertEqual(self.m._DECL_EXTS, frozenset({".oscript", ".aa"}))
        self.assertEqual(self.m._LANG_BY_EXT[".oscript"], "oscript")
        self.assertEqual(self.m._LANG_BY_EXT[".aa"], "oscript")

    def test_seed_takes_only_declarative_rows(self):
        ws = self._ws(
            manifest_rows=[
                {"file": "src/a.oscript", "function": "$g", "lang": "oscript"},
                {"file": "src/b.sol", "function": "transfer", "lang": "solidity"},
            ],
            sidecars={})
        seeded = self.m._seed_manifest_declarative_units(ws)
        names = {(Path(f.file).name, f.name, f.lang) for f in seeded}
        self.assertEqual(names, {("a.oscript", "$g", "oscript")})  # sol NOT seeded

    # ---- tolerant matcher --------------------------------------------------
    def test_tolerant_matcher(self):
        tok = self.m._declarative_anchor_tokens(
            "$adjust_prices / messages.cases[2] (mint) - init error checks")
        self.assertTrue(self.m._declarative_unit_matches_anchor("$adjust_prices", tok))
        self.assertTrue(self.m._declarative_unit_matches_anchor("case_2", tok))
        # case_1 is NOT referenced -> no match; case_20 must not match cases[2].
        self.assertFalse(self.m._declarative_unit_matches_anchor("case_1", tok))
        self.assertFalse(self.m._declarative_unit_matches_anchor("case_20", tok))
        # plain 'init' must NOT match a substring inside "init error checks"
        # (only an exact slash-SEGMENT credits a plain unit).
        self.assertFalse(self.m._declarative_unit_matches_anchor("init", tok))
        # a getter written WITHOUT the $ still matches (authors do both).
        tok2 = self.m._declarative_anchor_tokens("has_attestation / distribute")
        self.assertTrue(self.m._declarative_unit_matches_anchor("$has_attestation", tok2))

    # ---- end-to-end credit: both directions --------------------------------
    def _rows(self):
        f = "src/foo.oscript"
        return [{"file": f, "function": n, "lang": "oscript"} for n in
                ("$adjust_prices", "$pow2", "case_1", "case_2", "init")]

    def test_covered_hollow_and_untouched(self):
        # sidecar 1: applies=no + source cite -> credits $adjust_prices & case_1 (covered).
        sc1 = {
            "workspace_path": "IGNORED",
            "function_anchor": {"file": "src/foo.oscript",
                                "function": "$adjust_prices / messages.cases[1]",
                                "line": 9},
            "task_type": "hunt",
            "result": {"applies_to_target": "no",
                       "file_line": "src/foo.oscript:9-20"},
        }
        # sidecar 2: applies=yes WITHOUT confirmed/PoC -> case_2 examined -> hollow.
        sc2 = {
            "workspace_path": "IGNORED",
            "function_anchor": {"file": "src/foo.oscript",
                                "function": "messages.cases[2]", "line": 30},
            "task_type": "hunt",
            "result": {"applies_to_target": "yes", "confidence": "medium",
                       "candidate_finding": "possible issue",
                       "file_line": "src/foo.oscript:30-40"},
        }
        ws = self._ws(self._rows(), {"sc1.json": sc1, "sc2.json": sc2})
        cm = self._classify_map(ws)
        # all 5 oscript units RECOGNIZED
        self.assertEqual(sum(1 for k in cm if k[0] == "foo.oscript"), 5)
        # DIRECTION 1 - hunted + source-cited -> covered
        self.assertEqual(cm[("foo.oscript", "$adjust_prices")], "real-attack")
        self.assertEqual(cm[("foo.oscript", "case_1")], "real-attack")
        # examined-but-unconfirmed -> hollow (NOT covered, NOT untouched)
        self.assertEqual(cm[("foo.oscript", "case_2")], "hollow")
        # DIRECTION 2 - NOT named by any sidecar -> untouched (no over-credit)
        self.assertEqual(cm[("foo.oscript", "$pow2")], "untouched")
        self.assertEqual(cm[("foo.oscript", "init")], "untouched")

    def test_no_overcredit_when_sidecar_only_has_freetext_label(self):
        # A sidecar whose anchor is a pure free-text label (no $getter, no cases[N])
        # must credit NOTHING (the manifest has no such descriptive fn name).
        sc = {
            "workspace_path": "IGNORED",
            "function_anchor": {"file": "src/foo.oscript",
                                "function": "restore-user-balances / build-houses",
                                "line": 100},
            "task_type": "hunt",
            "result": {"applies_to_target": "no",
                       "file_line": "src/foo.oscript:100-120"},
        }
        ws = self._ws(self._rows(), {"sc.json": sc})
        cm = self._classify_map(ws)
        self.assertTrue(all(v == "untouched"
                            for k, v in cm.items() if k[0] == "foo.oscript"),
                        f"free-text-label sidecar over-credited: {cm}")


class TestDescriptiveAnchorCanonicalCredit(unittest.TestCase):
    """The descriptive-anchor join gap (obyte 2026-07-10): Oscript hunt sidecars
    carry a DESCRIPTIVE function_anchor.function (``case_12 (end rental, called by
    anyone)`` / ``case_16_edit_plot``) while the canonical unit key is bare
    ``case_12`` / ``case_16``. The underscore-blind legacy case regex
    (``cases?\\s*\\[?\\s*(\\d+)``) matched the space/bracket forms but NOT the
    underscore forms, leaving ~182 genuinely-hunted units untouched. The
    canonicalization helper closes the join without over-crediting a neighbour."""

    def setUp(self):
        self.m = _load()

    # ---- unit-level canonicalization --------------------------------------
    def test_canonical_key_case_forms(self):
        c = self.m._canonical_decl_key
        self.assertEqual(c("case_12 (end rental, called by anyone)"), "case_12")
        self.assertEqual(c("case 17 (edit user)"), "case_17")
        self.assertEqual(c("case_16_edit_plot"), "case_16")
        self.assertEqual(c("messages.cases[0] (define ...)"), "case_0")
        self.assertEqual(c("case_12"), "case_12")   # already-canonical unit key
        # LEADING token only: a trailing digit in a suffix is never picked.
        self.assertEqual(c("case_1_stake_2_tokens"), "case_1")

    def test_canonical_key_getter_and_keyword(self):
        c = self.m._canonical_decl_key
        self.assertEqual(c("$get_variables"), "$get_variables")
        self.assertEqual(c("$get_rewards (referral reward getter)"), "$get_rewards")
        self.assertEqual(c("init"), "init")
        self.assertEqual(c("set_nickname"), "set_nickname")

    def test_canonical_key_failsafe(self):
        c = self.m._canonical_decl_key
        # uncanonicalizable descriptive blobs / empties -> None (never credited).
        self.assertIsNone(c(""))
        self.assertIsNone(c("restore-user-balances / build-houses"))
        self.assertIsNone(c("(whole-file, perpetual-aa AA factory)"))
        self.assertIsNone(c("'add support to a value' (vote+deposit) + 'withdraw'"))

    def test_matcher_canonical_equality(self):
        f = self.m._declarative_unit_matches_anchor_canonical
        # (a) descriptive underscore anchor CREDITS the exact case unit.
        self.assertTrue(f("case_12", "case_12 (end rental, called by anyone)"))
        # (b) it does NOT credit the NEIGHBOUR case_13 (no over-credit).
        self.assertFalse(f("case_13", "case_12 (end rental, called by anyone)"))
        # (c) uncanonicalizable anchor -> never a match.
        self.assertFalse(f("case_12", "restore-user-balances / build-houses"))

    # ---- end-to-end credit through evaluate() ------------------------------
    def _rows(self):
        f = "src/rental.oscript"
        return [{"file": f, "function": n, "lang": "oscript"} for n in
                ("case_12", "case_13", "$get_variables")]

    def _classify_map(self, ws):
        rep = self.m.evaluate(ws)
        return {(x["file"].split("/")[-1], x["name"]): x["classification"]
                for x in rep.get("functions", [])}

    def _ws(self, rows, sidecars):
        ws = Path(tempfile.mkdtemp()).resolve()
        (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True)
        with (ws / ".auditooor" / "inscope_units.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        for r in rows:
            fp = ws / r["file"]
            fp.parent.mkdir(parents=True, exist_ok=True)
            if not fp.exists():
                fp.write_text("// oscript AA stub\n", encoding="utf-8")
        for name, obj in sidecars.items():
            (ws / ".auditooor" / "hunt_findings_sidecars" / name).write_text(
                json.dumps(obj), encoding="utf-8")
        return ws

    def test_end_to_end_descriptive_credit_no_overcredit_and_failsafe(self):
        # (a) descriptive underscore anchor for case_12, source-cited applies=no.
        sc_case = {
            "workspace_path": "IGNORED",
            "function_anchor": {"file": "src/rental.oscript",
                                "function": "case_12 (end rental, called by anyone)",
                                "line": 40},
            "task_type": "hunt",
            "result": {"applies_to_target": "no",
                       "file_line": "src/rental.oscript:40-60"},
        }
        # (c) an uncanonicalizable garbage anchor must credit NOTHING.
        sc_garbage = {
            "workspace_path": "IGNORED",
            "function_anchor": {"file": "src/rental.oscript",
                                "function": "restore-user-balances / build-houses",
                                "line": 90},
            "task_type": "hunt",
            "result": {"applies_to_target": "no",
                       "file_line": "src/rental.oscript:90-99"},
        }
        ws = self._ws(self._rows(),
                      {"sc_case.json": sc_case, "sc_garbage.json": sc_garbage})
        cm = self._classify_map(ws)
        # all three units recognized
        self.assertEqual(sum(1 for k in cm if k[0] == "rental.oscript"), 3)
        # (a) case_12 CREDITED via the descriptive underscore anchor
        self.assertEqual(cm[("rental.oscript", "case_12")], "real-attack")
        # (b) NO over-credit: neighbour case_13 stays untouched
        self.assertEqual(cm[("rental.oscript", "case_13")], "untouched")
        # (c) fail-safe: garbage anchor credited nothing; $get_variables untouched
        self.assertEqual(cm[("rental.oscript", "$get_variables")], "untouched")


if __name__ == "__main__":
    unittest.main()
