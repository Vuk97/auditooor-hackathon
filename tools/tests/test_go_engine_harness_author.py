#!/usr/bin/env python3
"""Tests for tools/go-engine-harness-author.py.

Hermetic: builds a tiny in-tmpdir Go package + a tiny invariant corpus, runs the
author, and asserts on the manifest + emitted files. No `go` invocation is
required for the unit assertions (a separate, skip-if-missing test compiles the
output with the real toolchain when `go` is on PATH).

A dedicated test asserts the authored Go property bodies satisfy the PR4a
proof-gate NOTION (real asserted property, not a no-op) by applying the gate's
OWN tautology detectors (engine-harness-proof-gate._is_tautological_body and its
neutered-mutation / self-equality regexes) to each generated property body. We
do not call the gate's `.go` dispatch path because the shared gate does not yet
parse Go function-name conventions; instead we reuse its primitive predicates,
which IS the proof-gate notion.
"""
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-engine-harness-author.py"
_spec = importlib.util.spec_from_file_location("go_engine_harness_author", _TOOL)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

# PR4a proof-gate, loaded by file path (hyphenated filename). We reuse its
# tautology primitives to certify the proof-gate notion against Go bodies.
_GATE_TOOL = Path(__file__).resolve().parents[1] / "engine-harness-proof-gate.py"
_gspec = importlib.util.spec_from_file_location("engine_harness_proof_gate", _GATE_TOOL)
GATE = importlib.util.module_from_spec(_gspec)
_gspec.loader.exec_module(GATE)


_PKG_GO = """package codec

// Decode parses bytes into an int.
func Decode(b []byte) (int, error) {
\tif len(b) == 0 {
\t\treturn 0, nil
\t}
\treturn int(b[0]), nil
}

// Encode renders an int back to bytes (round-trip partner of Decode).
func Encode(v int) ([]byte, error) {
\treturn []byte{byte(v)}, nil
}

// Normalize canonicalizes a string (idempotent shape: string -> string).
func Normalize(s string) string {
\treturn s
}

// Validate checks a payload (bool-returning predicate).
func Validate(payload []byte) bool {
\treturn len(payload) < 1024
}

// Apply mutates via pointer receiver; equality props must be skipped.
func (c *Cursor) Advance(n uint64) uint64 {
\tc.pos += n
\treturn c.pos
}

// helper is unexported -> must be skipped.
func helper(x int) int { return x }

// String is an accessor -> must be skipped.
func String() string { return "" }
"""

_TYPES_GO = """package codec

type Cursor struct{ pos uint64 }
"""


# GAP 1 fixture: a cosmos-style keeper package whose money-movers are RECEIVER
# methods taking sdk.Context / sdk.Coins - previously authored 0 (silent drop).
_KEEPER_GO = """package feekeeper

import (
\tsdk "github.com/cosmos/cosmos-sdk/types"
)

type Keeper struct{}

// deductFee is an UNEXPORTED keeper money-mover taking sdk.Context + sdk.Coins.
func (k Keeper) deductFee(ctx sdk.Context, payer sdk.AccAddress, fee sdk.Coins) error {
\treturn nil
}

// ComputeTransferFee is an EXPORTED keeper method taking sdk.Context.
func (k Keeper) ComputeTransferFee(ctx sdk.Context, amount sdk.Coins) sdk.Coins {
\treturn amount
}

// PlainScalar is an exported method with only a fuzzable scalar (NOT keeper-shaped);
// it must NOT become a keeper scaffold (no sdk.Context/Coins) and stays a normal
// method skip (no free-function fuzz author).
func (k Keeper) PlainScalar(n uint64) uint64 {
\treturn n
}
"""


def _write_keeper_pkg(ws: Path, pkg: str = "feekeeper") -> Path:
    d = ws / pkg
    d.mkdir(parents=True)
    (d / "keeper.go").write_text(_KEEPER_GO)
    return d


def _write_pkg(ws: Path, pkg: str = "codec") -> Path:
    d = ws / pkg
    d.mkdir(parents=True)
    (d / "codec.go").write_text(_PKG_GO)
    (d / "types.go").write_text(_TYPES_GO)
    return d


def _write_corpus(repo_root: Path):
    d = repo_root / "audit" / "corpus_tags" / "derived"
    d.mkdir(parents=True)
    rows = [
        {"invariant_id": "INV-BND-001", "category": "bounds",
         "statement": "Length-prefixed decode MUST reject lengths exceeding the buffer.",
         "target_lang": "go"},
        {"invariant_id": "INV-DET-001", "category": "determinism",
         "statement": "Same input MUST yield same output.", "target_lang": "go"},
        {"invariant_id": "INV-SND-001", "category": "soundness",
         "statement": "Accepted iff valid.", "target_lang": "any"},
        {"invariant_id": "INV-AUT-001", "category": "authorization",
         "statement": "Only an authorized caller may proceed.", "target_lang": "go"},
        {"invariant_id": "INV-ORD-001", "category": "ordering",
         "statement": "Settles only after checks.", "target_lang": "go"},
        {"invariant_id": "INV-CON-001", "category": "conservation",
         "statement": "Value moved MUST be conserved: no value created or destroyed.",
         "target_lang": "go"},
        # a rust/solidity row that MUST be ignored
        {"invariant_id": "INV-RS-999", "category": "bounds",
         "statement": "ignored", "target_lang": "rust"},
        {"invariant_id": "INV-SOL-999", "category": "bounds",
         "statement": "ignored", "target_lang": "solidity"},
    ]
    (d / "invariants_extracted.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    (d / "invariants_pilot.jsonl").write_text("")


class TestGoEngineHarnessAuthor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _write_corpus(self.repo)
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.pkg = _write_pkg(self.ws)

    def tearDown(self):
        self.tmp.cleanup()

    def _author(self, selector, **kw):
        return M.author(self.ws, selector, repo_root=self.repo, **kw)

    # 1. corpus load filters to go|any only
    def test_load_filters_lang(self):
        invs = M.load_go_invariants(self.repo)
        ids = {i["invariant_id"] for i in invs}
        self.assertIn("INV-BND-001", ids)
        self.assertIn("INV-SND-001", ids)        # any included
        self.assertNotIn("INV-RS-999", ids)      # rust excluded
        self.assertNotIn("INV-SOL-999", ids)     # solidity excluded

    # 2. whole-package author succeeds and skips helper/String/accessors
    def test_author_whole_pkg(self):
        m = self._author("codec", dry_run=True)
        self.assertEqual(m["status"], "ok")
        fns = {a["function"] for a in m["authored"]}
        self.assertIn("Decode", fns)
        self.assertIn("Validate", fns)
        self.assertNotIn("helper", fns)   # unexported
        self.assertNotIn("String", fns)   # accessor skip-list

    # 3. round-trip emitted on the DECODE side only (not Encode)
    def test_roundtrip_decode_side_only(self):
        m = self._author("codec", dry_run=True)
        by_fn = {a["function"]: a for a in m["authored"]}
        self.assertIn("FuzzPropRoundTripDecode", by_fn["Decode"]["property_fns"])
        # Encode must NOT carry a round-trip prop (avoids double emission)
        self.assertFalse(any(p.startswith("FuzzPropRoundTrip")
                             for p in by_fn["Encode"]["property_fns"]))

    # 4. idempotence emitted for Normalize (string->string normalize shape)
    def test_idempotence_for_normalize(self):
        m = self._author("codec", dry_run=True)
        by_fn = {a["function"]: a for a in m["authored"]}
        self.assertIn("FuzzPropIdempotenceNormalize", by_fn["Normalize"]["property_fns"])

    # 5. no-panic fuzz + determinism present on a pure value fn
    def test_nopanic_and_determinism(self):
        m = self._author("codec", dry_run=True)
        by_fn = {a["function"]: a for a in m["authored"]}
        self.assertIn("FuzzValidate", by_fn["Validate"]["property_fns"])
        self.assertIn("FuzzPropDeterminismValidate", by_fn["Validate"]["property_fns"])

    # 6. methods (pointer/value receiver) are NOT authored: calling `Method(in)`
    #    as a free function does not compile; a constructed receiver + protocol
    #    state cannot be safely synthesized from shape alone.
    def test_methods_excluded(self):
        m = self._author("codec", dry_run=True)
        fns = {a["function"] for a in m["authored"]}
        self.assertNotIn("Advance", fns)
        for a in m["authored"]:
            self.assertEqual(a["receiver_type"], "")

    # 7. fn-filter selector narrows the set
    def test_fn_filter(self):
        m = self._author("codec/Decode", dry_run=True)
        self.assertEqual(m["status"], "ok")
        self.assertTrue(all("Decode" in a["function"] for a in m["authored"]))

    # 8. files written + manifest emitted (non-dry-run)
    def test_write_files(self):
        m = self._author("codec")
        self.assertEqual(m["status"], "ok")
        for a in m["authored"]:
            self.assertTrue((self.pkg / a["harness_file"]).is_file())
            self.assertTrue(a["harness_file"].startswith("auditooor_"))
            self.assertTrue(a["harness_file"].endswith("_engine_test.go"))
        self.assertTrue((self.pkg / "auditooor_harness_manifest.json").is_file())

    # 9. idempotent: re-run -> byte-identical files
    def test_idempotent(self):
        self._author("codec")
        files = sorted(self.pkg.glob("auditooor_*_engine_test.go"))
        first = {f.name: f.read_text() for f in files}
        self._author("codec")
        files2 = sorted(self.pkg.glob("auditooor_*_engine_test.go"))
        second = {f.name: f.read_text() for f in files2}
        self.assertEqual(first, second)

    # 10. generated file carries grounded invariant id + marker + package clause
    def test_grounding_in_content(self):
        m = self._author("codec/Decode")
        a = m["authored"][0]
        txt = (self.pkg / a["harness_file"]).read_text()
        self.assertIn(M.GENERATED_MARKER, txt)
        self.assertIn(a["grounded_invariant"], txt)
        self.assertIn("package codec", txt)
        self.assertIn("import (", txt)

    # 11. --invariant-id restriction
    def test_invariant_id_restriction(self):
        m = self._author("codec/Decode", dry_run=True, invariant_ids={"INV-BND-001"})
        self.assertEqual(m["status"], "ok")
        self.assertTrue(all(a["grounded_invariant"] == "INV-BND-001"
                            for a in m["authored"]))

    # 12. missing package -> blocked
    def test_missing_pkg(self):
        m = self._author("nonexistent-pkg", dry_run=True)
        self.assertEqual(m["status"], "blocked")

    # 13. max-fns cap
    def test_max_fns(self):
        m = self._author("codec", dry_run=True, max_fns=2)
        self.assertLessEqual(m["authored_count"], 2)

    # 14. --no-determinism / --no-roundtrip / --no-idempotence toggles
    def test_toggles(self):
        m = self._author("codec", dry_run=True, want_determinism=False,
                         want_roundtrip=False, want_idempotence=False)
        for a in m["authored"]:
            self.assertTrue(all(p.startswith("Fuzz") and "Prop" not in p
                                for p in a["property_fns"]),
                            f"only no-panic Fuzz expected, got {a['property_fns']}")

    # 15. no go|any invariants -> blocked (no fabrication)
    def test_no_invariants_blocked(self):
        empty = self.root / "emptyrepo"
        (empty / "audit" / "corpus_tags" / "derived").mkdir(parents=True)
        m = M.author(self.ws, "codec", repo_root=empty, dry_run=True)
        self.assertEqual(m["status"], "blocked")
        self.assertIn("no go|any invariants", m["reason"])

    # 16. PROOF-GATE NOTION: every generated property body is REAL (not a no-op)
    #     per the PR4a gate's own tautology primitives.
    def test_proofgate_notion_real_properties(self):
        m = self._author("codec")
        # collect every fuzz/property body and assert non-tautological
        for a in m["authored"]:
            path = self.pkg / a["harness_file"]
            r = GATE.classify_path(path)
            self.assertEqual(
                r["verdict"], GATE.PASS_REAL,
                f"{a['function']} gate={r['verdict']}: {r['reason']}",
            )
            txt = path.read_text()
            # extract each func body via brace matching using the gate primitive
            clean = GATE._strip_comments(txt)
            for fm in re.finditer(r"\bfunc\s+(Fuzz\w+)\s*\(", clean):
                name = fm.group(1)
                brace = clean.find("{", fm.end())
                self.assertNotEqual(brace, -1)
                depth, i = 0, brace
                while i < len(clean):
                    if clean[i] == "{":
                        depth += 1
                    elif clean[i] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                body = clean[brace + 1:i]
                # no neutered `% 1` mutation
                self.assertIsNone(GATE.MOD_BY_ONE_RE.search(body),
                                  f"{name}: neutered % 1 mutation present")
                # no `assert(true)`-style tautology
                self.assertEqual(GATE.TAUTOLOGY_ASSERT_RE.findall(body), [],
                                 f"{name}: tautology assert present")
                # no `x == x` self-equality in an Errorf/if guard
                self.assertNotRegex(
                    body, r"reflect\.DeepEqual\(\s*([A-Za-z_]\w*)\s*,\s*\1\s*\)",
                    f"{name}: self-equality DeepEqual present")
                # body is non-empty and drives the real target (calls a Go fn)
                self.assertTrue(body.strip(), f"{name}: empty property body")
                self.assertIn("beforeState", body, f"{name}: missing before state")
                self.assertIn("afterState", body, f"{name}: missing after state")
                self.assertIn("negativeControlCleanPath", body,
                              f"{name}: missing negative control")
                self.assertRegex(body, r"f\.Fuzz\(func\(t \*testing\.T",
                                 f"{name}: not a real fuzz target")

    # 17. determinism/round-trip/idempotence bodies carry a REAL t.Errorf assertion
    def test_equality_props_have_real_assertion(self):
        m = self._author("codec")
        for a in m["authored"]:
            txt = (self.pkg / a["harness_file"]).read_text()
            for prop in a["property_fns"]:
                if any(k in prop for k in ("Determinism", "RoundTrip", "Idempotence")):
                    # locate the prop body and require a t.Errorf comparison
                    idx = txt.find(f"func {prop}(")
                    self.assertNotEqual(idx, -1)
                    seg = txt[idx:idx + 1400]
                    self.assertIn("t.Errorf", seg,
                                  f"{prop}: missing real t.Errorf assertion")


class TestGoKeeperScaffold(unittest.TestCase):
    """GAP 1: keeper money-mover methods (receiver + sdk.Context/sdk.Coins) must
    NEVER be silently authored 0 - they earn a typed needs-manual-setUp scaffold."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _write_corpus(self.repo)
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.pkg = _write_keeper_pkg(self.ws)

    def tearDown(self):
        self.tmp.cleanup()

    def _author(self, selector, **kw):
        return M.author(self.ws, selector, repo_root=self.repo, **kw)

    # CORE REGRESSION: a receiver method with an sdk.Coins/Context param is NOT a
    # silent 0 - the manifest is `ok` and carries needs-manual-setUp scaffolds.
    def test_keeper_method_not_silent_zero(self):
        m = self._author("feekeeper", dry_run=True)
        self.assertEqual(m["status"], "ok",
                         f"keeper-only pkg must not be blocked/silent-0: {m.get('reason')}")
        self.assertGreaterEqual(m["manual_setup_count"], 2)
        by_fn = {a["function"]: a for a in m["manual_setup"]}
        self.assertIn("deductFee", by_fn)            # unexported money-mover covered
        self.assertIn("ComputeTransferFee", by_fn)   # exported money-mover covered
        for a in m["manual_setup"]:
            self.assertEqual(a["verdict"], "needs-manual-setUp")
            self.assertTrue(a["receiver_type"])
            self.assertTrue(a["setup_params"],
                            f"{a['function']}: no keeper setup-params recorded")
            self.assertTrue(a["scaffold_test"].startswith("TestScaffold_"))

    # a non-keeper scalar method is NOT turned into a keeper scaffold and is not
    # a free-function fuzz author (proves we only route true money-movers).
    def test_plain_scalar_method_not_scaffolded(self):
        m = self._author("feekeeper", dry_run=True)
        scaffolded = {a["function"] for a in m["manual_setup"]}
        authored = {a["function"] for a in m["authored"]}
        self.assertNotIn("PlainScalar", scaffolded)
        self.assertNotIn("PlainScalar", authored)

    # the emitted scaffold FILE is written, compilable-shaped (imports testing,
    # t.Skip verdict, conservation template) and grounded in an invariant.
    def test_keeper_scaffold_file_written(self):
        m = self._author("feekeeper")
        self.assertEqual(m["status"], "ok")
        for a in m["manual_setup"]:
            path = self.pkg / a["harness_file"]
            self.assertTrue(path.is_file())
            self.assertTrue(a["harness_file"].endswith("_keeper_scaffold_test.go"))
            txt = path.read_text()
            self.assertIn("package feekeeper", txt)
            self.assertIn('import "testing"', txt)
            self.assertIn("needs-manual-setUp", txt)
            self.assertIn("t.Skip", txt)
            self.assertIn("conservation", txt.lower())
            self.assertIn(a["grounded_invariant"], txt)

    # toggle off -> keeper methods are not scaffolded (opt-out honored).
    def test_keeper_scaffold_toggle_off(self):
        m = self._author("feekeeper", dry_run=True, want_keeper_scaffold=False)
        self.assertEqual(m.get("manual_setup_count", 0), 0)
        # with no authorable fuzz fns AND no scaffolds -> honest blocked.
        self.assertEqual(m["status"], "blocked")

    # idempotent: re-run -> byte-identical scaffold files.
    def test_keeper_scaffold_idempotent(self):
        self._author("feekeeper")
        first = {f.name: f.read_text()
                 for f in sorted(self.pkg.glob("auditooor_*_keeper_scaffold_test.go"))}
        self._author("feekeeper")
        second = {f.name: f.read_text()
                  for f in sorted(self.pkg.glob("auditooor_*_keeper_scaffold_test.go"))}
        self.assertEqual(first, second)


@unittest.skipIf(shutil.which("go") is None, "go toolchain not installed")
class TestGoEngineHarnessCompiles(unittest.TestCase):
    """End-to-end: author + `go vet` + compile-build the generated package."""

    def test_generated_package_compiles_and_vets(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        repo = root / "repo"
        repo.mkdir()
        _write_corpus(repo)
        ws = root / "ws"
        ws.mkdir()
        pkg = _write_pkg(ws)
        m = M.author(ws, "codec", repo_root=repo)
        self.assertEqual(m["status"], "ok")
        subprocess.run(["go", "mod", "init", "gohauthorsmoke"], cwd=pkg,
                       check=True, capture_output=True)
        vet = subprocess.run(["go", "vet", "./..."], cwd=pkg, capture_output=True, text=True)
        self.assertEqual(vet.returncode, 0, f"go vet failed:\n{vet.stderr}")
        build = subprocess.run(["go", "test", "-run", "^$", "./..."], cwd=pkg,
                               capture_output=True, text=True)
        self.assertEqual(build.returncode, 0, f"compile failed:\n{build.stderr}")


if __name__ == "__main__":
    unittest.main()
