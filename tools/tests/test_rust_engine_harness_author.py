#!/usr/bin/env python3
"""Tests for tools/rust-engine-harness-author.py.

Hermetic: builds a tiny in-tmpdir Rust crate + a tiny invariant corpus, runs the
author, and asserts on the manifest + emitted files. No cargo invocation.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "rust-engine-harness-author.py"
_spec = importlib.util.spec_from_file_location("rust_engine_harness_author", _TOOL)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

# PR4a proof-gate, loaded by file path (hyphenated filename).
_GATE_TOOL = Path(__file__).resolve().parents[1] / "engine-harness-proof-gate.py"
_gspec = importlib.util.spec_from_file_location("engine_harness_proof_gate", _GATE_TOOL)
GATE = importlib.util.module_from_spec(_gspec)
_gspec.loader.exec_module(GATE)


def _write_crate(root: Path, name: str = "demo-crate"):
    cdir = root / name
    (cdir / "src").mkdir(parents=True)
    (cdir / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n')
    (cdir / "src" / "lib.rs").write_text(
        "pub fn deserialize(bytes: &[u8]) -> Result<u64, ()> { Ok(0) }\n"
        "pub fn serialize(&self) -> Vec<u8> { vec![] }\n"
        "pub fn verify(&self, msg: &[u8]) -> Result<(), ()> { Ok(()) }\n"
        "pub fn insert(&mut self, k: u64) {}\n"
        "pub fn advance_nonce(&mut self, n: u64) -> u64 { n + 1 }\n"
        "pub fn transfer(&mut self, a: u64, b: u64) {}\n"
        "pub fn new() -> Self { todo!() }\n"          # skipped
        "fn private_helper() {}\n"                     # not exported -> skipped
        "pub fn add(a: u64, b: u64) -> u64 { a + b }\n"
    )
    return cdir


def _write_corpus(repo_root: Path):
    d = repo_root / "audit" / "corpus_tags" / "derived"
    d.mkdir(parents=True)
    rows = [
        {"invariant_id": "INV-BND-001", "category": "bounds",
         "statement": "Length-prefixed decode MUST reject lengths exceeding the buffer.",
         "target_lang": "rust"},
        {"invariant_id": "INV-AUT-001", "category": "authorization",
         "statement": "A verify entrypoint MUST reject forged signatures.",
         "target_lang": "any"},
        {"invariant_id": "INV-ORD-001", "category": "ordering",
         "statement": "Index inserts MUST run only after validity checks.",
         "target_lang": "rust"},
        {"invariant_id": "INV-CONS-001", "category": "conservation",
         "statement": "Sum of credits minus debits MUST be conserved.",
         "target_lang": "rust"},
        {"invariant_id": "INV-UNI-001", "category": "uniqueness",
         "statement": "A consumed id MUST be rejected on replay.",
         "target_lang": "rust"},
        {"invariant_id": "INV-MON-001", "category": "monotonicity",
         "statement": "A nonce MUST strictly increase on advance.",
         "target_lang": "rust"},
        {"invariant_id": "INV-FRE-001", "category": "freshness",
         "statement": "A stale token MUST be rejected once consumed.",
         "target_lang": "rust"},
        {"invariant_id": "INV-ATM-001", "category": "atomicity",
         "statement": "The effect MUST run only after the check.",
         "target_lang": "rust"},
        {"invariant_id": "INV-DET-001", "category": "determinism",
         "statement": "Same input MUST yield same output.",
         "target_lang": "rust"},
        {"invariant_id": "INV-SND-001", "category": "soundness",
         "statement": "Accepted iff the proof is valid.",
         "target_lang": "rust"},
        # a solidity row that MUST be ignored
        {"invariant_id": "INV-SOL-999", "category": "bounds",
         "statement": "ignored", "target_lang": "solidity"},
    ]
    (d / "invariants_extracted.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")
    (d / "invariants_pilot.jsonl").write_text("")


class TestRustEngineHarnessAuthor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _write_corpus(self.repo)
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.crate = _write_crate(self.ws)

    def tearDown(self):
        self.tmp.cleanup()

    def _author(self, selector, **kw):
        return M.author(self.ws, selector, repo_root=self.repo, **kw)

    # 1. corpus load filters to rust|any only
    def test_load_filters_lang(self):
        invs = M.load_rust_invariants(self.repo)
        ids = {i["invariant_id"] for i in invs}
        self.assertIn("INV-BND-001", ids)
        self.assertIn("INV-AUT-001", ids)
        self.assertNotIn("INV-SOL-999", ids)  # solidity excluded

    # 2. whole-crate author succeeds and skips new()/private_helper
    def test_author_whole_crate(self):
        m = self._author("demo-crate", dry_run=True)
        self.assertEqual(m["status"], "ok")
        fns = {a["function"] for a in m["authored"]}
        self.assertIn("deserialize", fns)
        self.assertIn("verify", fns)
        self.assertNotIn("new", fns)            # skipped accessor
        self.assertNotIn("private_helper", fns)  # not exported

    # 3. category routing: deserialize->property, verify->model-check
    def test_engine_class_routing(self):
        m = self._author("demo-crate", dry_run=True)
        by_fn = {a["function"]: a for a in m["authored"]}
        self.assertEqual(by_fn["deserialize"]["engine_class"], "property")
        self.assertEqual(by_fn["verify"]["engine_class"], "model-check")
        self.assertIn("kani", by_fn["verify"]["engines"])
        self.assertNotIn("kani", by_fn["deserialize"]["engines"])

    # 4. fn filter selector narrows the set
    def test_fn_filter(self):
        m = self._author("demo-crate/verify", dry_run=True)
        self.assertEqual(m["status"], "ok")
        self.assertTrue(all("verif" in a["function"] for a in m["authored"]))

    # 5. files actually written + manifest emitted (non-dry-run)
    def test_write_files(self):
        m = self._author("demo-crate")
        self.assertEqual(m["status"], "ok")
        for a in m["authored"]:
            self.assertTrue((self.crate / a["harness_file"]).is_file())
            # cargo-discoverable: top-level tests/*.rs
            self.assertTrue(a["harness_file"].startswith("tests/auditooor_"))
        self.assertTrue(
            (self.crate / "tests" / "auditooor_harnesses" / "harness_manifest.json").is_file())

    # 6. idempotent: re-run -> byte-identical files
    def test_idempotent(self):
        self._author("demo-crate")
        files = sorted((self.crate / "tests").glob("*.rs"))
        first = {f.name: f.read_text() for f in files}
        self._author("demo-crate")
        files2 = sorted((self.crate / "tests").glob("*.rs"))
        second = {f.name: f.read_text() for f in files2}
        self.assertEqual(first, second)

    # 7. generated file carries the grounded invariant id + marker
    def test_grounding_in_content(self):
        m = self._author("demo-crate/verify")
        a = m["authored"][0]
        txt = (self.crate / a["harness_file"]).read_text()
        self.assertIn(M.GENERATED_MARKER, txt)
        self.assertIn(a["grounded_invariant"], txt)
        # bolero target gated behind cfg so plain cargo test compiles
        self.assertIn("#[cfg(bolero)]", txt)

    # 8. multi-line signature collapsed to one comment line (no raw newline leak)
    def test_multiline_signature_collapsed(self):
        fn = {"function_name": "verify", "file_path": "src/round2.rs",
              "line_start": 64,
              "function_signature": "pub fn verify(\n    &self,\n    x: u64,\n) -> Result<(), ()>"}
        inv = {"invariant_id": "INV-AUT-001", "category": "authorization",
               "statement": "x"}
        block = M._doc_block(fn, inv, "kani")
        sig_lines = [l for l in block if l.startswith("// signature:")]
        self.assertEqual(len(sig_lines), 1)
        self.assertNotIn("\n", sig_lines[0].replace("\\n", ""))
        self.assertIn("&self, x: u64", sig_lines[0])

    # 9. --invariant-id restriction
    def test_invariant_id_restriction(self):
        m = self._author("demo-crate/verify", dry_run=True,
                         invariant_ids={"INV-AUT-001"})
        self.assertEqual(m["status"], "ok")
        self.assertTrue(all(a["grounded_invariant"] == "INV-AUT-001"
                            for a in m["authored"]))

    # 10. missing crate -> blocked
    def test_missing_crate(self):
        m = self._author("nonexistent-crate", dry_run=True)
        self.assertEqual(m["status"], "blocked")

    # 11. max-fns cap
    def test_max_fns(self):
        m = self._author("demo-crate", dry_run=True, max_fns=2)
        self.assertLessEqual(m["authored_count"], 2)

    # 12. no-kani toggle drops kani from model-check fns
    def test_no_kani(self):
        m = self._author("demo-crate/verify", dry_run=True, want_kani=False)
        for a in m["authored"]:
            self.assertNotIn("kani", a["engines"])

    # 13. manifest schema version + runner filter present
    def test_manifest_schema(self):
        m = self._author("demo-crate/verify", dry_run=True)
        self.assertEqual(m["schema_version"], M.SCHEMA_VERSION)
        self.assertEqual(m["runner_filter"], M.AUTHORED_FN_PREFIX)
        self.assertIn("--target-kind tests", m["proptest_command"])

    # 14. EVERY authored harness file PASSES the engine-harness proof-gate
    #     (no assert(true) / ghost / %1 - real properties only). This is the
    #     load-bearing PR5b assertion.
    def test_all_harnesses_pass_proof_gate(self):
        m = self._author("demo-crate")
        self.assertEqual(m["status"], "ok")
        self.assertGreaterEqual(m["authored_count"], 6)
        for a in m["authored"]:
            path = self.crate / a["harness_file"]
            txt = path.read_text()
            self.assertIn("beforeState", txt)
            self.assertIn("afterState", txt)
            self.assertIn("negative_control_cleanPath", txt)
            self.assertIn(f"{a['function']}(", txt)
            r = GATE.classify_path(path)
            self.assertEqual(
                r["verdict"], GATE.PASS_REAL,
                msg=f"{a['function']} ({a['grounded_invariant']}) gate={r['verdict']}: {r['reason']}")
        # the whole tests/ dir also passes (worst-verdict-wins == pass)
        agg = GATE.classify_path(self.crate / "tests")
        self.assertEqual(agg["verdict"], GATE.PASS_REAL, msg=agg["reason"])

    # 15. proptest dev-dep injected into Cargo.toml when proptest harnesses are authored
    def test_proptest_dep_injected(self):
        """After a non-dry-run author, Cargo.toml MUST declare proptest under
        [dev-dependencies] so `cargo test` compiles without E0433."""
        m = self._author("demo-crate")
        self.assertEqual(m["status"], "ok")
        # At least one proptest harness should have been authored.
        self.assertTrue(any("proptest" in a["engines"] for a in m["authored"]),
                        "expected at least one proptest harness to be authored")
        # The Cargo.toml in the crate must now carry proptest.
        cargo_text = (self.crate / "Cargo.toml").read_text()
        import re as _re
        self.assertTrue(
            _re.search(r'^\s*proptest\s*=', cargo_text, _re.MULTILINE),
            "proptest not found in [dev-dependencies] after author():\n" + cargo_text)
        # Manifest flag is set.
        self.assertTrue(m.get("proptest_dep_injected"),
                        "manifest 'proptest_dep_injected' should be True")

    # 15b. idempotent: second author() does not duplicate proptest entry
    def test_proptest_dep_injected_idempotent(self):
        self._author("demo-crate")
        self._author("demo-crate")
        cargo_text = (self.crate / "Cargo.toml").read_text()
        import re as _re
        matches = _re.findall(r'^\s*proptest\s*=', cargo_text, _re.MULTILINE)
        self.assertEqual(len(matches), 1, "proptest entry duplicated on second run")

    # 15c. dry-run does NOT modify Cargo.toml
    def test_dry_run_no_cargo_modification(self):
        original = (self.crate / "Cargo.toml").read_text()
        self._author("demo-crate", dry_run=True)
        after = (self.crate / "Cargo.toml").read_text()
        self.assertEqual(original, after, "dry-run must not modify Cargo.toml")

    # 15d. virtual workspace manifest is NOT modified (cargo rejects dev-deps there)
    def test_virtual_manifest_not_modified(self):
        """A [workspace]-only Cargo.toml with no [package] must be skipped.
        Injecting into a virtual manifest causes a hard cargo parse error:
        'this virtual manifest specifies a dev-dependencies section, which is not allowed'
        """
        virtual = self.root / "virtual_ws" / "Cargo.toml"
        virtual.parent.mkdir(parents=True, exist_ok=True)
        virtual_text = '[workspace]\nmembers = []\nresolver = "2"\n'
        virtual.write_text(virtual_text)
        result = M._inject_proptest_dev_dep(virtual.parent)
        self.assertFalse(result, "virtual manifest must not be modified")
        self.assertEqual(virtual.read_text(), virtual_text,
                         "virtual manifest content must be unchanged")

    # original test 15 (renumbered 16 in comments but kept in sequence)
    # 16. authored bodies contain NO tautology / ghost / %1 anti-patterns
    def test_no_stub_antipatterns_in_bodies(self):
        m = self._author("demo-crate")
        for a in m["authored"]:
            txt = (self.crate / a["harness_file"]).read_text()
            self.assertNotIn("assert!(true", txt)
            self.assertNotIn("prop_assert!(true", txt)
            self.assertNotIn("TODO: prove", txt)
            self.assertNotIn("TODO: property", txt)
            self.assertNotRegex(txt, r"%\s*1\b(?!\d)")
            # ghost self-equality: assert_eq!(x, x) with identical operand
            self.assertNotRegex(
                txt, r"assert_eq!\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\1\s*[,)]")

    # 16. every invariant category routes to a real, distinct predicate relation
    def test_category_predicates_real(self):
        for cat, needle in [
            ("uniqueness", "first_accept && !second_accept"),
            ("freshness", "first_accept && !second_accept"),
            ("monotonicity", "next > prev"),
            ("conservation", "assert_eq!(total_before, total_after"),
            ("bounds", "decoded_len <= buf_len"),
            ("ordering", "!committed || validated"),
            ("atomicity", "!committed || validated"),
            ("authorization", "authorized, presented == expected"),
            ("determinism", "assert_eq!(out_a, out_b"),
            ("soundness", "assert_eq!(out_a, out_b"),
        ]:
            inv = {"invariant_id": f"INV-{cat[:3].upper()}-X",
                   "category": cat, "statement": "s"}
            lines = "\n".join(M._predicate_lines("targetfn", inv))
            self.assertIn(needle, lines, msg=f"category {cat} predicate missing {needle!r}")
            # the predicate is non-tautological per the gate's own classifier
            body = "\n".join(M._predicate_lines("targetfn", inv))
            self.assertFalse(
                GATE._is_tautological_body(body),
                msg=f"category {cat} predicate body flagged tautological")


if __name__ == "__main__":
    unittest.main(verbosity=2)
