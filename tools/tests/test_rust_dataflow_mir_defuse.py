"""Tests for tools/rust-dataflow.py - native offline Rust DefUsePath backend.

Covers:
  - the tool py_compiles
  - MIR (Tier-1/2) backend recovers a multi-hop (call_depth>=2) backward slice
    from a tainted fn param to a value-moving sink, with confidence semantic-ssa
  - guard analysis is REAL (non-vacuous): the guarded multi-hop chain is
    unguarded:false with a populated guard_nodes list, while the unguarded chain
    is unguarded:true
  - MUTATION-VERIFICATION (R-C): removing the guard from the fixture flips the
    guarded chain to unguarded:true. An assert(true) scaffold cannot do that.
  - every emitted record validates against the SHARED dataflow_schema.py
  - R80 degrade contract: a non-compiling / empty target yields a single
    degraded record (engine=unsupported-or-compile-fail-degrade), not a fake flow

The MIR tests require a working `cargo`/`rustc` toolchain; they skip cleanly when
one is not present so the suite stays green on toolchain-less CI.
"""
from __future__ import annotations

import importlib.util
import json
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
TOOL = REPO_ROOT / "tools" / "rust-dataflow.py"
SCHEMA = REPO_ROOT / "tools" / "dataflow_schema.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "rust_dataflow" / "defuse_fixture"


def _load_schema():
    spec = importlib.util.spec_from_file_location("dataflow_schema", str(SCHEMA))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _have_cargo() -> bool:
    return shutil.which("cargo") is not None and shutil.which("rustc") is not None


def _run_tool(workspace: Path, extra=None):
    cmd = [sys.executable, str(TOOL), "--workspace", str(workspace), "--json"]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return proc


def _read_records(workspace: Path):
    jl = workspace / ".auditooor" / "dataflow_paths.jsonl"
    return [json.loads(l) for l in jl.read_text().splitlines() if l.strip()]


def _cleanup(workspace: Path):
    for d in (".auditooor", "target"):
        shutil.rmtree(workspace / d, ignore_errors=True)
    lock = workspace / "Cargo.lock"
    if lock.exists():
        lock.unlink()


class RustDataflowToolBasics(unittest.TestCase):
    def test_tool_py_compiles(self):
        py_compile.compile(str(TOOL), doraise=True)


@unittest.skipUnless(_have_cargo(), "requires cargo/rustc toolchain")
class RustDataflowMirBackend(unittest.TestCase):
    def setUp(self):
        # Work on a temp COPY so the checked-in fixture src is never mutated and
        # no build artifacts land next to it.
        self.tmp = Path(tempfile.mkdtemp(prefix="rdf-test-"))
        self.ws = self.tmp / "defuse_fixture"
        shutil.copytree(FIXTURE, self.ws)
        self.schema = _load_schema()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mir_recovers_multihop_guarded_and_unguarded(self):
        proc = _run_tool(self.ws, ["--mode", "mir"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["status"], "ok", out)
        self.assertEqual(out["crates"]["defuse_fixture"]["backend"], "mir",
                         f"expected MIR backend, got {out}")
        self.assertGreaterEqual(out["semantic_ssa_paths"], 1)
        self.assertGreaterEqual(out["max_call_depth"], 2,
                                "expected a >=2-hop inter-procedural slice")

        recs = _read_records(self.ws)
        # All MIR records are semantic-ssa, rust, non-degraded.
        for r in recs:
            self.assertEqual(r["language"], "rust")
            self.assertEqual(r["confidence"], "semantic-ssa")
            self.assertFalse(r["degraded"])

        # depth-2 guarded chain: unguarded:false, guard_nodes populated
        guarded = [r for r in recs
                   if r["source"]["fn"] == "entry_guarded" and r["call_depth"] >= 2]
        self.assertTrue(guarded, "no depth>=2 slice from entry_guarded")
        self.assertTrue(all(not r["unguarded"] for r in guarded),
                        "guarded chain should be unguarded:false")
        self.assertTrue(all(r["guard_nodes"] for r in guarded),
                        "guarded chain should carry guard_nodes")

        # depth-2 unguarded chain: unguarded:true, no guards
        unguarded = [r for r in recs
                     if r["source"]["fn"] == "entry_unguarded" and r["call_depth"] >= 2]
        self.assertTrue(unguarded, "no depth>=2 slice from entry_unguarded")
        self.assertTrue(all(r["unguarded"] for r in unguarded),
                        "unguarded chain should be unguarded:true")

        # the sink is the value-moving transfer
        for r in recs:
            self.assertEqual(r["sink"]["callee"], "transfer")

    def test_all_records_validate_against_shared_schema(self):
        proc = _run_tool(self.ws, ["--mode", "mir"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        recs = _read_records(self.ws)
        self.assertTrue(recs)
        for r in recs:
            ok, errs = self.schema.validate(r)
            self.assertTrue(ok, f"record failed schema: {errs}\n{r}")

    def test_mutation_removing_guard_flips_unguarded(self):
        """R-C non-vacuity: deleting the guard flips the guarded chain to
        unguarded:true. assert(true) cannot produce this flip."""
        lib = self.ws / "src" / "lib.rs"
        baseline = lib.read_text()

        # --- baseline: guarded chain is unguarded:false ---
        _cleanup(self.ws)
        proc = _run_tool(self.ws, ["--mode", "mir"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        base_recs = _read_records(self.ws)
        base_guarded = [r for r in base_recs
                        if r["source"]["fn"] == "entry_guarded" and r["call_depth"] >= 2]
        self.assertTrue(base_guarded)
        self.assertTrue(all(not r["unguarded"] for r in base_guarded),
                        "baseline guarded chain must be guarded")

        # --- mutant: remove the guard ---
        mutant = baseline.replace(
            "    if amt > bank.cap {\n        return 0;\n    }\n    pay_guarded(bank, amt)",
            "    pay_guarded(bank, amt)",
        )
        self.assertNotEqual(mutant, baseline, "mutation did not apply")
        lib.write_text(mutant)
        _cleanup(self.ws)
        proc = _run_tool(self.ws, ["--mode", "mir"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        mut_recs = _read_records(self.ws)
        mut_guarded = [r for r in mut_recs
                       if r["source"]["fn"] == "entry_guarded" and r["call_depth"] >= 2]
        self.assertTrue(mut_guarded)
        self.assertTrue(all(r["unguarded"] for r in mut_guarded),
                        "mutant (guard removed) must flip guarded chain to unguarded:true")

        # restore (we operate on a temp copy, but keep the contract explicit)
        lib.write_text(baseline)


def _load_tool():
    """Import rust-dataflow.py as a module (name has a hyphen)."""
    spec = importlib.util.spec_from_file_location("rust_dataflow", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


class RustDataflowCeremonyArm(unittest.TestCase):
    """Ceremony / threshold-sig surface (BitForge/GG20). A crypto crate (tofn,
    gg20, ...) moves no ERC20/Promise value, so the token vocabulary finds 0 sinks
    and rust-dataflow degrades - starving tools/mpc-round-proof-obligation.py. The
    ceremony arm restores a real def-use surface. These are pure-unit (no cargo):
    they exercise the parse + classifier + path-resolution primitives directly."""

    def setUp(self):
        self.m = _load_tool()

    def test_trait_call_terminator_is_captured(self):
        """Fully-qualified trait calls `<T as Trait>::method(` START with `<`.
        Before the fix the callee regex demanded a leading [A-Za-z_], silently
        dropping every trait-method sink (verify_prehashed, try_sign_prehashed,
        <T as Transfer>::transfer). Assert they now parse as call terminators."""
        mir = (
            "fn ecdsa::verify(_1: &[u8; 33], _2: &MessageDigest, _3: &[u8]) -> bool {\n"
            "    // scope 0 at src/ecdsa/mod.rs:94:1: 98:26\n"
            "    debug encoded_verifying_key => _1;\n"
            "    debug encoded_signature => _3;\n"
            "    _19 = <AffinePoint as VerifyPrimitive<Secp256k1>>::verify_prehashed"
            "(move _20, copy _1, copy _3) -> [return: bb15, unwind continue];"
            " // scope 6 at src/ecdsa/mod.rs:103:8: 106:79\n"
            "}\n"
        )
        fns = self.m.parse_mir_text(mir)
        self.assertEqual(len(fns), 1)
        callees = [self.m._last_segment(c["callee"]) for c in fns[0].calls]
        self.assertIn("verify_prehashed", callees,
                      f"trait-method sink not captured: {callees}")

    def test_ceremony_sink_only_fires_for_ceremony_crate(self):
        """A ceremony sink callee is a sink ONLY when ceremony=True. A generic
        crate keeps its exact prior (token/Promise) behavior."""
        callee = "<AffinePoint as VerifyPrimitive>::verify_prehashed"
        self.assertIsNone(self.m._is_value_sink_callee(callee, ceremony=False))
        self.assertEqual(self.m._is_value_sink_callee(callee, ceremony=True),
                         "ceremony:verify_prehashed")
        # token sinks still fire regardless of the ceremony flag (no regression)
        self.assertEqual(self.m._is_value_sink_callee("erc20::transfer", ceremony=False),
                         "value_move:transfer")

    def test_ceremony_crate_detection(self):
        """tofn / gg20 / paillier crates are detected; a plain crate is not."""
        tmp = Path(tempfile.mkdtemp(prefix="rdf-cer-"))
        try:
            cer = tmp / "tofn"
            cer.mkdir()
            (cer / "Cargo.toml").write_text('[package]\nname="tofn"\nversion="1.1.0"\n')
            self.assertTrue(self.m._is_ceremony_crate("tofn", cer))
            plain = tmp / "widget"
            plain.mkdir()
            (plain / "Cargo.toml").write_text('[package]\nname="widget"\nversion="0.1.0"\n')
            self.assertFalse(self.m._is_ceremony_crate("widget", plain))
            # detection also works off the Cargo.toml body (dep on a threshold-sig lib)
            bybody = tmp / "svc"
            bybody.mkdir()
            (bybody / "Cargo.toml").write_text(
                '[package]\nname="svc"\n[dependencies]\ngg20 = "0.1"\n')
            self.assertTrue(self.m._is_ceremony_crate("svc", bybody))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_crate_relative_span_is_rerooted_to_workspace(self):
        """MIR spans are CRATE-relative. When the crate is a subdir of the
        workspace (src/tofn), a bare 'src/ecdsa/mod.rs' must be re-rooted to
        'src/tofn/src/ecdsa/mod.rs' - else the ceremony/scope marker downstream
        consumers key on (e.g. mpc-round-proof-obligation's 'tofn' gate) is lost."""
        ws = Path("/ws")
        crate_root = Path("/ws/src/tofn")
        self.assertEqual(
            self.m._rel_to_ws(ws, crate_root, "src/ecdsa/mod.rs"),
            "src/tofn/src/ecdsa/mod.rs")
        # an already-absolute span under the workspace is just relativized
        self.assertEqual(
            self.m._rel_to_ws(ws, crate_root, "/ws/src/tofn/src/ecdsa/mod.rs"),
            "src/tofn/src/ecdsa/mod.rs")

    def test_ceremony_slice_end_to_end_on_synthetic_mir(self):
        """A synthetic tofn-shaped MIR yields a semantic-ssa ceremony DefUsePath
        from the decoded field param to the verify sink, with a workspace-rooted
        file:line citation - the exact substrate mpc-round-proof needs."""
        mir = (
            "fn ecdsa::verify(_1: &[u8; 33], _2: &MessageDigest, _3: &[u8]) -> bool {\n"
            "    // scope 0 at src/ecdsa/mod.rs:94:1: 98:26\n"
            "    debug encoded_verifying_key => _1;\n"
            "    debug encoded_signature => _3;\n"
            "    _19 = <AffinePoint as VerifyPrimitive<Secp256k1>>::verify_prehashed"
            "(move _20, copy _1, copy _3) -> [return: bb15, unwind continue];"
            " // scope 6 at src/ecdsa/mod.rs:103:8: 106:79\n"
            "}\n"
        )
        fns = self.m.parse_mir_text(mir)
        recs = self.m.mir_slices(Path("/ws"), fns, "tofn", 512,
                                 ceremony=True, crate_root=Path("/ws/src/tofn"))
        self.assertTrue(recs, "ceremony arm produced no rows over synthetic MIR")
        self.assertTrue(all(r["confidence"] == "semantic-ssa" for r in recs))
        self.assertTrue(any(r["sink"]["callee"] == "verify_prehashed" for r in recs))
        self.assertTrue(all(r["sink"]["file"] == "src/tofn/src/ecdsa/mod.rs"
                            for r in recs),
                        "sink file must be workspace-rooted (carry the tofn marker)")
        self.assertTrue(any(r["source"]["var"] == "encoded_verifying_key"
                            for r in recs))
        # every ceremony row still validates against the shared schema
        sch = _load_schema()
        for r in recs:
            ok, errs = sch.validate(r)
            self.assertTrue(ok, f"ceremony row failed schema: {errs}")


class RustDataflowDegradeContract(unittest.TestCase):
    """R80 degrade: a non-compiling / source-less target yields one degraded
    record, never a fabricated semantic flow. Does not require cargo."""

    def test_degrade_on_noncompiling_crate(self):
        tmp = Path(tempfile.mkdtemp(prefix="rdf-degrade-"))
        try:
            crate = tmp / "broken"
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                "[package]\nname=\"broken\"\nversion=\"0.1.0\"\nedition=\"2021\"\n"
                "[lib]\npath=\"src/lib.rs\"\n"
            )
            # syntactically broken Rust: no MIR, and tree-sitter finds no fns/sinks
            (crate / "src" / "lib.rs").write_text("fn @@@ not rust at all ;;;\n")
            proc = _run_tool(crate, ["--mode", "mir"])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["status"], "degraded", out)
            recs = _read_records(crate)
            self.assertEqual(len(recs), 1)
            self.assertTrue(recs[0]["degraded"])
            self.assertEqual(recs[0]["engine"],
                             "unsupported-or-compile-fail-degrade")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
