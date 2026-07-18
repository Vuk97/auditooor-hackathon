#!/usr/bin/env python3
"""Guard tests for tools/cross-language-proof-path.py.

The automated lead -> proof_backed funnel was EVM-monolingual: Go (op-node/cosmos)
and Rust (op-reth/kona/substrate) leads dead-ended as advisory_only with no
runnable confirm/refute. These tests prove:

  1. A Rust lead AND a Go lead each reach a NON-advisory proof status (a
     materialized skeleton / proof-attempted), not advisory_only.
  2. proof_backed is reached ONLY from a REAL observed `cargo test` / `go test`
     PASS of BOTH an exploit test and a negative control (R80). We build real
     fixture projects, run the real toolchain, and assert the verdict.
  3. A real run whose exploit test does NOT reproduce yields `refuted`, not
     proof_backed.
  4. The EVM front-door (evm-0day-proof-pipeline.py) routes a Go/Rust lead to
     this engine instead of erroring out.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent


def _load(modname, relpath):
    spec = importlib.util.spec_from_file_location(modname, TOOLS / relpath)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


clp = _load("cross_language_proof_path", "cross-language-proof-path.py")

HAVE_CARGO = shutil.which("cargo") is not None
HAVE_GO = shutil.which("go") is not None


class TestLanguageDetection(unittest.TestCase):
    def test_family_labels_route(self):
        self.assertEqual(clp.detect_language("rust-cargo-test", []), "rust")
        self.assertEqual(clp.detect_language("forge-rust", []), "rust")
        self.assertEqual(clp.detect_language("cosmos-production", []), "go")
        self.assertEqual(clp.detect_language("go-test", []), "go")
        self.assertEqual(clp.detect_language("foundry", []), "evm")

    def test_source_ref_fallback(self):
        self.assertEqual(
            clp.detect_language("", ["rust/op-reth/crates/payload/src/builder.rs:494"]),
            "rust")
        self.assertEqual(
            clp.detect_language("", ["x/keeper/msg_server.go:20"]), "go")
        self.assertEqual(clp.detect_language("", ["src/Foo.sol:10"]), "evm")

    def test_rust_is_not_solana(self):
        # op-reth .rs without a Solana signal must be rust, not solana.
        self.assertEqual(
            clp.detect_language("", ["rust/op-reth/crates/payload/src/builder.rs"]),
            "rust")
        # actual solana signal stays solana (out of this engine's scope).
        self.assertEqual(
            clp.detect_language("", ["programs/x/src/lib.rs"]) if False else
            clp.detect_language("solana-program-test", []), "solana")


class TestNonAdvisorySkeleton(unittest.TestCase):
    """A Rust lead and a Go lead with NO existing harness must each reach a
    materialized, non-advisory proof status - not advisory_only."""

    def _route(self, family, file_line, td):
        lead = {
            "lead_id": "EQ-test",
            "harness_family": family,
            "source_refs": [file_line],
            "file_line": file_line,
            "rel_path": file_line.split(":")[0],
            "line": None,
            "attack_class": "consensus-divergence",
            "title": "t",
        }
        return clp.route_lead(lead, workspace=None, out_dir=Path(td),
                              do_run=False, harness_file=None)

    def test_rust_lead_reaches_non_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._route("rust-cargo-test",
                            "rust/op-reth/crates/payload/src/builder.rs:494", td)
            self.assertEqual(r["verdict"], "proof-engine-pending-rust")
            self.assertFalse(r["advisory_only"])
            self.assertEqual(r["binding_status"], "skeleton-materialized")
            self.assertTrue(r["skeleton_path"].endswith(".rs"))
            self.assertTrue(Path(r["skeleton_path"]).is_file())
            # honesty: a skeleton is NOT proof_backed.
            self.assertNotEqual(r["verdict"], "proof_backed")

    def test_go_lead_reaches_non_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._route("cosmos-production", "x/keeper/msg_server.go:20", td)
            self.assertEqual(r["verdict"], "proof-engine-pending-go")
            self.assertFalse(r["advisory_only"])
            self.assertEqual(r["binding_status"], "skeleton-materialized")
            # go test files MUST end _test.go
            self.assertTrue(r["skeleton_path"].endswith("_test.go"))
            self.assertTrue(Path(r["skeleton_path"]).is_file())
            self.assertNotEqual(r["verdict"], "proof_backed")


class TestAdjudicationContract(unittest.TestCase):
    """proof_backed requires BOTH exploit + control PASS in a real run."""

    def test_only_both_pass_is_proof_backed(self):
        run = {"ran": True, "timeout": False, "compile_fail": False,
               "exploit_pass": True, "control_pass": True}
        v, _ = clp.adjudicate(run, "rust")
        self.assertEqual(v, "proof_backed")

    def test_exploit_fail_is_refuted(self):
        run = {"ran": True, "timeout": False, "compile_fail": False,
               "exploit_pass": False, "control_pass": True}
        v, _ = clp.adjudicate(run, "go")
        self.assertEqual(v, "refuted")

    def test_control_not_clean(self):
        run = {"ran": True, "timeout": False, "compile_fail": False,
               "exploit_pass": True, "control_pass": False}
        v, _ = clp.adjudicate(run, "rust")
        self.assertEqual(v, "control-not-clean")

    def test_compile_block(self):
        run = {"ran": True, "timeout": False, "compile_fail": True,
               "exploit_pass": False, "control_pass": False}
        v, _ = clp.adjudicate(run, "go")
        self.assertEqual(v, "compile-blocked")

    def test_not_run_never_proof_backed(self):
        v, _ = clp.adjudicate(None, "rust")
        self.assertNotEqual(v, "proof_backed")


# --------------------------------------------------------------------------
# REAL toolchain runs (R80: proof_backed only from an observed real PASS).
# --------------------------------------------------------------------------

def _write_rust_project(root: Path, exploit_ok: bool, control_ok: bool):
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        "[package]\nname = \"auditooor_fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
    (root / "src" / "lib.rs").write_text("pub fn add(a: i64, b: i64) -> i64 { a + b }\n")
    exploit_assert = "assert_eq!(add(2, 2), 4);" if exploit_ok else "assert_eq!(add(2, 2), 5);"
    control_assert = "assert_eq!(add(0, 0), 0);" if control_ok else "assert_eq!(add(0, 0), 1);"
    (root / "src" / "tests.rs").write_text("")
    test_dir = root / "tests"
    test_dir.mkdir()
    test_dir.joinpath("auditooor_cross_lang_proof.rs").write_text(
        "use auditooor_fixture::add;\n"
        f"#[test]\nfn test_exploit_divergence() {{ {exploit_assert} }}\n"
        f"#[test]\nfn test_negative_control_divergence() {{ {control_assert} }}\n")


def _write_go_project(root: Path, exploit_ok: bool, control_ok: bool):
    root.mkdir(parents=True, exist_ok=True)
    (root / "go.mod").write_text("module auditooor_fixture\n\ngo 1.20\n")
    exploit_body = "" if exploit_ok else "t.Fatalf(\"exploit did not reproduce\")"
    control_body = "" if control_ok else "t.Fatalf(\"control not clean\")"
    root.joinpath("auditooor_cross_lang_proof_test.go").write_text(
        "package fixture\n\nimport \"testing\"\n\n"
        f"func TestExploitDivergence(t *testing.T) {{ {exploit_body} }}\n\n"
        f"func TestNegativeControlDivergence(t *testing.T) {{ {control_body} }}\n")


@unittest.skipUnless(HAVE_CARGO, "cargo not installed")
class TestRealCargoRun(unittest.TestCase):
    def test_real_pass_pass_is_proof_backed(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _write_rust_project(proj, exploit_ok=True, control_ok=True)
            run = clp.run_cargo_test(proj, timeout=600)
            self.assertTrue(run.get("ran"), run)
            self.assertFalse(run.get("compile_fail"), run.get("raw_tail"))
            self.assertTrue(run["exploit_pass"], run.get("raw_tail"))
            self.assertTrue(run["control_pass"], run.get("raw_tail"))
            v, _ = clp.adjudicate(run, "rust")
            self.assertEqual(v, "proof_backed")

    def test_real_exploit_fail_is_refuted(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _write_rust_project(proj, exploit_ok=False, control_ok=True)
            run = clp.run_cargo_test(proj, timeout=600)
            self.assertTrue(run.get("ran"), run)
            self.assertFalse(run["exploit_pass"], run.get("raw_tail"))
            v, _ = clp.adjudicate(run, "rust")
            self.assertEqual(v, "refuted")


@unittest.skipUnless(HAVE_GO, "go not installed")
class TestRealGoRun(unittest.TestCase):
    def test_real_pass_pass_is_proof_backed(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _write_go_project(proj, exploit_ok=True, control_ok=True)
            run = clp.run_go_test(proj, timeout=600)
            self.assertTrue(run.get("ran"), run)
            self.assertFalse(run.get("compile_fail"), run.get("raw_tail"))
            self.assertTrue(run["exploit_pass"], run.get("raw_tail"))
            self.assertTrue(run["control_pass"], run.get("raw_tail"))
            v, _ = clp.adjudicate(run, "go")
            self.assertEqual(v, "proof_backed")

    def test_real_exploit_fail_is_refuted(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "proj"
            _write_go_project(proj, exploit_ok=False, control_ok=True)
            run = clp.run_go_test(proj, timeout=600)
            self.assertTrue(run.get("ran"), run)
            self.assertFalse(run["exploit_pass"], run.get("raw_tail"))
            v, _ = clp.adjudicate(run, "go")
            self.assertEqual(v, "refuted")

    def test_end_to_end_route_runs_real_go_harness(self):
        # full route_lead path with a real located harness + real go test run.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            proj = ws / "x"
            _write_go_project(proj, exploit_ok=True, control_ok=True)
            lead = {
                "lead_id": "EQ-e2e", "harness_family": "cosmos-production",
                "source_refs": ["x/keeper/msg_server.go:20"],
                "file_line": "x/keeper/msg_server.go:20", "attack_class": "x", "title": "t",
            }
            r = clp.route_lead(lead, workspace=ws, out_dir=None,
                               do_run=True, harness_file=None)
            self.assertEqual(r["language"], "go")
            self.assertEqual(r["verdict"], "proof_backed", r.get("reason"))
            self.assertFalse(r["advisory_only"])


# --------------------------------------------------------------------------
# REAL exploit-body AUTHORING (the Go/Rust parallel to the EVM
# author_pure_library_proof front-door). A shape-detectable lead with NO
# pre-authored harness must now AUTHOR a real-crate/pkg-importing body, run it,
# and adjudicate - proof_backed ONLY from an observed real PASS + control (R80).
# --------------------------------------------------------------------------

def _write_rust_crate_with_fn(root: Path, crate: str, rel_src: str,
                              fn_body: str) -> str:
    """Create a real cargo crate exposing a `pub fn roundtrip(seed: u64) -> u64`
    whose body is `fn_body`. Returns the cited file_line of the fn."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        f"[package]\nname = \"{crate}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
    # crate root declares the module so `<crate>::<mod>::roundtrip` resolves -
    # exactly how a real crate's src tree is wired.
    mod_ident = Path(rel_src).with_suffix("").name
    (root / "src" / "lib.rs").write_text(f"pub mod {mod_ident};\n")
    src = root / rel_src
    src.parent.mkdir(parents=True, exist_ok=True)
    header = "// crate src\n"
    line_of_fn = header.count("\n") + 1
    src.write_text(header + f"pub fn roundtrip(seed: u64) -> u64 {{\n{fn_body}\n}}\n")
    return f"{src.relative_to(root.parent)}:{line_of_fn + 1}"


def _write_go_pkg_with_fn(mod_root: Path, module: str, pkg_rel: str,
                          fn_body: str) -> str:
    """Create a real go module with a package exposing
    `func Determinize(seed uint64) uint64`. Returns the cited file_line."""
    mod_root.mkdir(parents=True, exist_ok=True)
    (mod_root / "go.mod").write_text(f"module {module}\n\ngo 1.20\n")
    pkg_dir = mod_root / pkg_rel
    pkg_dir.mkdir(parents=True, exist_ok=True)
    src = pkg_dir / "lib.go"
    pkgname = pkg_rel.replace("/", "_").split("/")[-1] if "/" in pkg_rel else pkg_rel
    pkgname = pkg_rel.split("/")[-1]
    text = (f"package {pkgname}\n\n"
            f"func Determinize(seed uint64) uint64 {{\n{fn_body}\n}}\n")
    src.write_text(text)
    line_of_fn = text[:text.index("func Determinize")].count("\n") + 1
    return f"{pkg_rel}/lib.go:{line_of_fn}"


@unittest.skipUnless(HAVE_CARGO, "cargo not installed")
class TestRustRealBodyAuthoring(unittest.TestCase):
    def test_roundtrip_lead_authors_real_crate_body_and_proves(self):
        # Deterministic real fn -> exploit (referential transparency) PASSES and
        # the clean control PASSES -> proof_backed, sourced from a REAL cargo run.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            crate_dir = ws / "real_crate"
            cited = _write_rust_crate_with_fn(
                ws, "real_crate", "src/codec.rs",
                "    seed.rotate_left(7) ^ 0x9E37_79B9")
            lead = {
                "lead_id": "EQ-rust-rt", "harness_family": "rust-cargo-test",
                "source_refs": [cited], "file_line": cited,
                "rel_path": cited.split(":")[0], "line": int(cited.split(":")[1]),
                "attack_class": "round-trip-divergence", "title": "rt",
            }
            r = clp.route_lead(lead, workspace=ws, out_dir=None,
                               do_run=True, harness_file=None)
            self.assertTrue(r.get("authored_real_body"), r)
            self.assertEqual(r["real_target"], "real_crate::codec::roundtrip")
            self.assertEqual(r["verdict"], "proof_backed", r.get("reason"))
            self.assertFalse(r["advisory_only"])
            # honesty: the real run actually observed both passes.
            self.assertTrue(r["test_run"]["exploit_pass"], r["test_run"].get("raw_tail"))
            self.assertTrue(r["test_run"]["control_pass"], r["test_run"].get("raw_tail"))

    def test_nondeterministic_real_fn_is_refuted_not_proof_backed(self):
        # A real fn that is NOT referentially transparent -> exploit FAILS ->
        # refuted. R80: a non-reproducing real run must never be proof_backed.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            # static mut counter makes f(seed) != f(seed) -> determinism violated.
            body = ("    static mut N: u64 = 0;\n"
                    "    unsafe { N = N.wrapping_add(1); seed.wrapping_add(N) }")
            cited = _write_rust_crate_with_fn(ws, "buggy_crate", "src/codec.rs", body)
            lead = {
                "lead_id": "EQ-rust-bug", "harness_family": "rust-cargo-test",
                "source_refs": [cited], "file_line": cited,
                "rel_path": cited.split(":")[0], "line": int(cited.split(":")[1]),
                "attack_class": "round-trip-divergence", "title": "rt",
            }
            r = clp.route_lead(lead, workspace=ws, out_dir=None,
                               do_run=True, harness_file=None)
            self.assertTrue(r.get("authored_real_body"), r)
            self.assertEqual(r["verdict"], "refuted", r.get("reason"))
            self.assertNotEqual(r["verdict"], "proof_backed")

    def test_no_shape_class_falls_through_to_skeleton(self):
        # A non-shape-detectable attack_class on a non-shape fn name -> the author
        # returns None and the honest skeleton path runs (NOT proof_backed).
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "real_crate" / "src").mkdir(parents=True)
            (ws / "real_crate" / "Cargo.toml").write_text(
                "[package]\nname = \"real_crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            (ws / "real_crate" / "src" / "auth.rs").write_text(
                "// hdr\npub fn enforce_role(seed: u64) -> u64 { seed }\n")
            cited = "real_crate/src/auth.rs:2"
            lead = {
                "lead_id": "EQ-rust-noshape", "harness_family": "rust-cargo-test",
                "source_refs": [cited], "file_line": cited,
                "rel_path": cited.split(":")[0], "line": 2,
                "attack_class": "access-control", "title": "ac",
            }
            r = clp.route_lead(lead, workspace=ws, out_dir=Path(td) / "out",
                               do_run=True, harness_file=None)
            # enforce_role -> no shape hint; access-control -> not shape-detectable.
            self.assertEqual(r["verdict"], "proof-engine-pending-rust")
            self.assertNotEqual(r["verdict"], "proof_backed")


@unittest.skipUnless(HAVE_GO, "go not installed")
class TestGoRealBodyAuthoring(unittest.TestCase):
    def test_determinism_lead_authors_real_pkg_body_and_proves(self):
        with tempfile.TemporaryDirectory() as td:
            mod_root = Path(td) / "mod"
            cited = _write_go_pkg_with_fn(
                mod_root, "example.com/realmod", "pkg/codec",
                "    return seed*2654435761 + 0x9E3779B9")
            lead = {
                "lead_id": "EQ-go-det", "harness_family": "go-test",
                "source_refs": [cited], "file_line": cited,
                "rel_path": cited.split(":")[0], "line": int(cited.split(":")[1]),
                "attack_class": "determinism-divergence", "title": "det",
            }
            r = clp.route_lead(lead, workspace=mod_root, out_dir=None,
                               do_run=True, harness_file=None)
            self.assertTrue(r.get("authored_real_body"), r)
            self.assertEqual(r["real_target"], "example.com/realmod/pkg/codec.Determinize")
            self.assertEqual(r["verdict"], "proof_backed", r.get("reason"))
            self.assertFalse(r["advisory_only"])
            self.assertTrue(r["test_run"]["exploit_pass"], r["test_run"].get("raw_tail"))
            self.assertTrue(r["test_run"]["control_pass"], r["test_run"].get("raw_tail"))

    def test_cosmos_protocol_keyed_lead_stays_skeleton(self):
        # R26/R44: a cosmos msg_server/keeper surface must NOT be auto-authored;
        # it stays an honest skeleton + obligation (no faked proof).
        with tempfile.TemporaryDirectory() as td:
            mod_root = Path(td) / "mod"
            cited = _write_go_pkg_with_fn(
                mod_root, "example.com/chain", "x/keeper",
                "    return seed")
            # rename the fn to a keeper-shaped surface via path keyword already
            # present (x/keeper); attack_class names a cosmos msg path.
            lead = {
                "lead_id": "EQ-go-cosmos", "harness_family": "cosmos-production",
                "source_refs": [cited], "file_line": cited,
                "rel_path": cited.split(":")[0], "line": int(cited.split(":")[1]),
                "attack_class": "determinism-divergence",
                "title": "msg_server RunTx path",
            }
            r = clp.route_lead(lead, workspace=mod_root, out_dir=Path(td) / "out",
                               do_run=True, harness_file=None)
            self.assertEqual(r["verdict"], "proof-engine-pending-go")
            self.assertNotEqual(r["verdict"], "proof_backed")
            self.assertEqual(r["binding_status"], "skeleton-materialized")


class TestEvmFrontDoorRoutes(unittest.TestCase):
    """The EVM front-door must ROUTE a Go/Rust lead here, not error out."""

    def test_evm_pipeline_routes_rust_lead(self):
        with tempfile.TemporaryDirectory() as td:
            qpath = Path(td) / "queue.json"
            qpath.write_text(json.dumps({"queue": [{
                "lead_id": "EQ-rust",
                "harness_family": "rust-cargo-test",
                "source_refs": ["rust/op-reth/crates/payload/src/builder.rs:494"],
                "file_line": "rust/op-reth/crates/payload/src/builder.rs:494",
                "attack_class": "consensus-divergence",
            }]}))
            r = subprocess.run(
                [sys.executable, str(TOOLS / "evm-0day-proof-pipeline.py"),
                 "--queue-json", str(qpath), "--lead-id", "EQ-rust",
                 "--no-run", "--json"],
                capture_output=True, text=True, timeout=120)
            data = json.loads(r.stdout)
            # routed to cross-language engine; must NOT be an EVM error about a
            # missing .sol citation.
            self.assertEqual(data.get("schema"), "auditooor.cross_language_proof_path.v1")
            self.assertEqual(data.get("language"), "rust")
            self.assertIn(data.get("verdict"),
                          {"proof-engine-pending-rust", "proof_backed", "refuted",
                           "compile-blocked", "control-not-clean"})

    def test_evm_pipeline_routes_go_lead(self):
        with tempfile.TemporaryDirectory() as td:
            qpath = Path(td) / "queue.json"
            qpath.write_text(json.dumps({"queue": [{
                "lead_id": "EQ-go",
                "harness_family": "cosmos-production",
                "source_refs": ["x/keeper/msg_server.go:20"],
                "file_line": "x/keeper/msg_server.go:20",
                "attack_class": "cosmos",
            }]}))
            r = subprocess.run(
                [sys.executable, str(TOOLS / "evm-0day-proof-pipeline.py"),
                 "--queue-json", str(qpath), "--lead-id", "EQ-go",
                 "--no-run", "--json"],
                capture_output=True, text=True, timeout=120)
            data = json.loads(r.stdout)
            self.assertEqual(data.get("schema"), "auditooor.cross_language_proof_path.v1")
            self.assertEqual(data.get("language"), "go")
            self.assertNotEqual(data.get("verdict"), "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
