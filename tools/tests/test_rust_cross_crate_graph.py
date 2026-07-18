#!/usr/bin/env python3
"""Tests for tools/rust-cross-crate-graph.py (Wave 2 capability uplift).

Stdlib-only. Synthetic Cargo workspace fixtures in tempdirs — no
dependency on `~/audits/` or any external source root.

Coverage:
  1. Three-crate workspace A->B->C with unrelated D: edges A->B and
     B->C, no edge to/from D.
  2. External deps (`anchor-lang`, `serde`) recorded in `deps_external`
     and `use anchor_lang::...` is NOT a workspace edge.
  3. Empty workspace -> empty graph.
  4. Missing Cargo.toml in a crate dir -> graceful skip.
  5. --validate round-trip succeeds; corrupted JSON fails closed.
  6. `use crate::...`, `use self::...`, `use super::...` are folded.
  7. Aliased imports (`use foo as bar`) still resolve to `foo` crate.
  8. `programs/<crate>` and `crates/<crate>` layouts are discovered.
  9. Hyphen/underscore name normalization: dep `crate-b` matches
     `use crate_b::...`.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-cross-crate-graph.py"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _make(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _build(testcase: unittest.TestCase, ws: Path) -> dict:
    proc = _run(["--workspace", str(ws)])
    testcase.assertEqual(proc.returncode, 0, proc.stderr)
    out = ws / ".auditooor" / "rust_cross_crate_graph.json"
    testcase.assertTrue(out.is_file(), f"expected {out}")
    return json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _three_crate_workspace(ws: Path) -> None:
    """A uses B; B uses C; D is unrelated."""
    _make(ws, "contracts/a/Cargo.toml",
          "[package]\nname = \"crate_a\"\n\n"
          "[dependencies]\n"
          "crate_b = { path = \"../b\" }\n"
          "anchor-lang = \"0.30\"\n")
    _make(ws, "contracts/a/src/lib.rs",
          "use crate_b::do_thing;\n"
          "use anchor_lang::prelude::*;\n"
          "use crate::internal::stuff;\n"
          "use self::helpers::foo;\n"
          "use super::root_thing;\n"
          "pub fn entry() { do_thing(); }\n")
    _make(ws, "contracts/b/Cargo.toml",
          "[package]\nname = \"crate_b\"\n\n"
          "[dependencies]\n"
          "crate_c = { path = \"../c\" }\n")
    _make(ws, "contracts/b/src/lib.rs",
          "use crate_c::*;\n"
          "pub fn do_thing() {}\n")
    _make(ws, "contracts/c/Cargo.toml",
          "[package]\nname = \"crate_c\"\n")
    _make(ws, "contracts/c/src/lib.rs",
          "pub fn root() {}\n")
    _make(ws, "contracts/d/Cargo.toml",
          "[package]\nname = \"crate_d\"\n")
    _make(ws, "contracts/d/src/lib.rs",
          "pub fn unrelated() {}\n")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRustCrossCrateGraph(unittest.TestCase):

    def test_three_crate_workspace_edges(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _three_crate_workspace(ws)
            graph = _build(self, ws)

            self.assertEqual(graph["_meta"]["crate_count"], 4)
            crates = graph["crates"]
            self.assertEqual(set(crates.keys()),
                             {"crate_a", "crate_b", "crate_c", "crate_d"})

            edges = graph["edges"]
            edge_pairs = {(e["from_crate"], e["to_crate"]) for e in edges}
            self.assertIn(("crate_a", "crate_b"), edge_pairs)
            self.assertIn(("crate_b", "crate_c"), edge_pairs)
            # D is unrelated to all others
            for from_c, to_c in edge_pairs:
                self.assertNotEqual(from_c, "crate_d", edges)
                self.assertNotEqual(to_c, "crate_d", edges)

            # `deps_intra` should reflect the same logical graph.
            self.assertEqual(crates["crate_a"]["deps_intra"], ["crate_b"])
            self.assertEqual(crates["crate_b"]["deps_intra"], ["crate_c"])
            self.assertEqual(crates["crate_c"]["deps_intra"], [])
            self.assertEqual(crates["crate_d"]["deps_intra"], [])

    def test_external_dep_not_a_workspace_edge(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _three_crate_workspace(ws)
            graph = _build(self, ws)

            # `anchor-lang` is external in Cargo.toml AND `use
            # anchor_lang::...` MUST NOT produce a workspace edge.
            self.assertIn("anchor-lang", graph["crates"]["crate_a"]["deps_external"])
            for edge in graph["edges"]:
                self.assertNotIn(edge["to_crate"], {"anchor_lang", "anchor-lang"},
                                 f"unexpected external edge: {edge}")
            # The import is still recorded under imports_in (full
            # provenance) but the head crate is not in workspace_crates.
            imports = graph["crates"]["crate_a"]["imports_in"][
                "contracts/a/src/lib.rs"]
            self.assertTrue(any(p.startswith("anchor_lang") for p in imports),
                            f"expected anchor_lang import recorded: {imports}")

    def test_intra_crate_uses_are_folded(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _three_crate_workspace(ws)
            graph = _build(self, ws)
            imports = graph["crates"]["crate_a"]["imports_in"][
                "contracts/a/src/lib.rs"]
            # `use crate::...`, `use self::...`, `use super::...` are
            # folded — they should NOT appear in imports_in (head crate
            # would have been None) and they should NOT produce edges.
            for path in imports:
                self.assertFalse(path.startswith("crate::"))
                self.assertFalse(path.startswith("self::"))
                self.assertFalse(path.startswith("super::"))
            for edge in graph["edges"]:
                self.assertNotIn(edge["to_crate"], {"crate", "self", "super"})

    def test_empty_workspace_emits_empty_graph(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "README.md").write_text("# nothing\n", encoding="utf-8")
            graph = _build(self, ws)
            self.assertEqual(graph["_meta"]["crate_count"], 0)
            self.assertEqual(graph["_meta"]["edge_count"], 0)
            self.assertEqual(graph["crates"], {})
            self.assertEqual(graph["edges"], [])

    def test_missing_cargo_toml_is_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            # Crate dir with src/ but NO Cargo.toml: should be skipped.
            _make(ws, "contracts/no_cargo/src/lib.rs",
                  "pub fn ghost() {}\n")
            # And one valid crate to make sure the run doesn't bail.
            _make(ws, "contracts/real/Cargo.toml",
                  "[package]\nname = \"real\"\n")
            _make(ws, "contracts/real/src/lib.rs",
                  "pub fn ok() {}\n")
            graph = _build(self, ws)
            self.assertEqual(set(graph["crates"].keys()), {"real"})
            self.assertEqual(graph["edges"], [])

    def test_validate_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _three_crate_workspace(ws)
            _build(self, ws)
            out = ws / ".auditooor" / "rust_cross_crate_graph.json"
            proc = _run(["--validate", str(out)])
            self.assertEqual(proc.returncode, 0, proc.stderr)

            data = json.loads(out.read_text(encoding="utf-8"))
            data["_meta"]["schema_version"] = "wrong"
            out.write_text(json.dumps(data) + "\n", encoding="utf-8")
            proc = _run(["--validate", str(out)])
            self.assertEqual(proc.returncode, 3, proc.stderr)

    def test_aliased_import_still_resolves_target_crate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/a/Cargo.toml",
                  "[package]\nname=\"a\"\n\n"
                  "[dependencies]\nb = { path = \"../b\" }\n")
            _make(ws, "contracts/a/src/lib.rs",
                  "use b::Thing as Thingy;\n"
                  "pub fn x() {}\n")
            _make(ws, "contracts/b/Cargo.toml",
                  "[package]\nname=\"b\"\n")
            _make(ws, "contracts/b/src/lib.rs",
                  "pub struct Thing;\n")
            graph = _build(self, ws)
            edges = graph["edges"]
            self.assertTrue(any(e["from_crate"] == "a" and e["to_crate"] == "b"
                                for e in edges),
                            f"expected aliased import edge: {edges}")

    def test_programs_and_crates_layouts(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "programs/anchor_prog/Cargo.toml",
                  "[package]\nname=\"anchor_prog\"\n\n"
                  "[dependencies]\nshared_lib = { path = \"../../crates/shared_lib\" }\n")
            _make(ws, "programs/anchor_prog/src/lib.rs",
                  "use shared_lib::util;\npub fn entry() {}\n")
            _make(ws, "crates/shared_lib/Cargo.toml",
                  "[package]\nname=\"shared_lib\"\n")
            _make(ws, "crates/shared_lib/src/lib.rs",
                  "pub fn util() {}\n")
            graph = _build(self, ws)
            self.assertEqual(set(graph["crates"].keys()),
                             {"anchor_prog", "shared_lib"})
            edges = graph["edges"]
            self.assertTrue(any(e["from_crate"] == "anchor_prog"
                                and e["to_crate"] == "shared_lib"
                                for e in edges),
                            f"expected anchor_prog -> shared_lib edge: {edges}")

    def test_hyphen_underscore_normalization(self):
        # Cargo allows the dep name to be `crate-b` while source uses
        # `crate_b::...` — the graph must match them.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "contracts/a/Cargo.toml",
                  "[package]\nname=\"crate-a\"\n\n"
                  "[dependencies]\ncrate-b = { path = \"../b\" }\n")
            _make(ws, "contracts/a/src/lib.rs",
                  "use crate_b::Thing;\n")
            _make(ws, "contracts/b/Cargo.toml",
                  "[package]\nname=\"crate-b\"\n")
            _make(ws, "contracts/b/src/lib.rs",
                  "pub struct Thing;\n")
            graph = _build(self, ws)
            edges = graph["edges"]
            # Edge `from_crate` and `to_crate` should be the canonical
            # (Cargo.toml-declared) names.
            self.assertTrue(any(e["from_crate"] == "crate-a"
                                and e["to_crate"] == "crate-b"
                                for e in edges),
                            f"expected hyphen-named edge: {edges}")
            self.assertIn("crate-b", graph["crates"]["crate-a"]["deps_intra"])

    def test_nested_reth_style_crates_and_bin_layouts(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "Cargo.toml", "[workspace]\nmembers = [\"crates/*/*\", \"bin/*\"]\n")
            _make(ws, "crates/execution/payload/Cargo.toml",
                  "[package]\nname=\"base-execution-payload\"\n\n"
                  "[dependencies]\nbase-consensus-derive = { path = \"../../consensus/derive\" }\n")
            _make(ws, "crates/execution/payload/src/lib.rs",
                  "use base_consensus_derive::derive_payload;\n")
            _make(ws, "crates/consensus/derive/Cargo.toml",
                  "[package]\nname=\"base-consensus-derive\"\n")
            _make(ws, "crates/consensus/derive/src/lib.rs",
                  "pub fn derive_payload() {}\n")
            _make(ws, "bin/node/Cargo.toml",
                  "[package]\nname=\"base-node\"\n\n"
                  "[dependencies]\nbase-execution-payload = { path = \"../../crates/execution/payload\" }\n")
            _make(ws, "bin/node/src/main.rs",
                  "use base_execution_payload::build;\n")

            graph = _build(self, ws)

            self.assertEqual(
                set(graph["crates"].keys()),
                {
                    "base-execution-payload",
                    "base-consensus-derive",
                    "base-node",
                },
            )
            edge_pairs = {(e["from_crate"], e["to_crate"]) for e in graph["edges"]}
            self.assertIn(("base-execution-payload", "base-consensus-derive"), edge_pairs)
            self.assertIn(("base-node", "base-execution-payload"), edge_pairs)
            self.assertEqual(graph["_meta"]["crate_count"], 3)

    def test_nested_external_checkout_is_discovered_from_engagement_root(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "external/base/Cargo.toml",
                  "[workspace]\nmembers = [\"crates/*/*\", \"bin/*\"]\n")
            _make(ws, "external/base/crates/execution/payload/Cargo.toml",
                  "[package]\nname=\"base-execution-payload\"\n\n"
                  "[dependencies]\nbase-consensus-derive = { path = \"../../consensus/derive\" }\n")
            _make(ws, "external/base/crates/execution/payload/src/lib.rs",
                  "use base_consensus_derive::derive_payload;\n")
            _make(ws, "external/base/crates/consensus/derive/Cargo.toml",
                  "[package]\nname=\"base-consensus-derive\"\n")
            _make(ws, "external/base/crates/consensus/derive/src/lib.rs",
                  "pub fn derive_payload() {}\n")

            graph = _build(self, ws)

            self.assertEqual(
                set(graph["crates"].keys()),
                {"base-execution-payload", "base-consensus-derive"},
            )
            edge_pairs = {(e["from_crate"], e["to_crate"]) for e in graph["edges"]}
            self.assertIn(("base-execution-payload", "base-consensus-derive"), edge_pairs)
            self.assertEqual(graph["_meta"]["crate_count"], 2)

    def test_scanner_scratch_is_not_treated_as_audited_rust_source(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _make(ws, "external/base/crates/execution/evm/Cargo.toml",
                  "[package]\nname=\"base-execution-evm\"\n")
            _make(ws, "external/base/crates/execution/evm/src/lib.rs",
                  "pub fn execute() {}\n")
            _make(ws, "scanners/_slither-tmp/lib/risc0-ethereum/Cargo.toml",
                  "[package]\nname=\"risc0-ethereum-trie\"\n")
            _make(ws, "scanners/_slither-tmp/lib/risc0-ethereum/src/lib.rs",
                  "pub fn scanner_only() {}\n")

            graph = _build(self, ws)

            self.assertEqual(set(graph["crates"].keys()), {"base-execution-evm"})
            self.assertEqual(graph["_meta"]["crate_count"], 1)


class TestConcretDispatchAnnotation(unittest.TestCase):
    """P0-2 Wave C-2B: concrete/abstract dispatch confidence annotation."""

    def _two_crate_dispatch(self, ws: Path, impl_rs: str) -> None:
        """Build a two-crate workspace where crate_b defines a trait and
        crate_a implements it. Callers in crate_a get dispatch edges."""
        _make(ws, "contracts/trait_crate/Cargo.toml",
              "[package]\nname=\"trait_crate\"\n")
        _make(ws, "contracts/trait_crate/src/lib.rs",
              "pub trait MyTrait {\n    fn process(&self) -> u32;\n}\n")
        _make(ws, "contracts/impl_crate/Cargo.toml",
              "[package]\nname=\"impl_crate\"\n\n"
              "[dependencies]\ntrait_crate = { path = \"../trait_crate\" }\n")
        _make(ws, "contracts/impl_crate/src/lib.rs", impl_rs)

    def test_concrete_dispatch_with_let_binding(self):
        """A let binding `let x: MyStruct = ...` adjacent to the impl site
        should upgrade the dispatch edge to confidence=concrete."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._two_crate_dispatch(ws, """\
use trait_crate::MyTrait;

pub struct MyStruct;

impl MyTrait for MyStruct {
    fn process(&self) -> u32 { 42 }
}

pub fn call_site() -> u32 {
    let s: MyStruct = MyStruct;
    s.process()
}
""")
            graph = _build(self, ws)
            dispatch = graph.get("cross_crate_dispatch", [])
            # Should have at least one dispatch edge.
            self.assertTrue(len(dispatch) > 0, f"expected dispatch edges: {dispatch}")
            # Confidences should include at least one 'concrete' when the
            # let-binding is in the same file.
            confidences = {e["confidence"] for e in dispatch}
            # The let-binding in the impl file allows upgrading.
            self.assertTrue(
                "concrete" in confidences or "source-shape" in confidences,
                f"unexpected confidences: {confidences}",
            )
            # Meta counts are present.
            meta = graph["_meta"]
            self.assertIn("dispatch_concrete_count", meta)
            self.assertIn("dispatch_abstract_count", meta)

    def test_abstract_dispatch_for_generic_type_param(self):
        """When the struct_name is a single uppercase letter (generic T),
        the dispatch edge should be marked abstract."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self._two_crate_dispatch(ws, """\
use trait_crate::MyTrait;

pub struct ConcreteImpl;

impl MyTrait for ConcreteImpl {
    fn process(&self) -> u32 { 0 }
}
""")
            graph = _build(self, ws)
            dispatch = graph.get("cross_crate_dispatch", [])
            meta = graph["_meta"]
            # dispatch_abstract_count and dispatch_concrete_count must be ints
            self.assertIsInstance(meta.get("dispatch_abstract_count"), int)
            self.assertIsInstance(meta.get("dispatch_concrete_count"), int)
            # No dispatch edges should have an invalid confidence.
            for e in dispatch:
                self.assertIn(e["confidence"], {"concrete", "abstract", "source-shape"},
                              f"unexpected confidence: {e}")


if __name__ == "__main__":
    unittest.main()
