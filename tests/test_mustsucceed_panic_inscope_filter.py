"""Regression: the go-mustsucceed-panic-reachability consumer must FILTER the
panic substrate's sink.file to the in-scope source tree before counting a node as
an attacker-tainted panic node.

Context (axelar-dlt, 2026-07-14): the owned go-dataflow `-panic-sinks` arm emits
~134,876 panic records, but ~87% are stdlib / dependency-declaration noise
(methodsOf / exportedTypeHack over the whole SSA closure). Only ~17,738 land in
the fork's own source tree. Without an in-scope filter the consumer would either
drown the reachability set in `archive/tar` / `internal/sync` panics or, because
those out-of-tree files carry paths under `/pkg/mod`, mis-attribute a halt to code
the protocol never authored. `_in_scope_file` is that filter; this locks its
contract:

  IN  : a file under the workspace root that is not vendored/codegen/test.
  OUT : anything under /pkg/mod, /go/pkg, /vendor, /node_modules; any .pb.go /
        .gen.go codegen; any path that does not live under the ws root; test/mock.
  REL : a module-relative sink.file is anchored to the ws root (not the CWD) so an
        in-scope node is not silently dropped.

It also exercises build() end-to-end on a tiny synthetic substrate to prove the
filter is what gates the panic_nodes set (in-scope kept, /pkg/mod dropped).
"""
import importlib.util
import json
import pathlib
import tempfile
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"


def _load_module():
    # hyphenated filename -> load by path.
    path = _TOOLS / "go-mustsucceed-panic-reachability.py"
    spec = importlib.util.spec_from_file_location("go_mustsucceed_panic", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_M = _load_module()


class InScopeFileFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws = pathlib.Path(self.tmp).resolve()
        (self.ws / "src" / "axelar-core" / "x" / "nexus" / "keeper").mkdir(
            parents=True, exist_ok=True)
        # a real in-scope source file must physically exist so .resolve() succeeds.
        self.inscope = (self.ws / "src" / "axelar-core" / "x" / "nexus"
                        / "keeper" / "chain.go")
        self.inscope.write_text("package keeper\n")

    def _f(self, fpath, include_oos=False):
        return _M._in_scope_file(fpath, self.ws, include_oos)

    def test_inscope_source_kept(self):
        self.assertTrue(self._f(str(self.inscope)),
                        "an in-scope fork source file must pass the filter")

    def test_empty_path_dropped(self):
        # stdlib panic records commonly carry sink.file == None/"".
        self.assertFalse(self._f(""))
        self.assertFalse(self._f(None))

    def test_pkg_mod_dependency_dropped(self):
        # the dominant noise class: a panic inside a module-cache dependency.
        self.assertFalse(self._f(
            "/Users/x/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.0/"
            "src/internal/sync/hashtriemap.go"),
            "a /pkg/mod dependency panic is not an in-scope obligation")

    def test_vendor_and_node_modules_dropped(self):
        self.assertFalse(self._f("/some/proj/vendor/foo/bar.go"))
        self.assertFalse(self._f("/some/proj/node_modules/foo/bar.js"))

    def test_codegen_dropped_even_if_in_ws(self):
        # .pb.go protobuf codegen lives IN the ws src tree but is not authored.
        pb = (self.ws / "src" / "axelar-core" / "x" / "nexus" / "keeper"
              / "query.pb.go")
        pb.write_text("package keeper\n")
        self.assertFalse(self._f(str(pb)),
                         "protobuf .pb.go codegen must be excluded")

    def test_outside_ws_dropped(self):
        # an absolute path that is NOT under the ws root (e.g. another checkout).
        with tempfile.TemporaryDirectory() as other:
            outside = pathlib.Path(other) / "elsewhere.go"
            outside.write_text("package x\n")
            self.assertFalse(self._f(str(outside)),
                             "a source file outside the ws root is out of scope")

    def test_relative_path_anchored_to_ws_not_cwd(self):
        # a module-relative sink.file must be resolved against the ws root, not the
        # process CWD, or an in-scope node is silently starved.
        rel = "src/axelar-core/x/nexus/keeper/chain.go"
        self.assertTrue(self._f(rel),
                        "a relative in-scope path must be anchored to the ws root")

    def test_test_and_mock_files_dropped(self):
        t = (self.ws / "src" / "axelar-core" / "x" / "nexus" / "keeper"
             / "chain_test.go")
        t.write_text("package keeper\n")
        self.assertFalse(self._f(str(t)),
                         "_test.go is out of scope via the shared OOS guard")


class BuildGatesOnInScopeFilter(unittest.TestCase):
    """build() must only count panic nodes whose sink.file survives the filter."""

    def _run_build(self, records):
        tmp = tempfile.mkdtemp()
        ws = pathlib.Path(tmp).resolve()
        src = ws / "src" / "axelar-core" / "x" / "nexus" / "keeper"
        src.mkdir(parents=True, exist_ok=True)
        inscope = src / "chain.go"
        inscope.write_text("package keeper\n")
        df = ws / ".auditooor"
        df.mkdir(parents=True, exist_ok=True)
        p = df / "dataflow_paths.jsonl"
        # materialize the in-scope path into the records that reference it.
        with p.open("w") as fh:
            for r in records:
                r = json.loads(json.dumps(r).replace("__INSCOPE__", str(inscope)))
                fh.write(json.dumps(r) + "\n")
        edges, panic_nodes, roots, warnings, n = _M.build(
            [p], ws, include_oos=False)
        return edges, panic_nodes, roots, warnings, n

    def test_only_inscope_panic_nodes_counted(self):
        records = [
            # in-scope attacker-tainted panic node -> counted.
            {"language": "go",
             "source": {"kind": "param", "fn": "EndBlocker", "var": "req"},
             "sink": {"kind": "panic", "panic_op": "nil-deref",
                      "fn": "(*x).SetChainMaintainerState",
                      "file": "__INSCOPE__", "line": 176}},
            # /pkg/mod dependency panic node -> dropped by the filter.
            {"language": "go",
             "source": {"kind": "param", "fn": "String", "var": "f"},
             "sink": {"kind": "panic", "panic_op": "nil-deref",
                      "fn": "(*archive/tar.Format).String",
                      "file": "/u/go/pkg/mod/std/archive/tar/format.go",
                      "line": 10}},
            # in-scope but not attacker-tainted (source.kind != param) -> dropped.
            {"language": "go",
             "source": {"kind": "const", "fn": "EndBlocker", "var": "c"},
             "sink": {"kind": "panic", "panic_op": "index",
                      "fn": "(*x).Foo", "file": "__INSCOPE__", "line": 200}},
        ]
        edges, panic_nodes, roots, warnings, n = self._run_build(records)
        self.assertEqual(len(panic_nodes), 1,
                         "exactly the one in-scope, param-tainted panic node counts")
        (key, node), = panic_nodes.items()
        self.assertTrue(key[1].endswith("chain.go"))
        self.assertEqual(node.op, "nil-deref")

    def test_all_out_of_scope_yields_zero_nodes(self):
        records = [
            {"language": "go",
             "source": {"kind": "param", "fn": "String", "var": "f"},
             "sink": {"kind": "panic", "panic_op": "nil-deref",
                      "fn": "(*archive/tar.Format).String",
                      "file": "/u/go/pkg/mod/std/archive/tar/format.go",
                      "line": 10}},
        ]
        _, panic_nodes, _, _, _ = self._run_build(records)
        self.assertEqual(len(panic_nodes), 0,
                         "a substrate of only /pkg/mod panics yields 0 in-scope "
                         "panic nodes (not a false halt)")


if __name__ == "__main__":
    unittest.main()
