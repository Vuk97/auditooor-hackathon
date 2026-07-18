#!/usr/bin/env python3
"""Regression test for the generic vendored-dependency path filter in dataflow.py.

The router drops a def-use path ONLY when BOTH its source and sink files are in
vendored third-party code (node_modules / .cargo / vendor / forge-std / OZ). A
protocol path, or a protocol<->library path, must always be kept. This keeps the
EVM/Rust/Go detector surface on in-scope source instead of compiled dependencies.
Surfaced on near-intents 2026-06-25: 141/467 EVM dataflow paths were library-internal
OZ node_modules noise with no exclusion anywhere in the router.
"""
import importlib.util
import json
import unittest
from pathlib import Path

_THIS = Path(__file__).resolve()
_DATAFLOW = _THIS.parent.parent / "dataflow.py"
_spec = importlib.util.spec_from_file_location("dataflow_under_test", _DATAFLOW)
dataflow = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dataflow)


PROTOCOL = "/ws/src/omni-bridge/contracts/OmniBridge.sol"
OZ_NODE_MODULES = "/ws/src/omni-bridge/evm/node_modules/@openzeppelin/contracts/utils/Address.sol"
OZ_BUILD = "/ws/src/omni-bridge/evm/build/@openzeppelin/contracts/utils/Context.sol"
CARGO = "/home/u/.cargo/registry/src/index.crates.io-abc/serde-1.0/src/lib.rs"
FORGE_STD = "/ws/lib/forge-std/src/Test.sol"
GO_VENDOR = "/ws/vendor/github.com/foo/bar/baz.go"


def _rec(src_file, sink_file, language="solidity", pid="dfp-x"):
    return {
        "schema": "dataflow_path.v1",
        "path_id": pid,
        "language": language,
        "source": {"kind": "param-entrypoint", "fn": "f", "var": "x", "file": src_file, "line": 1},
        "sink": {"kind": "low_level_call", "callee": "call", "fn": "g", "file": sink_file, "line": 2},
        "hops": [],
    }


class VendoredMarkerTest(unittest.TestCase):
    def test_markers_match(self):
        self.assertTrue(dataflow._is_vendored(OZ_NODE_MODULES))
        self.assertTrue(dataflow._is_vendored(OZ_BUILD))
        self.assertTrue(dataflow._is_vendored(CARGO))
        self.assertTrue(dataflow._is_vendored(FORGE_STD))
        self.assertTrue(dataflow._is_vendored(GO_VENDOR))

    def test_protocol_not_vendored(self):
        self.assertFalse(dataflow._is_vendored(PROTOCOL))
        self.assertFalse(dataflow._is_vendored(""))
        self.assertFalse(dataflow._is_vendored("/ws/src/mpc/crates/signer/src/lib.rs"))


class FilterPathsTest(unittest.TestCase):
    def _write(self, tmp, recs):
        p = Path(tmp) / "dataflow_paths.jsonl"
        p.write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
        return p

    def test_drops_both_ends_vendored_only(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            recs = [
                _rec(PROTOCOL, PROTOCOL, pid="keep-protocol"),
                _rec(PROTOCOL, OZ_NODE_MODULES, pid="keep-proto-to-lib"),
                _rec(OZ_NODE_MODULES, PROTOCOL, pid="keep-lib-to-proto"),
                _rec(OZ_NODE_MODULES, OZ_BUILD, pid="drop-lib-internal-1"),
                _rec(CARGO, CARGO, language="rust", pid="drop-lib-internal-2"),
            ]
            p = self._write(tmp, recs)
            dropped = dataflow._filter_vendored_paths(p)
            self.assertEqual(dropped, 2)
            surviving = [json.loads(l)["path_id"] for l in p.read_text().splitlines() if l.strip()]
            self.assertEqual(
                sorted(surviving),
                ["keep-lib-to-proto", "keep-proto-to-lib", "keep-protocol"],
            )

    def test_no_drop_returns_zero_and_preserves(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            recs = [_rec(PROTOCOL, PROTOCOL, pid="a"), _rec(PROTOCOL, OZ_BUILD, pid="b")]
            p = self._write(tmp, recs)
            before = p.read_text()
            self.assertEqual(dataflow._filter_vendored_paths(p), 0)
            self.assertEqual(p.read_text(), before)

    def test_missing_file_is_zero(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                dataflow._filter_vendored_paths(Path(tmp) / "nope.jsonl"), 0)

    def test_unparseable_rows_preserved(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "dataflow_paths.jsonl"
            p.write_text(
                json.dumps(_rec(OZ_BUILD, CARGO, pid="drop")) + "\n"
                + "{not valid json\n"
                + json.dumps(_rec(PROTOCOL, PROTOCOL, pid="keep")) + "\n",
                encoding="utf-8",
            )
            dropped = dataflow._filter_vendored_paths(p)
            self.assertEqual(dropped, 1)
            lines = [l for l in p.read_text().splitlines() if l.strip()]
            self.assertIn("{not valid json", lines)  # preserved verbatim
            self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
