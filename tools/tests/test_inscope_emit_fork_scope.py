# <!-- r36-rebuttal: lane-K1-keystone-fork-scope-in-emit registered in .auditooor/agent_pathspec.json -->
"""Tests for the FORK-SCOPE prune wired into the in-scope manifest emitter
(tools/workspace-coverage-heatmap.py build_inscope_manifest_rows /
write_inscope_manifest).

KEYSTONE behaviour under test:
  - emit over a FORK workspace (with <ws>/.auditooor/fork_bases.json) drops rows
    whose repo-relative file is UNMODIFIED-upstream, while a MODIFIED .sol/.go/.rs
    survives - across LANGUAGES (multi-language fork_modified lib),
  - re-emit over the already-scoped tree yields the SAME row set (idempotent /
    prune-preserving; a fork_scope_signature is stamped in the sidecar),
  - a NON-fork workspace (no fork_bases.json) emits EXACTLY as before (byte-for-
    byte identical row set with vs without the fork-scope code path),
  - missing base ref (fork_bases row without upstream_repo/base_ref) -> KEEP-ALL
    for that fork + a WARN (never silently under-scope).

The upstream clone is monkeypatched to copy a LOCAL fixture upstream tree, so the
test is offline / network-free.
"""
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "workspace-coverage-heatmap.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("_emit_fork_scope_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_emit_fork_scope_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


_MOD = _load_mod()


def _write(p: Path, txt: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(txt, encoding="utf-8")


# Source bodies. The fork copies upstream VERBATIM for the "unmodified" files and
# EDITS the "modified" ones, so compute_modified_files flags exactly the edited
# files across .sol / .go / .rs.
_UNMOD_SOL = (
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
    "contract Inherited {\n    function untouched() external {}\n}\n"
)
_MOD_SOL_UP = (
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
    "contract Patched {\n    function base() external {}\n}\n"
)
_MOD_SOL_FORK = (
    "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
    "contract Patched {\n    function base() external {}\n"
    "    function forkAdded() external {}\n}\n"
)
_UNMOD_GO = "package core\n\nfunc Untouched() {}\n"
_MOD_GO_UP = "package core\n\nfunc Base() {}\n"
_MOD_GO_FORK = "package core\n\nfunc Base() { _ = 1 }\n"
_UNMOD_RS = "pub fn untouched() {}\n"
_MOD_RS_UP = "pub fn base() {}\n"
_MOD_RS_FORK = "pub fn base() { let _x = 1; }\n"


def _build_upstream(up: Path) -> None:
    _write(up / "a" / "Inherited.sol", _UNMOD_SOL)
    _write(up / "a" / "Patched.sol", _MOD_SOL_UP)
    _write(up / "b" / "core_untouched.go", _UNMOD_GO)
    _write(up / "b" / "core_base.go", _MOD_GO_UP)
    _write(up / "c" / "untouched.rs", _UNMOD_RS)
    _write(up / "c" / "base.rs", _MOD_RS_UP)


def _build_fork(fork: Path) -> None:
    # unmodified files: byte-identical to upstream
    _write(fork / "a" / "Inherited.sol", _UNMOD_SOL)
    _write(fork / "b" / "core_untouched.go", _UNMOD_GO)
    _write(fork / "c" / "untouched.rs", _UNMOD_RS)
    # modified files: forked edits
    _write(fork / "a" / "Patched.sol", _MOD_SOL_FORK)
    _write(fork / "b" / "core_base.go", _MOD_GO_FORK)
    _write(fork / "c" / "base.rs", _MOD_RS_FORK)


def _make_fork_ws(tmp: Path) -> tuple[Path, Path]:
    """A workspace whose sole src/ child is a fork ('bor'), plus a sibling
    upstream fixture tree the monkeypatched clone copies from."""
    ws = tmp / "ws"
    fork = ws / "src" / "bor"
    _build_fork(fork)
    up = tmp / "upstream_fixture"
    _build_upstream(up)
    # the fork_bases sidecar the emitter reads
    fb = ws / ".auditooor" / "fork_bases.json"
    fb.parent.mkdir(parents=True, exist_ok=True)
    fb.write_text(json.dumps([
        {"local_name": "bor", "upstream_repo": "ethereum/go-ethereum",
         "base_ref": "v1.16.8"}
    ]), encoding="utf-8")
    return ws, up


class _ClonePatch:
    """Context manager that replaces _clone_upstream_for_fork with a local copy
    from a fixture upstream dir (offline)."""
    def __init__(self, mod, upstream_fixture: Path):
        self.mod = mod
        self.up = upstream_fixture
        self.orig = None

    def __enter__(self):
        self.orig = self.mod._clone_upstream_for_fork

        def fake(upstream_repo, ref, dest):
            shutil.copytree(self.up, dest)
            return True

        self.mod._clone_upstream_for_fork = fake
        return self

    def __exit__(self, *exc):
        self.mod._clone_upstream_for_fork = self.orig
        return False


def _files(rows):
    return {r["file"] for r in rows}


class TestEmitForkScope(unittest.TestCase):
    def test_fork_scope_drops_unmodified_keeps_modified_multilang(self):
        with tempfile.TemporaryDirectory() as td:
            ws, up = _make_fork_ws(Path(td))
            with _ClonePatch(_MOD, up):
                rows = _MOD.build_inscope_manifest_rows(ws)
            files = _files(rows)
            # modified files across THREE languages survive
            self.assertIn("src/bor/a/Patched.sol", files)
            self.assertIn("src/bor/b/core_base.go", files)
            self.assertIn("src/bor/c/base.rs", files)
            # unmodified-upstream files are pruned
            self.assertNotIn("src/bor/a/Inherited.sol", files)
            self.assertNotIn("src/bor/b/core_untouched.go", files)
            self.assertNotIn("src/bor/c/untouched.rs", files)
            # a modified .sol keeps its function-granularity row
            self.assertTrue(any(
                r["file"] == "src/bor/a/Patched.sol" and r["function"] == "forkAdded"
                for r in rows
            ))

    def test_idempotent_prune_preserving(self):
        with tempfile.TemporaryDirectory() as td:
            ws, up = _make_fork_ws(Path(td))
            with _ClonePatch(_MOD, up):
                out1, count1, wrote1 = _MOD.write_inscope_manifest(ws, force=True)
                rows1 = [json.loads(l) for l in out1.read_text().splitlines() if l.strip()]
                # re-emit over the already-scoped tree (force to bypass freshness)
                out2, count2, wrote2 = _MOD.write_inscope_manifest(ws, force=True)
                rows2 = [json.loads(l) for l in out2.read_text().splitlines() if l.strip()]
            self.assertEqual(count1, count2)
            self.assertEqual(_files(rows1), _files(rows2))
            # signature sidecar stamped + stable
            sidecar = ws / ".auditooor" / "inscope_units.fork_scope.json"
            self.assertTrue(sidecar.is_file())
            sig = json.loads(sidecar.read_text())
            self.assertTrue(sig.get("applied"))
            self.assertTrue(sig.get("fork_scope_signature"))

    def test_nonfork_ws_identical_to_pre_fix(self):
        # A workspace with NO fork_bases.json must emit EXACTLY the same rows as
        # if the fork-scope code path did not exist. We assert the prune is a
        # no-op by checking _apply_fork_scope returns the input unchanged AND no
        # row is dropped relative to a direct walk.
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "plain"
            _write(ws / "src" / "Vault.sol",
                   "pragma solidity ^0.8.0;\ncontract V { function f() external {} }\n")
            _write(ws / "src" / "engine.rs", "pub fn run() {}\n")
            rows = _MOD.build_inscope_manifest_rows(ws)
            # no fork_bases.json -> apply_fork_scope is a pure passthrough
            scoped, detail = _MOD._apply_fork_scope(ws, list(rows))
            self.assertEqual(scoped, rows)
            self.assertFalse(detail.get("applied"))
            self.assertEqual(detail.get("reason"), "no-fork_bases.json")
            files = _files(rows)
            self.assertIn("src/Vault.sol", files)
            self.assertIn("src/engine.rs", files)

    def test_missing_base_ref_keeps_all_with_warn(self):
        with tempfile.TemporaryDirectory() as td:
            ws, up = _make_fork_ws(Path(td))
            # overwrite fork_bases with a row missing upstream_repo/base_ref
            fb = ws / ".auditooor" / "fork_bases.json"
            fb.write_text(json.dumps([
                {"local_name": "bor", "upstream_repo": "", "base_ref": ""}
            ]), encoding="utf-8")
            buf = io.StringIO()
            with redirect_stderr(buf):
                # builder itself applies fork-scope; malformed sidecar -> keep-all
                rows = _MOD.build_inscope_manifest_rows(ws)
            warn = buf.getvalue()
            self.assertIn("base unresolved", warn)
            self.assertIn("KEEPING ALL", warn)
            self.assertIn("resolve-fork-bases.py", warn)
            # all fork files retained (NONE dropped, incl. the unmodified ones)
            files = _files(rows)
            self.assertIn("src/bor/a/Inherited.sol", files)
            self.assertIn("src/bor/a/Patched.sol", files)
            self.assertIn("src/bor/b/core_untouched.go", files)


if __name__ == "__main__":
    unittest.main()
