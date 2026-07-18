#!/usr/bin/env python3
"""test_fork_delta_materialize.py - regression tests for the FORK-DELTA
materialize -> apply -> hand-off pipeline (stdlib-only).

Covers the SEI gap: for a FORK target, unmodified-upstream code is OOS but was
still reaching the per-fn HUNT residual. The fix:

  (1) MATERIALIZE .auditooor/fork_modified/<name>.json once
      (lib.fork_modified.materialize_fork_modified), with a robust upstream
      resolution chain: git-clone -> language-package-cache (go-mod-cache for a
      GO fork) -> unresolved keep-all. Tests use a LOCAL fake upstream dir
      injected as the go-mod-cache module so NO network is needed AND the
      go-mod-cache fallback path is exercised deterministically.
  (2) APPLY the materialized set to the per-fn HUNT residual
      (residual-scope-per-fn.py): unmodified-upstream units DROPPED, Sei
      modified/added units KEPT.
  (3) HAND the fork-delta to hunt agents: per-fn-mimo-batch-gen carries a
      fork_delta_status per fork-target unit.

Completeness-safety: an UNRESOLVED upstream keeps-all + a loud WARN and NEVER
produces a drop-list.
"""
from __future__ import annotations

import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

_TOOLS = pathlib.Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
if str(_TOOLS / "lib") not in sys.path:
    sys.path.insert(0, str(_TOOLS / "lib"))

from lib import fork_modified as fm  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[2]
RESIDUAL_TOOL = REPO / "tools" / "residual-scope-per-fn.py"


def _mk_fork_and_upstream(tmp: pathlib.Path):
    """Build a fork checkout + a matching upstream dir with a KNOWN modified /
    unmodified / added set. Returns (fork_dir, upstream_dir)."""
    up = tmp / "upstream"
    fork = tmp / "fork" / "go-ethereum"
    for d in (up / "core", up / "core" / "rawdb", up / "consensus" / "clique"):
        d.mkdir(parents=True, exist_ok=True)
    for d in (fork / "core", fork / "core" / "rawdb",
              fork / "consensus" / "clique", fork / "sei"):
        d.mkdir(parents=True, exist_ok=True)
    # MODIFIED: state_processor.go (real token change)
    (up / "core" / "state_processor.go").write_text(
        "package core\nfunc Process() int { return 1 }\n")
    (fork / "core" / "state_processor.go").write_text(
        "package core\nfunc Process() int { return 42 }\n")
    # UNMODIFIED: rawdb/accessors.go + clique/clique.go (byte-identical)
    (up / "core" / "rawdb" / "accessors.go").write_text(
        "package rawdb\nfunc Read() {}\n")
    (fork / "core" / "rawdb" / "accessors.go").write_text(
        "package rawdb\nfunc Read() {}\n")
    (up / "consensus" / "clique" / "clique.go").write_text(
        "package clique\nfunc Seal() {}\n")
    (fork / "consensus" / "clique" / "clique.go").write_text(
        "package clique\nfunc Seal() {}\n")
    # ADDED: sei/precompile.go (fork-only)
    (fork / "sei" / "precompile.go").write_text(
        "package sei\nfunc Call() {}\n")
    return fork, up


class MaterializeCoreTest(unittest.TestCase):
    def test_materialize_modified_added_unmodified_split(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            fork, up = _mk_fork_and_upstream(tmp)
            # inject upstream as a resolved dir via the resolver override
            orig = fm.resolve_upstream_dir
            fm.resolve_upstream_dir = lambda *a, **k: (up, "git-clone", None)
            try:
                payload = fm.materialize_fork_modified(
                    fork, "ethereum/go-ethereum", "v1.15.7", lang="go")
            finally:
                fm.resolve_upstream_dir = orig
            self.assertEqual(payload["verdict"], "scoped")
            self.assertIn("core/state_processor.go", payload["sei_modified_files"])
            self.assertNotIn("core/rawdb/accessors.go", payload["sei_modified_files"])
            self.assertNotIn("consensus/clique/clique.go", payload["sei_modified_files"])
            self.assertIn("sei/precompile.go", payload["sei_added_files"])
            # unmodified-upstream count = the two byte-identical files
            self.assertEqual(payload["unmodified_upstream_count"], 2)

    def test_go_mod_cache_fallback_when_git_clone_fails(self):
        # Force git clone to FAIL and point the go-mod-cache resolver at a LOCAL
        # fake module dir. Proves the shallow-clone-safe fallback path.
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            fork, up = _mk_fork_and_upstream(tmp)
            orig_clone = fm._git_clone_upstream
            orig_cache = fm._go_mod_cache_module_dir
            fm._git_clone_upstream = lambda *a, **k: False
            fm._go_mod_cache_module_dir = lambda *a, **k: up
            try:
                up_dir, src, holder = fm.resolve_upstream_dir(
                    "ethereum/go-ethereum", "v1.15.7", lang="go")
            finally:
                fm._git_clone_upstream = orig_clone
                fm._go_mod_cache_module_dir = orig_cache
            self.assertEqual(src, "go-mod-cache")
            self.assertEqual(up_dir, up)
            if holder is not None:
                holder.cleanup()

    def test_unresolved_upstream_keeps_all_and_warns(self):
        # Neither git-clone NOR the package cache resolves -> unresolved + WARN,
        # NO drop-list (completeness-safe keep-all).
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            fork, _up = _mk_fork_and_upstream(tmp)
            orig_clone = fm._git_clone_upstream
            orig_cache = fm._go_mod_cache_module_dir
            fm._git_clone_upstream = lambda *a, **k: False
            fm._go_mod_cache_module_dir = lambda *a, **k: None
            buf = io.StringIO()
            try:
                with redirect_stderr(buf):
                    payload = fm.materialize_fork_modified(
                        fork, "ethereum/go-ethereum", "v1.15.7", lang="go")
            finally:
                fm._git_clone_upstream = orig_clone
                fm._go_mod_cache_module_dir = orig_cache
            self.assertEqual(payload["verdict"], "upstream-unresolved")
            self.assertEqual(payload["upstream_source"], "unresolved")
            self.assertEqual(payload["sei_modified_files"], [])
            self.assertEqual(payload["sei_added_files"], [])
            self.assertIn("UNRESOLVED", buf.getvalue())
            # keep-set is None (keep-all) for an unresolved artifact
            self.assertIsNone(fm.fork_modified_keep_set(payload))

    def test_keep_set_is_modified_union_added(self):
        payload = {
            "verdict": "scoped",
            "sei_modified_files": ["core/state_processor.go"],
            "sei_added_files": ["sei/precompile.go"],
        }
        keep = fm.fork_modified_keep_set(payload)
        self.assertEqual(keep, {"core/state_processor.go", "sei/precompile.go"})


class ResidualApplyTest(unittest.TestCase):
    """The materialized artifact DROPS unmodified-upstream units from the per-fn
    HUNT residual and KEEPS Sei modified/added units (run via the real tool)."""

    def _mk_ws(self, tmp: pathlib.Path, keep_set, verdict="scoped"):
        ws = tmp / "ws"
        (ws / ".auditooor" / "fork_modified").mkdir(parents=True, exist_ok=True)
        art = {
            "schema": "auditooor.fork_modified.v1",
            "local_name": "go-ethereum",
            "verdict": verdict,
            "sei_modified_files": ["core/state_processor.go"],
            "sei_added_files": ["sei/precompile.go"],
        }
        if verdict != "scoped":
            art["sei_modified_files"] = []
            art["sei_added_files"] = []
        (ws / ".auditooor" / "fork_modified" / "go-ethereum.json").write_text(
            json.dumps(art), encoding="utf-8")
        ranked = ws / ".auditooor" / "ranked.jsonl"
        rows = [
            {"file": "src/go-ethereum/core/state_processor.go", "fn": "Process"},   # modified -> keep
            {"file": "src/go-ethereum/sei/precompile.go", "fn": "Call"},            # added -> keep
            {"file": "src/go-ethereum/core/rawdb/accessors.go", "fn": "Read"},      # unmodified -> DROP
            {"file": "src/go-ethereum/consensus/clique/clique.go", "fn": "Seal"},   # unmodified -> DROP
            {"file": "src/sei-chain/x/evm/keeper.go", "fn": "Handle"},              # non-fork -> keep
        ]
        ranked.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return ws, ranked

    def _run(self, ws, ranked, out):
        return subprocess.run(
            [sys.executable, str(RESIDUAL_TOOL),
             "--workspace", str(ws), "--ranked", str(ranked), "--output", str(out)],
            capture_output=True, text=True, timeout=120,
        )

    def _files(self, out: pathlib.Path):
        seen = set()
        for line in out.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            seen.add(json.loads(line)["file"])
        return seen

    def test_unmodified_upstream_dropped_scoped_keeps_sei(self):
        # No coverage-gate sidecar -> keep-full path, BUT fork-OOS still dropped.
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            ws, ranked = self._mk_ws(tmp, {"core/state_processor.go", "sei/precompile.go"})
            out = ws / ".auditooor" / "resid.jsonl"
            rc = self._run(ws, ranked, out)
            self.assertEqual(rc.returncode, 0, rc.stderr)
            files = self._files(out)
            self.assertIn("src/go-ethereum/core/state_processor.go", files)
            self.assertIn("src/go-ethereum/sei/precompile.go", files)
            self.assertIn("src/sei-chain/x/evm/keeper.go", files)
            self.assertNotIn("src/go-ethereum/core/rawdb/accessors.go", files,
                             "unmodified-upstream rawdb must be dropped")
            self.assertNotIn("src/go-ethereum/consensus/clique/clique.go", files,
                             "unmodified-upstream clique must be dropped")

    def test_unresolved_artifact_keeps_all_fork_units(self):
        # verdict != scoped => keep-set None => NO fork drop (completeness-safe).
        with tempfile.TemporaryDirectory() as t:
            tmp = pathlib.Path(t)
            ws, ranked = self._mk_ws(tmp, None, verdict="upstream-unresolved")
            out = ws / ".auditooor" / "resid.jsonl"
            rc = self._run(ws, ranked, out)
            self.assertEqual(rc.returncode, 0, rc.stderr)
            files = self._files(out)
            # ALL rows retained (no drop) because upstream unresolved.
            self.assertIn("src/go-ethereum/core/rawdb/accessors.go", files)
            self.assertIn("src/go-ethereum/consensus/clique/clique.go", files)


class HandOffTest(unittest.TestCase):
    """per-fn-mimo-batch-gen carries a fork_delta_status per fork-target unit."""

    def test_fork_delta_status_for_helper(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "per_fn_mimo_batch_gen", _TOOLS / "per-fn-mimo-batch-gen.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        idx = {"go-ethereum": {"core/state_processor.go", "sei/precompile.go"}}
        # Sei-modified file -> yes
        s = mod.fork_delta_status_for("src/go-ethereum/core/state_processor.go", idx)
        self.assertIsNotNone(s)
        self.assertEqual(s["sei_modified"], "yes")
        self.assertEqual(s["local_name"], "go-ethereum")
        self.assertEqual(s["repo_relative_path"], "core/state_processor.go")
        # unmodified-upstream file -> no
        s2 = mod.fork_delta_status_for("src/go-ethereum/core/rawdb/accessors.go", idx)
        self.assertEqual(s2["sei_modified"], "no")
        # keep-set None (unresolved) -> unresolved
        idx_unres = {"go-ethereum": None}
        s3 = mod.fork_delta_status_for("src/go-ethereum/core/rawdb/accessors.go", idx_unres)
        self.assertEqual(s3["sei_modified"], "unresolved")
        # non-fork file -> None (not a fork-target unit)
        self.assertIsNone(mod.fork_delta_status_for("src/sei-chain/x/evm/keeper.go", idx))


if __name__ == "__main__":
    unittest.main()
