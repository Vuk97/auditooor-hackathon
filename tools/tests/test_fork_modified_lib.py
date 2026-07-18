#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/tests/test_fork_modified_lib.py - the fork-modified-files-scope core is
now an importable library (lib.fork_modified) so the step-1 manifest emitter can
call it in-process, AND scope_exclusion.is_oos treats a Go ``cmd/`` operator-only
CLI entrypoint as non-production (it leaked into scope before).
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

_TOOLS = pathlib.Path(__file__).resolve().parent.parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from lib import fork_modified as fm  # noqa: E402
from lib import scope_exclusion as se  # noqa: E402


class ForkModifiedLibTest(unittest.TestCase):
    def test_lib_exposes_core_callables(self):
        # The keystone prerequisite: the core is importable as lib.fork_modified.
        for name in (
            "compute_modified_files",
            "filter_manifest",
            "_normalized_content_hash",
            "_go_files",
        ):
            self.assertTrue(callable(getattr(fm, name)), f"lib missing {name}")

    def test_compute_modified_files_via_lib(self):
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "core").mkdir(parents=True)
            (up / "core" / "vm.go").write_text("package core\nfunc A() int { return 1 }\n")
            (fork / "core" / "vm.go").write_text("package core\nfunc A() int { return 2 }\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertIn("core/vm.go", mod)

    def test_whitespace_only_diff_not_modified_via_lib(self):
        # CRLF + trailing spaces + blank-line insertion is NOT a semantic change.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "rlp").mkdir(parents=True)
            (up / "rlp" / "decode.go").write_bytes(b"package rlp\nfunc A() {}\n")
            (fork / "rlp" / "decode.go").write_bytes(
                b"package rlp\r\n\r\nfunc A() {}   \r\n\r\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertNotIn("rlp/decode.go", mod,
                             "whitespace-only diff must NOT count as modified")

    # ---- multi-language generalization (LG1) --------------------------------
    def test_modified_solidity_detected_whitespace_only_not(self):
        # A Solidity fork: a real .sol token change IS modified; a whitespace-only
        # .sol change is NOT. Proves the diff is no longer Go-only.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "contracts").mkdir(parents=True)
            # real token change -> modified
            (up / "contracts" / "Vault.sol").write_text(
                "// SPDX\ncontract Vault { uint x = 1; }\n")
            (fork / "contracts" / "Vault.sol").write_text(
                "// SPDX\ncontract Vault { uint x = 2; }\n")
            # whitespace/blank-line-only change -> NOT modified
            (up / "contracts" / "Token.sol").write_bytes(
                b"contract Token {}\n")
            (fork / "contracts" / "Token.sol").write_bytes(
                b"contract Token {}   \r\n\r\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertIn("contracts/Vault.sol", mod,
                          "a real .sol token change must be detected")
            self.assertNotIn("contracts/Token.sol", mod,
                             "whitespace-only .sol diff must NOT count as modified")

    def test_modified_rust_detected(self):
        # A Rust fork: an added/changed .rs file is detected.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "src").mkdir(parents=True)
            (up / "src" / "lib.rs").write_text("fn a() -> u8 { 1 }\n")
            (fork / "src" / "lib.rs").write_text("fn a() -> u8 { 2 }\n")
            # fork-only added module
            (fork / "src" / "exploit.rs").write_text("pub fn drain() {}\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertIn("src/lib.rs", mod, "a real .rs change must be detected")
            self.assertIn("src/exploit.rs", mod, "a fork-added .rs must be detected")

    def test_unknown_extension_only_fork_zero_modified(self):
        # A fork containing ONLY files of an extension outside the source set
        # yields 0 modified -> the caller (filter_manifest None / CLI keep-all)
        # path. compute_modified_files itself just reports the empty diff.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "data").mkdir(parents=True)
            (up / "data" / "blob.xyz").write_text("alpha\n")
            (fork / "data" / "blob.xyz").write_text("beta-changed\n")
            (fork / "data" / "added.zzz").write_text("new\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertEqual(mod, set(),
                             "unknown-extension-only fork must yield 0 modified")

    def test_narrow_extension_set_honored(self):
        # A caller may pass a narrower set (e.g. workspace-detected langs); a .go
        # change is then ignored when only {.sol} is requested.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "core").mkdir(parents=True)
            (up / "core" / "vm.go").write_text("package core\nfunc A() {}\n")
            (fork / "core" / "vm.go").write_text("package core\nfunc B() {}\n")
            (up / "core" / "Vault.sol").write_text("contract V { uint x = 1; }\n")
            (fork / "core" / "Vault.sol").write_text("contract V { uint x = 2; }\n")
            mod_sol_only = fm.compute_modified_files(fork, up, extensions={".sol"})
            self.assertIn("core/Vault.sol", mod_sol_only)
            self.assertNotIn("core/vm.go", mod_sol_only,
                             ".go must be ignored when only .sol requested")

    def test_per_language_test_files_skipped(self):
        # Per-language test patterns are skipped from the diff surface; a real
        # non-test sibling change in the same fork is still detected.
        with tempfile.TemporaryDirectory() as tmp:
            up = pathlib.Path(tmp) / "up"
            fork = pathlib.Path(tmp) / "fork"
            for d in (up, fork):
                (d / "contracts").mkdir(parents=True)
                (d / "src").mkdir(parents=True)
            # Foundry test (*.t.sol) - changed but must be SKIPPED
            (up / "contracts" / "Vault.t.sol").write_text("contract T { uint a = 1; }\n")
            (fork / "contracts" / "Vault.t.sol").write_text("contract T { uint a = 9; }\n")
            # Rust test (*_test.rs) - changed but must be SKIPPED
            (up / "src" / "mod_test.rs").write_text("fn t() -> u8 { 1 }\n")
            (fork / "src" / "mod_test.rs").write_text("fn t() -> u8 { 9 }\n")
            # real production change - kept
            (up / "contracts" / "Vault.sol").write_text("contract V { uint x = 1; }\n")
            (fork / "contracts" / "Vault.sol").write_text("contract V { uint x = 2; }\n")
            mod = fm.compute_modified_files(fork, up)
            self.assertIn("contracts/Vault.sol", mod)
            self.assertNotIn("contracts/Vault.t.sol", mod,
                             "*.t.sol foundry test must be skipped")
            self.assertNotIn("src/mod_test.rs", mod,
                             "*_test.rs must be skipped")

    def test_default_set_includes_go_backcompat(self):
        # The default extension set must include .go so historical Go forks are
        # diffed byte-for-byte as before (back-compat anchor).
        self.assertIn(".go", fm.DEFAULT_SOURCE_EXTENSIONS)
        # the broad set must also cover the major audited languages
        for ext in (".sol", ".rs", ".move", ".cairo", ".vy", ".huff", ".ts"):
            self.assertIn(ext, fm.DEFAULT_SOURCE_EXTENSIONS, f"missing {ext}")

    def test_source_files_and_go_files_shim_agree_on_go(self):
        # The back-compat _go_files shim must produce the same map as
        # _source_files restricted to {.go}.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "core").mkdir(parents=True)
            (root / "core" / "vm.go").write_text("package core\nfunc A() {}\n")
            (root / "core" / "vm_test.go").write_text("package core\nfunc T() {}\n")
            (root / "core" / "Vault.sol").write_text("contract V {}\n")
            shim = fm._go_files(root, skip_tests=True)
            direct = fm._source_files(root, extensions={".go"}, skip_tests=True)
            self.assertEqual(shim, direct)
            self.assertIn("core/vm.go", shim)
            self.assertNotIn("core/vm_test.go", shim, "_test.go must be skipped")
            self.assertNotIn("core/Vault.sol", shim, ".sol excluded from go-only")

    def test_filter_manifest_via_lib(self):
        with tempfile.TemporaryDirectory() as tmp:
            mani = pathlib.Path(tmp) / "inscope_units.jsonl"
            rows = [
                {"file": "src/bor/core/vm.go", "lang": "go"},
                {"file": "src/bor/core/chain.go", "lang": "go"},
                {"file": "src/other/X.sol", "lang": "solidity"},
            ]
            mani.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
            out = pathlib.Path(tmp) / "scoped.jsonl"
            stats = fm.filter_manifest(mani, out, "bor", {"core/vm.go"})
            self.assertEqual(stats["kept_in_repo"], 1)
            self.assertEqual(stats["dropped_in_repo_oos_upstream"], 1)
            self.assertEqual(stats["passthrough_other"], 1)


class CmdEntrypointOosTest(unittest.TestCase):
    def test_go_cmd_entrypoint_is_oos(self):
        # Operator-only Go CLI entrypoint under cmd/ must be OUT of scope.
        self.assertTrue(se.is_oos("x/cmd/geth/main.go"))
        self.assertTrue(se.is_oos("cmd/bor/main.go"))
        self.assertTrue(se.is_cli_entrypoint("x/cmd/geth/main.go"))

    def test_protocol_solidity_not_oos(self):
        # A plain protocol contract must stay in scope (no cmd segment).
        self.assertFalse(se.is_oos("contracts/Foo.sol"))

    def test_cmd_gate_does_not_drop_non_go_or_substrings(self):
        # cmd is Go-convention-only: a Solidity contracts/cmd file is NOT dropped.
        self.assertFalse(se.is_oos("contracts/cmd/Foo.sol"))
        # bare 'cmd.go' basename (not a dir segment) is NOT a cmd/ entrypoint.
        self.assertFalse(se.is_cli_entrypoint("modules/cmd.go"))
        # 'cmdline' dir is a substring of cmd but a different segment - KEPT.
        self.assertFalse(se.is_cli_entrypoint("cmdline/parse.go"))
        # an ordinary protocol Go file stays in scope.
        self.assertFalse(se.is_oos("modules/exchange/keeper.go"))

    def test_cmd_entrypoint_oos_via_dir_shape(self):
        # is_oos_dir (fork-repo enumeration path) also drops Go cmd/ entrypoints.
        self.assertTrue(se.is_oos_dir("src/bor/cmd/bor/main.go"))


if __name__ == "__main__":
    unittest.main()
