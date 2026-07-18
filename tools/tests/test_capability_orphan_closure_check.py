"""Tests for tools/capability-orphan-closure-check.py (PR12 orphan-closure gate).

The classifier touches the live repo (Makefile/hooks corpus, tools/ source) for
its WIRED / HELPER detectors, so these tests exercise the disposition logic and
the strict/non-strict verdict surface via small synthetic inventories + the
declarations sidecar (per-cap overrides + default_policy), which are the parts a
fixture can fully control.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = REPO_ROOT / "tools" / "capability-orphan-closure-check.py"


def _load_module():
    """Import the hyphenated tool module in-process for unit-level tests."""
    spec = importlib.util.spec_from_file_location("_coc_p7", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_inventory(tmp: Path, caps: list[dict]) -> Path:
    p = tmp / "inv.jsonl"
    p.write_text("\n".join(json.dumps(c) for c in caps) + "\n", encoding="utf-8")
    return p


def _write_declarations(tmp: Path, obj: dict) -> Path:
    p = tmp / "decl.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _run(inv: Path, *, strict=False, declarations: Path | None = None) -> dict:
    cmd = [sys.executable, str(TOOL), "--inventory", str(inv), "--json"]
    if strict:
        cmd.append("--strict")
    if declarations is not None:
        cmd += ["--declarations", str(declarations)]
    else:
        # point at a non-existent declarations file so the live repo sidecar
        # does not leak into the fixture run.
        cmd += ["--declarations", str(inv.parent / "no-such-decl.json")]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = json.loads(proc.stdout)
    out["_rc"] = proc.returncode
    return out


# An mcp-callable is a surface-wired category -> always WIRED, never orphan.
WIRED_SURFACE_CAP = {
    "id": "CAP-mcp-vault-foo",
    "name": "vault_foo",
    "category": "mcp-callable",
    "status": "NOMINAL-WIRED",
    "file_paths": [],
}

# A KNOWN-BROKEN python tool -> BLOCKED.
BLOCKED_CAP = {
    "id": "CAP-tool-broken-thing",
    "name": "broken-thing",
    "category": "python-tool",
    "status": "KNOWN-BROKEN",
    "file_paths": ["tools/broken-thing.py"],
}

# A python tool with no wiring, no import, no advisory/deprecation, no policy
# -> unexplained ORPHAN.
ORPHAN_CAP = {
    "id": "CAP-tool-zzz-totally-unwired-xyz",
    "name": "zzz-totally-unwired-xyz",
    "category": "python-tool",
    "status": "landed-orphan",
    "file_paths": ["tools/zzz-totally-unwired-xyz.py"],
}


class TestOrphanClosure(unittest.TestCase):
    def test_orphan_fails_strict(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [WIRED_SURFACE_CAP, ORPHAN_CAP])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "fail-unexplained-orphans")
            self.assertEqual(res["_rc"], 1)
            self.assertEqual(res["orphan_count"], 1)
            self.assertEqual(res["orphans"][0]["name"], "zzz-totally-unwired-xyz")

    def test_orphan_non_strict_passes_but_reports(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [WIRED_SURFACE_CAP, ORPHAN_CAP])
            res = _run(inv, strict=False)
            self.assertEqual(res["verdict"], "pass-orphans-non-strict")
            self.assertEqual(res["_rc"], 0)
            self.assertEqual(res["orphan_count"], 1)

    def test_fully_classified_set_passes_strict(self):
        # Only surface-wired + blocked caps -> zero orphans, STRICT passes.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [WIRED_SURFACE_CAP, BLOCKED_CAP])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "pass-all-classified")
            self.assertEqual(res["_rc"], 0)
            self.assertEqual(res["orphan_count"], 0)
            self.assertEqual(res["counts"]["WIRED"], 1)
            self.assertEqual(res["counts"]["BLOCKED"], 1)

    def test_per_cap_declaration_resolves_orphan(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp,
                {
                    "declarations": {
                        "CAP-tool-zzz-totally-unwired-xyz": {
                            "disposition": "DEPRECATED",
                            "reason": "retired in fixture",
                        }
                    }
                },
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["verdict"], "pass-all-classified")
            self.assertEqual(res["_rc"], 0)
            self.assertEqual(res["counts"]["DEPRECATED"], 1)

    def test_category_catchall_disabled_by_default_does_not_rescue(self):
        # The OLD category catch-all (default_disposition + applies_to_categories
        # WITHOUT allow_category_catchall:true) must NOT rubber-stamp a pure-lib
        # no-output orphan ADVISORY. This is the false-pass the PR12b fix closes:
        # ADVISORY is evidence-based, not category-based.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp,
                {
                    "default_policy": {
                        "default_disposition": "ADVISORY",
                        "default_reason": "standalone CLI by policy",
                        "applies_to_categories": ["python-tool"],
                    }
                },
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["verdict"], "fail-unexplained-orphans")
            self.assertEqual(res["_rc"], 1)
            self.assertEqual(res["counts"]["ORPHAN"], 1)
            self.assertEqual(res["counts"].get("ADVISORY", 0), 0)

    def test_category_catchall_honored_only_with_explicit_optin(self):
        # If an operator EXPLICITLY opts in via allow_category_catchall:true, the
        # category rubber-stamp is honored (escape hatch), but it is off by
        # default so the orphan count stays honest.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp,
                {
                    "default_policy": {
                        "allow_category_catchall": True,
                        "default_disposition": "ADVISORY",
                        "default_reason": "operator opt-in",
                        "applies_to_categories": ["python-tool"],
                    }
                },
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["verdict"], "pass-all-classified")
            self.assertEqual(res["_rc"], 0)
            self.assertEqual(res["counts"]["ADVISORY"], 1)

    def test_per_cap_declaration_beats_category_catchall(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp,
                {
                    "default_policy": {
                        "allow_category_catchall": True,
                        "default_disposition": "ADVISORY",
                        "applies_to_categories": ["python-tool"],
                    },
                    "declarations": {
                        "zzz-totally-unwired-xyz": {
                            "disposition": "DEPRECATED",
                            "reason": "explicit override",
                        }
                    },
                },
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["counts"]["DEPRECATED"], 1)
            self.assertEqual(res["counts"].get("ADVISORY", 0), 0)

    def test_evidence_pure_lib_no_output_is_orphan_under_strict(self):
        # A REAL pure-library no-output python tool (no CLI entrypoint, no
        # artifact emission) on disk -> ORPHAN, STRICT fails. This is the core
        # false-pass regression lock: category=python-tool is NOT enough.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            libf = tmp / "planted_pure_lib_xyz.py"
            libf.write_text(
                '"""Pure library, no entrypoint, no output."""\n'
                "import os\n\n"
                "def helper(x):\n    return x + 1\n\n"
                "class Thing:\n    def m(self):\n        return 42\n",
                encoding="utf-8",
            )
            cap = {
                "id": "CAP-tool-planted-pure-lib-xyz",
                "name": "planted-pure-lib-xyz",
                "category": "python-tool",
                "status": "landed-orphan",
                "file_paths": [str(libf)],
            }
            inv = _write_inventory(tmp, [cap])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "fail-unexplained-orphans")
            self.assertEqual(res["_rc"], 1)
            self.assertEqual(res["counts"]["ORPHAN"], 1)

    def test_evidence_cli_plus_artifact_is_advisory(self):
        # A standalone CLI tool with argparse + a printed report -> evidence-backed
        # ADVISORY (no category rubber-stamp needed, no sidecar policy).
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tf = tmp / "planted_advisory_xyz.py"
            tf.write_text(
                "#!/usr/bin/env python3\n"
                '"""Standalone advisory CLI emitting a leads report."""\n'
                "import argparse, json, sys\n\n"
                "def main():\n"
                "    ap = argparse.ArgumentParser()\n"
                "    ap.add_argument('--out')\n"
                "    args = ap.parse_args()\n"
                "    print(json.dumps({'leads': [1, 2, 3]}))\n"
                "    return 0\n\n"
                "if __name__ == '__main__':\n    sys.exit(main())\n",
                encoding="utf-8",
            )
            cap = {
                "id": "CAP-tool-planted-advisory-xyz",
                "name": "planted-advisory-xyz",
                "category": "python-tool",
                "status": "landed-orphan",
                "file_paths": [str(tf)],
            }
            inv = _write_inventory(tmp, [cap])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "pass-all-classified")
            self.assertEqual(res["_rc"], 0)
            self.assertEqual(res["counts"]["ADVISORY"], 1)
            self.assertEqual(res["counts"]["ORPHAN"], 0)

    def test_evidence_toplevel_script_body_no_main_guard_is_advisory(self):
        # A script with a top-level executable body (a for-loop that prints) but
        # NO __main__ guard and NO argparse is still a runnable entrypoint with
        # output -> ADVISORY. (Mirrors the real aggregate-*-leads.py tools.)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tf = tmp / "planted_scriptbody_xyz.py"
            tf.write_text(
                "#!/usr/bin/env python3\n"
                '"""Top-level script body, no __main__ guard."""\n'
                "import json\n\n"
                "leads = [1, 2, 3]\n"
                "for i in leads:\n"
                "    print(i)\n",
                encoding="utf-8",
            )
            cap = {
                "id": "CAP-tool-planted-scriptbody-xyz",
                "name": "planted-scriptbody-xyz",
                "category": "python-tool",
                "status": "landed-orphan",
                "file_paths": [str(tf)],
            }
            inv = _write_inventory(tmp, [cap])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "pass-all-classified")
            self.assertEqual(res["counts"]["ADVISORY"], 1)

    def test_evidence_cli_only_no_output_is_orphan(self):
        # A tool with a CLI entrypoint but NO artifact/output emission fails the
        # advisory shape (advisory tools must produce a lead/report). -> ORPHAN.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            tf = tmp / "planted_cli_noout_xyz.py"
            tf.write_text(
                "#!/usr/bin/env python3\n"
                '"""CLI parse but no output at all."""\n'
                "import argparse\n\n"
                "def main():\n"
                "    ap = argparse.ArgumentParser()\n"
                "    ap.add_argument('--x')\n"
                "    args = ap.parse_args()\n"
                "    _ = args.x\n\n"
                "if __name__ == '__main__':\n    main()\n",
                encoding="utf-8",
            )
            cap = {
                "id": "CAP-tool-planted-cli-noout-xyz",
                "name": "planted-cli-noout-xyz",
                "category": "python-tool",
                "status": "landed-orphan",
                "file_paths": [str(tf)],
            }
            inv = _write_inventory(tmp, [cap])
            res = _run(inv, strict=True)
            self.assertEqual(res["verdict"], "fail-unexplained-orphans")
            self.assertEqual(res["counts"]["ORPHAN"], 1)

    def test_missing_inventory_errors(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cmd = [
                sys.executable,
                str(TOOL),
                "--inventory",
                str(tmp / "does-not-exist.jsonl"),
                "--json",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "error")
            self.assertEqual(proc.returncode, 2)

    def test_invalid_default_policy_disposition_ignored(self):
        # A garbage / ORPHAN default disposition must not silence a real orphan.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp, {"default_policy": {"default_disposition": "ORPHAN"}}
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["verdict"], "fail-unexplained-orphans")
            self.assertEqual(res["_rc"], 1)

    def test_schema_present(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [WIRED_SURFACE_CAP])
            res = _run(inv)
            self.assertEqual(res["schema"], "auditooor.capability_orphan_closure.v1")


# ---------------------------------------------------------------------------
# P7: STALE_WIRE / SHADOW_READER + seed-tightening. These are unit-level tests
# that monkeypatch the module's corpus builders so the comment-vs-live wiring
# world is deterministic (the live repo has no STALE_WIRE tool, so an end-to-end
# fixture cannot inject a Makefile-comment reference on its own).
# ---------------------------------------------------------------------------
class TestP7StaleWireShadowReader(unittest.TestCase):
    def setUp(self):
        self.mod = _load_module()
        self._orig = {
            "build_wired_corpus": self.mod.build_wired_corpus,
            "build_tool_source_index": self.mod.build_tool_source_index,
            "build_advisory_names": self.mod.build_advisory_names,
            "build_deprecated_names": self.mod.build_deprecated_names,
        }

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(self.mod, k, v)

    def _patch_world(self, *, wired_corpus: str, src_index: dict):
        self.mod.build_wired_corpus = lambda: wired_corpus
        self.mod.build_tool_source_index = lambda: dict(src_index)
        self.mod.build_advisory_names = lambda: set()
        self.mod.build_deprecated_names = lambda: set()

    @staticmethod
    def _cap(stem):
        return {
            "id": f"CAP-{stem}",
            "name": stem,
            "category": "python-tool",
            "status": "landed-orphan",
            # file_paths point at non-existent paths so classify() falls back to
            # the (patched) stem source index instead of reading disk.
            "file_paths": [f"tools/{stem}.py"],
        }

    def _disp(self, results):
        return {r["cap_id"]: r["disposition"] for r in results}

    def test_stale_wire_fires_for_comment_only_makefile_ref(self):
        # ghost-tool: named ONLY in a Makefile COMMENT line, pure-lib no shape.
        # -> STALE_WIRE (a dead comment-wire), NOT a false-green WIRED, NOT ORPHAN.
        self._patch_world(
            wired_corpus=(
                "# usage: python3 tools/ghost-tool.py write --workspace ...\n"
                "real-target:\n\t@python3 tools/live-tool.py\n"
            ),
            src_index={
                "ghost-tool": '"""pure lib, no cli, no output"""\ndef h(x):\n    return x\n',
                "live-tool": '#!/usr/bin/env python3\nimport sys\nprint("hi")\n',
            },
        )
        res = self.mod.classify([self._cap("ghost-tool"), self._cap("live-tool")], {}, {})
        disp = self._disp(res)
        self.assertEqual(disp["CAP-ghost-tool"], "STALE_WIRE")
        # A genuinely-wired tool (real recipe line) stays WIRED -> clean.
        self.assertEqual(disp["CAP-live-tool"], "WIRED")

    def test_seed_tightening_removes_comment_false_green(self):
        # The pre-P7 LOOSE substring seed would have marked ghost-tool WIRED off
        # the comment. Prove the tightened LIVE-corpus seed does NOT, by checking
        # the direct_wired seed the classifier computes from the live corpus.
        wired_corpus = "# python3 tools/ghost-tool.py   <-- comment only\n"
        live = self.mod._strip_comment_lines(wired_corpus)
        self.assertNotIn("ghost-tool.py", live)  # comment stripped
        self.assertIn("ghost-tool.py", wired_corpus)  # but present in raw
        # End-to-end: with ONLY the comment mention, ghost-tool is STALE_WIRE
        # (would have been a false WIRED under the loose substring match).
        self._patch_world(
            wired_corpus=wired_corpus,
            src_index={"ghost-tool": '"""pure lib"""\ndef h():\n    return 1\n'},
        )
        res = self.mod.classify([self._cap("ghost-tool")], {}, {})
        self.assertEqual(res[0]["disposition"], "STALE_WIRE")

    def test_shadow_reader_fires_for_unwired_sibling_live_source_ref(self):
        # shadow-target: unreached by the declared wiring graph AND referenced in
        # the LIVE source of an UNWIRED sibling (so transitive closure never picks
        # it up) -> SHADOW_READER. (If the observer were WIRED, shadow-target would
        # be legitimately transitively WIRED, which is the correct call - that is
        # NOT a shadow read; the shadow case is precisely an UNDECLARED reader.)
        self._patch_world(
            wired_corpus="real:\n\t@python3 tools/some-other-live-tool.py\n",
            src_index={
                # unwired-observer is itself not reached by the declared graph.
                "unwired-observer": (
                    "#!/usr/bin/env python3\nimport subprocess\n"
                    'subprocess.run(["python3", "tools/shadow-target.py"])\nprint("ran")\n'
                ),
                "shadow-target": '"""pure lib"""\ndef g():\n    return 1\n',
            },
        )
        res = self.mod.classify([self._cap("shadow-target")], {}, {})
        self.assertEqual(res[0]["disposition"], "SHADOW_READER")

    def test_comment_only_sibling_ref_is_not_shadow_reader(self):
        # If the sibling only NAMES the tool in a COMMENT (not live code) and the
        # declared graph does not reach it, it must NOT become SHADOW_READER (a
        # comment mention is not a live consumer). Not in the wire corpus at all
        # -> ORPHAN.
        self._patch_world(
            wired_corpus="real:\n\t@python3 tools/some-other-live-tool.py\n",
            src_index={
                "unwired-observer": (
                    "#!/usr/bin/env python3\n"
                    "# see tools/lonely-target.py for the manual step\nprint('x')\n"
                ),
                "lonely-target": '"""pure lib"""\ndef g():\n    return 1\n',
            },
        )
        res = self.mod.classify([self._cap("lonely-target")], {}, {})
        # Only a comment mention in a sibling -> not a live shadow read -> ORPHAN.
        self.assertEqual(res[0]["disposition"], "ORPHAN")

    def test_stale_wire_advisory_by_default_flag_unset(self):
        # STALE_WIRE present, --strict, but env flag UNSET -> STILL a pass
        # (orphans==0), advisory-only. This is the advisory-first contract.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [WIRED_SURFACE_CAP])  # any 0-orphan set
            env = dict(os.environ)
            env.pop("AUDITOOOR_ORPHAN_RUNBOOK_STRICT", None)
            cmd = [
                sys.executable, str(TOOL), "--inventory", str(inv), "--json",
                "--strict", "--declarations", str(tmp / "none.json"),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "pass-all-classified")
            self.assertEqual(proc.returncode, 0)
            self.assertFalse(out["runbook_strict"])

    def test_env_flag_promotes_stale_wire_to_failure_under_strict(self):
        # With the opt-in env flag AND --strict, a STALE_WIRE fails closed.
        # We exercise this against the LIVE repo where stale_wire_count may be 0;
        # so we assert the FLAG PLUMBING: verdict==fail-stale-wires IFF stale>0.
        env = dict(os.environ)
        env["AUDITOOOR_ORPHAN_RUNBOOK_STRICT"] = "1"
        cmd = [
            sys.executable, str(TOOL), "--inventory",
            str(REPO_ROOT / "reference" / "capability_inventory.jsonl"),
            "--json", "--strict",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        out = json.loads(proc.stdout)
        self.assertTrue(out["runbook_strict"])
        if out["stale_wire_count"] > 0:
            self.assertEqual(out["verdict"], "fail-stale-wires")
            self.assertEqual(proc.returncode, 1)
        else:
            # No stale wires on the live tree -> flag has no adverse effect.
            self.assertEqual(out["verdict"], "pass-all-classified")
            self.assertEqual(proc.returncode, 0)

    def test_declaration_can_pin_stale_wire_disposition(self):
        # STALE_WIRE / SHADOW_READER are now VALID_DISPOSITIONS, so an operator
        # can pin one via the sidecar (additive enum acceptance).
        self.assertIn("STALE_WIRE", self.mod.VALID_DISPOSITIONS)
        self.assertIn("SHADOW_READER", self.mod.VALID_DISPOSITIONS)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inv = _write_inventory(tmp, [ORPHAN_CAP])
            decl = _write_declarations(
                tmp,
                {"declarations": {"CAP-tool-zzz-totally-unwired-xyz": {
                    "disposition": "STALE_WIRE", "reason": "operator-pinned"}}},
            )
            res = _run(inv, strict=True, declarations=decl)
            self.assertEqual(res["counts"]["STALE_WIRE"], 1)
            self.assertEqual(res["counts"]["ORPHAN"], 0)


class TestP7FlagUnsetBaselineRegression(unittest.TestCase):
    """Flag-unset output MUST equal the captured pre-change baseline (contract #6).

    Compares the live-repo, default (non-strict) run of the tool against the
    disposition COUNTS + verdict recorded in /tmp/qna-build-baselines/P7.txt.
    The seed-tightening intentionally reclassifies two comment-false-green caps
    (mining-manifest WIRED->ADVISORY; lane.result.validator HELPER->WIRED), so
    the byte-invariant here is: total unchanged, orphans==0, verdict unchanged,
    and NO capability landed STALE_WIRE/SHADOW_READER/ORPHAN on the live tree
    (the two P7 states only ever capture would-be-orphans, of which there are 0).
    """

    BASELINE = Path("/tmp/qna-build-baselines/P7.txt")

    def test_live_default_run_is_zero_orphan_and_no_new_state_fires(self):
        env = dict(os.environ)
        env.pop("AUDITOOOR_ORPHAN_RUNBOOK_STRICT", None)
        cmd = [
            sys.executable, str(TOOL), "--inventory",
            str(REPO_ROOT / "reference" / "capability_inventory.jsonl"), "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        out = json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "pass-all-classified")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(out["orphan_count"], 0)
        # The two P7 diagnostic states must NOT fire on the live tree (they only
        # ever capture would-be-orphans; the tree has none).
        self.assertEqual(out["counts"].get("STALE_WIRE", 0), 0)
        self.assertEqual(out["counts"].get("SHADOW_READER", 0), 0)
        # total capability count unchanged from baseline.
        if self.BASELINE.exists():
            m = re.search(r"total=(\d+)\s+orphans=(\d+)", self.BASELINE.read_text())
            if m:
                self.assertEqual(out["total_capabilities"], int(m.group(1)))
                self.assertEqual(out["orphan_count"], int(m.group(2)))

    def test_strict_flag_unset_matches_nonstrict_pass(self):
        # Contract #1: flag-unset --strict is byte-identical verdict to today
        # (pass, rc 0) because orphans==0 and STALE_WIRE cannot fail without the
        # opt-in env flag.
        env = dict(os.environ)
        env.pop("AUDITOOOR_ORPHAN_RUNBOOK_STRICT", None)
        cmd = [
            sys.executable, str(TOOL), "--inventory",
            str(REPO_ROOT / "reference" / "capability_inventory.jsonl"),
            "--json", "--strict",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        out = json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "pass-all-classified")
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
