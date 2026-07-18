# r36-rebuttal: registered in .auditooor/agent_pathspec.json as lane cross-seed-fix3; orchestrator commits
"""Tests for tools/cross-workspace-seed.py (FIX 3 cross-workspace intake seed)."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "cross-workspace-seed.py"
_spec = importlib.util.spec_from_file_location("cross_workspace_seed", _TOOL)
cws = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cws)


def _make_ws(tmp: Path, *, ext_counts=None, repos=None, assets=None) -> Path:
    ws = tmp / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    intake = {
        "file_extension_counts": ext_counts or {},
        "assets_in_scope": assets or [],
    }
    (ws / "INTAKE_BASELINE.json").write_text(json.dumps(intake), encoding="utf-8")
    if repos is not None:
        lines = ["# header comment"]
        lines.extend(f"{r}\tmain\tprimary" for r in repos)
        (ws / "targets.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ws


def _fake_caller(responses):
    """Return a vault_caller stub that maps callable-name -> (json, err)."""

    def caller(name, args_obj):
        if name in responses:
            val = responses[name]
            if callable(val):
                return val(args_obj)
            return val
        return None, f"unmocked:{name}"

    return caller


class TestLanguageDerivation(unittest.TestCase):
    def test_go_primary(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".go": 2000, ".sol": 5, ".md": 100})
            lang, counts = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "go")
            self.assertIn(".go", counts)
            self.assertNotIn(".md", counts)  # non-source ext excluded

    def test_solidity_primary(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".sol": 300, ".js": 50})
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "solidity")

    def test_no_language_signal(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".md": 10, ".json": 3})
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "")

    def test_security_language_beats_higher_count_scripting(self):
        # r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
        # dYdX anchor: .ts file count exceeds .go, but go is the security
        # surface and corpus key. Must NOT pick typescript.
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".ts": 2180, ".go": 2043, ".py": 237})
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "go")

    def test_scripting_only_falls_through(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".ts": 100, ".py": 50})
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "typescript")

    def test_highest_security_language_wins(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".go": 10, ".sol": 400, ".ts": 9000})
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "solidity")

    def test_fallback_scan_when_no_counts(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={})
            (ws / "a.rs").write_text("fn main(){}", encoding="utf-8")
            (ws / "b.rs").write_text("fn x(){}", encoding="utf-8")
            lang, _ = cws.derive_language(cws._load_intake(ws), ws)
            self.assertEqual(lang, "rust")


class TestFamilyDerivation(unittest.TestCase):
    def test_morpho_family(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), repos=["github.com/morpho-org/morpho-blue"])
            fams = cws.derive_families(cws._load_intake(ws), cws._read_targets_tsv(ws))
            self.assertIn("morpho-blue", fams)

    def test_dydx_cosmos_family(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), repos=["github.com/dydxprotocol/v4-chain"])
            fams = cws.derive_families(cws._load_intake(ws), cws._read_targets_tsv(ws))
            self.assertIn("dydx-perps", fams)

    def test_hyperbridge_bridge_family(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), repos=["github.com/polytope-labs/hyperbridge"])
            fams = cws.derive_families(cws._load_intake(ws), cws._read_targets_tsv(ws))
            self.assertIn("cross-chain-bridge", fams)

    def test_no_family_signal(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), repos=["github.com/example/random-thing"])
            fams = cws.derive_families(cws._load_intake(ws), cws._read_targets_tsv(ws))
            self.assertEqual(fams, [])

    def test_comment_lines_skipped_in_targets(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), repos=["github.com/morpho-org/morpho-blue"])
            # The "# header comment" line must not become a repo token
            repos = cws._read_targets_tsv(ws)
            self.assertEqual(repos, ["github.com/morpho-org/morpho-blue"])


class TestBuildSeed(unittest.TestCase):
    def test_happy_path_all_pulls(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(
                Path(t),
                ext_counts={".go": 2043},
                repos=["github.com/dydxprotocol/v4-chain"],
            )
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": (
                        {
                            "dead_ends": [
                                {"record_id": "d1", "kill_reason": "math impossible"}
                            ],
                            "context_pack_id": "ddc.v1:abc",
                        },
                        None,
                    ),
                    "vault_corpus_search": (
                        {
                            "degraded": False,
                            "total_records_matched": 42,
                            "records": [
                                {
                                    "record_id": "c1",
                                    "attack_class": "oracle",
                                    "target_domain": "dydx-perps",
                                }
                            ],
                            "context_pack_id": "cs.v1:def",
                        },
                        None,
                    ),
                    "vault_cross_language_pattern_lift": (
                        {
                            "lift_candidates": [{"pattern": "reentrancy", "record_id": "l1"}],
                            "source_language": "solidity",
                            "target_language": "go",
                        },
                        None,
                    ),
                }
            )
            seed = cws.build_seed(ws, limit=10, vault_caller=caller)
            self.assertFalse(seed["degraded"])
            self.assertEqual(seed["derived"]["primary_language"], "go")
            self.assertIn("dydx-perps", seed["derived"]["families"])
            self.assertEqual(seed["totals"]["known_dead_ends"], 1)
            self.assertGreaterEqual(seed["totals"]["same_family_corpus"], 1)
            self.assertEqual(seed["totals"]["cross_language_lift"], 1)

    def test_corpus_dedup(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(
                Path(t),
                ext_counts={".go": 100},
                repos=["github.com/dydxprotocol/v4-chain", "github.com/cosmos/cosmos-sdk"],
            )
            # both language query and domain queries return the SAME record id
            same = (
                {
                    "degraded": False,
                    "total_records_matched": 1,
                    "records": [{"record_id": "dup1", "attack_class": "x"}],
                },
                None,
            )
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": ({"dead_ends": []}, None),
                    "vault_corpus_search": same,
                    "vault_cross_language_pattern_lift": ({"lift_candidates": []}, None),
                }
            )
            seed = cws.build_seed(ws, vault_caller=caller)
            # despite multiple queries returning dup1, it appears once
            self.assertEqual(seed["pulls"]["same_family_corpus"]["count"], 1)

    def test_vault_failure_degrades_not_fatal(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".rs": 500}, repos=["github.com/buildonspark/spark"])
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": (None, "timeout:vault_known_dead_ends"),
                    "vault_corpus_search": (None, "rc=1:boom"),
                    "vault_cross_language_pattern_lift": (None, "json-decode-error"),
                }
            )
            seed = cws.build_seed(ws, vault_caller=caller)
            self.assertTrue(seed["degraded"])
            self.assertTrue(seed["degraded_reasons"])
            # totals still present (zeroed), build did not raise
            self.assertEqual(seed["totals"]["known_dead_ends"], 0)

    def test_corpus_degraded_response_handled(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".go": 10}, repos=["github.com/dydxprotocol/v4-chain"])
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": ({"dead_ends": []}, None),
                    "vault_corpus_search": ({"degraded": True, "reason": "query_must_be_object"}, None),
                    "vault_cross_language_pattern_lift": ({"lift_candidates": []}, None),
                }
            )
            seed = cws.build_seed(ws, vault_caller=caller)
            self.assertEqual(seed["pulls"]["same_family_corpus"]["count"], 0)
            # degraded corpus responses are recorded in query meta
            metas = seed["pulls"]["same_family_corpus"]["queries"]
            self.assertTrue(any(m.get("degraded_reason") == "query_must_be_object" for m in metas))

    def test_no_language_skips_lift(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".md": 3}, repos=["github.com/example/x"])
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": ({"dead_ends": []}, None),
                    "vault_corpus_search": ({"degraded": False, "records": []}, None),
                }
            )
            seed = cws.build_seed(ws, vault_caller=caller)
            self.assertEqual(seed["pulls"]["cross_language_pattern_lift"]["count"], 0)
            self.assertIn("note", seed["pulls"]["cross_language_pattern_lift"])


class TestWriteAndRender(unittest.TestCase):
    def test_write_seed_creates_both_files(self):
        with tempfile.TemporaryDirectory() as t:
            ws = _make_ws(Path(t), ext_counts={".go": 5}, repos=["github.com/dydxprotocol/v4-chain"])
            caller = _fake_caller(
                {
                    "vault_known_dead_ends": ({"dead_ends": []}, None),
                    "vault_corpus_search": ({"degraded": False, "records": []}, None),
                    "vault_cross_language_pattern_lift": ({"lift_candidates": []}, None),
                }
            )
            seed = cws.build_seed(ws, vault_caller=caller)
            jp, mp = cws.write_seed(ws, seed)
            self.assertTrue(jp.is_file())
            self.assertTrue(mp.is_file())
            self.assertEqual(jp.name, "cross_workspace_seed.json")
            self.assertEqual(mp.name, "cross_workspace_seed.md")
            # JSON must round-trip
            json.loads(jp.read_text(encoding="utf-8"))

    def test_render_markdown_contains_sections(self):
        seed = {
            "derived": {"primary_language": "go", "families": ["dydx-perps"]},
            "degraded": False,
            "pulls": {
                "known_dead_ends": {"count": 1, "items": [{"record_id": "d1", "kill_reason": "r"}]},
                "same_family_corpus": {"count": 1, "items": [{"record_id": "c1", "attack_class": "a"}]},
                "cross_language_pattern_lift": {"count": 1, "items": [{"pattern": "p"}]},
            },
        }
        md = cws.render_brief_markdown(seed)
        self.assertIn("Cross-Workspace Seed", md)
        self.assertIn("Known dead-ends to SKIP", md)
        self.assertIn("Prior same-family corpus findings", md)
        self.assertIn("Cross-language patterns liftable", md)
        self.assertIn("d1", md)
        self.assertIn("c1", md)

    def test_render_dead_end_alternate_shape(self):
        # r36-rebuttal: registered lane cross-seed-fix3; orchestrator commits
        # mined-triage dead-ends carry attack_class/reason/verdict, not
        # record_id/kill_reason. Renderer must not emit "?" placeholders.
        seed = {
            "derived": {"primary_language": "go", "families": []},
            "degraded": False,
            "pulls": {
                "known_dead_ends": {
                    "count": 1,
                    "items": [
                        {
                            "attack_class": "liquidation-collapse",
                            "file": "x/clob/keeper/foo.go",
                            "reason": "liq bonus improves ratio",
                            "verdict": "KILL",
                        }
                    ],
                },
                "same_family_corpus": {"count": 0, "items": []},
                "cross_language_pattern_lift": {"count": 0, "items": []},
            },
        }
        md = cws.render_brief_markdown(seed)
        self.assertIn("liquidation-collapse", md)
        self.assertIn("liq bonus improves ratio", md)
        # the specific dead-end line must not degrade to a bare "?"
        self.assertNotIn("- `?` —", md)

    def test_render_markdown_empty_pulls(self):
        seed = {
            "derived": {"primary_language": "", "families": []},
            "degraded": True,
            "degraded_reasons": ["known_dead_ends:timeout"],
            "pulls": {
                "known_dead_ends": {"count": 0, "items": []},
                "same_family_corpus": {"count": 0, "items": []},
                "cross_language_pattern_lift": {"count": 0, "items": []},
            },
        }
        md = cws.render_brief_markdown(seed)
        self.assertIn("(none recorded for this workspace)", md)
        self.assertIn("partially degraded", md)


class TestCLI(unittest.TestCase):
    def test_main_missing_workspace_rc2(self):
        rc = cws.main(["--workspace", "/nonexistent/path/xyz123"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
