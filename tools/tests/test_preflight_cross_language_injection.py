"""Guard: A5-crosslang-inject - cross-language analogue lift is wired into the pre-flight
pack AND surfaced as a PRIMING-ONLY block by the in-scope hunt batch builder.

Two load-bearing assertions:
 (a) build_pack(): the orchestrator emits a `cross_language_analogues` key (with the lift
     schema sub-keys) AND records `vault_cross_language_pattern_lift` in mcp_status_summary.
 (b) _load_pack_intel(): a pack carrying a non-empty cross_language_analogues block produces
     a priming string containing the `[cross_language_analogues]` marker.

The R76 caveat banner (analogues are accelerant, not evidence) is already enforced by the
existing pack-intel guard test; here we only prove the new key flows end-to-end. A future
removal of either wiring regresses these assertions.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ORCH = ROOT / "tools" / "per-function-preflight-orchestrator.py"
BATCH = ROOT / "tools" / "inscope-hunt-batch-builder.py"


def _load(path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


class CrossLanguageInjectionTest(unittest.TestCase):
    def test_build_pack_emits_cross_language_analogues_block(self):
        from unittest.mock import patch

        tool = _load(ORCH, "per_function_preflight_orchestrator_xlang")
        invariant = tool.load_invariant_module(ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Vault {\n"
                "    uint256 public total;\n"
                "    function deposit(uint256 amount) external { total += amount; }\n"
                "}\n",
                encoding="utf-8",
            )
            functions = invariant.parse_functions(
                ws,
                invariant.discover_solidity_files(ws, None),
                include_internal=False,
                function_filter=None,
            )
            self.assertEqual(len(functions), 1)

            seen_calls = {}

            def fake_call(_repo_root, call, args, _timeout):
                seen_calls[call] = args
                if call == "vault_cross_language_pattern_lift":
                    return {
                        "status": "ok",
                        "call": call,
                        "payload": {
                            "lift_candidates": [{"candidate_id": "x1", "attack_class": "reentrancy"}],
                            "target_language_precedents": [{"candidate_id": "p1"}],
                            "total_records_matched": 2,
                            "degraded": False,
                            "source_refs": ["audit/corpus_tags/tags/foo.json"],
                        },
                    }
                return {"status": "ok", "call": call, "payload": {"selector": "Vault.deposit"}}

            with patch.object(tool, "call_vault", side_effect=fake_call):
                pack = tool.build_pack(ROOT, ws, functions[0], timeout=1, llm_enrich=False)

            # the call ran and was driven with the fn's OWN language as target + a differing source
            self.assertIn("vault_cross_language_pattern_lift", seen_calls)
            xargs = seen_calls["vault_cross_language_pattern_lift"]
            self.assertEqual(xargs["target_language"], "solidity")
            self.assertEqual(xargs["source_language"], "rust")

            # the new pack key is present with the lift schema sub-keys
            self.assertIn("cross_language_analogues", pack)
            cla = pack["cross_language_analogues"]
            for k in ("lift_candidates", "target_language_precedents", "total_records_matched", "degraded"):
                self.assertIn(k, cla)
            self.assertEqual(cla["total_records_matched"], 2)
            self.assertFalse(cla["degraded"])
            self.assertEqual(len(cla["lift_candidates"]), 1)

            # status reporting is free via the loop
            self.assertIn("vault_cross_language_pattern_lift", pack["mcp_status_summary"])
            self.assertIn("vault_cross_language_pattern_lift", pack["mcp_context"])
            # the orchestrator-wide invariant (existing test) still holds: keys == MCP_CALLS
            self.assertEqual(set(pack["mcp_context"].keys()), set(tool.MCP_CALLS))

    def test_load_pack_intel_surfaces_cross_language_block(self):
        builder = _load(BATCH, "inscope_hunt_batch_builder_xlang")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            packs = ws / ".auditooor" / "pre_flight_packs"
            packs.mkdir(parents=True)
            rel = "src/L1/Portal.sol"
            (packs / "pre_flight_pack_Portal_finalize.json").write_text(
                json.dumps(
                    {
                        "per_function_hunter_brief": "check the withdrawal replay guard",
                        "cross_language_analogues": {
                            "lift_candidates": [
                                {"candidate_id": "rust-reentrancy-1", "attack_class": "reentrancy"}
                            ],
                            "target_language_precedents": [],
                            "total_records_matched": 1,
                            "degraded": False,
                            "source_refs": ["audit/corpus_tags/tags/bar.json"],
                        },
                    }
                ),
                encoding="utf-8",
            )
            intel = builder._load_pack_intel(ws, rel, "finalize")
            self.assertIn("[cross_language_analogues]", intel)
            self.assertIn("rust-reentrancy-1", intel)
            # still an accelerant-only block: the source-read warning banner is present
            self.assertIn("PRIMING ONLY", intel)

    def test_load_pack_intel_omits_block_when_absent(self):
        builder = _load(BATCH, "inscope_hunt_batch_builder_xlang2")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            packs = ws / ".auditooor" / "pre_flight_packs"
            packs.mkdir(parents=True)
            (packs / "pre_flight_pack_Portal_prove.json").write_text(
                json.dumps({"per_function_hunter_brief": "no xlang here"}),
                encoding="utf-8",
            )
            intel = builder._load_pack_intel(ws, "src/L1/Portal.sol", "prove")
            self.assertNotIn("[cross_language_analogues]", intel)


if __name__ == "__main__":
    unittest.main(verbosity=2)
