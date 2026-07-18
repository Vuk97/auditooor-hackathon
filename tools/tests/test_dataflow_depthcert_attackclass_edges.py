#!/usr/bin/env python3
"""Tests for bidirectional wiring 49c (additive, default-off):

  edge 5 - depth-cert negative-space residual smells from UNGUARDED multi-hop
           value-flow DefUsePaths whose sink fn has NO hunter verdict.
  edge 9 - sink.kind -> CANONICAL attack-class suggestion (R38, taxonomy-verbatim).

Both are ADDITIVE and DEFAULT-OFF: with no slice the outputs are byte-identical to
before the edges existed.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


BUILD = _load("_depthcert_build_49c", TOOLS / "depth-certificate-build.py")
PFHQ = _load("_pfhq_49c", TOOLS / "per-function-hacker-questions.py")
ACMAP = _load("_acmap_49c", TOOLS / "lib" / "dataflow_attack_class.py")


# --- DefUsePath fixtures (schema-valid v1 records) ---------------------------
def _path(
    path_id: str,
    *,
    unguarded: bool,
    call_depth: int,
    sink_kind: str,
    sink_fn: str,
    sink_file: str = "src/Vault.sol",
    sink_line: int = 42,
    confidence: str = "semantic-ssa",
    guard_nodes=None,
) -> dict:
    guard_nodes = guard_nodes or []
    hops = []
    for i in range(call_depth):
        hops.append({
            "from_var": f"v{i}", "to_var": f"v{i+1}", "fn": f"hop{i}",
            "via": "internal_call", "file": "src/H.sol", "line": 10 + i,
            "ir": "", "guarded": False,
        })
    return {
        "schema": "dataflow_path.v1",
        "path_id": path_id,
        "language": "solidity",
        "direction": "forward",
        "engine": "slither",
        "source": {"kind": "param-entrypoint", "fn": "entry", "var": "amt",
                   "file": "src/Vault.sol", "line": 5},
        "sink": {"kind": sink_kind, "callee": sink_kind, "arg_pos": 0,
                 "fn": sink_fn, "file": sink_file, "line": sink_line},
        "hops": hops,
        "call_depth": call_depth,
        "unguarded": unguarded,
        "guard_nodes": guard_nodes,
        "source_unit_ids": [],
        "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": False,
    }


def _write_slice(ws: Path, paths: list[dict]) -> None:
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (aud / "dataflow_paths.jsonl").write_text(
        "\n".join(json.dumps(p) for p in paths) + "\n", encoding="utf-8"
    )


def _write_coverage_verdict(ws: Path, unit_id: str) -> None:
    aud = ws / ".auditooor" / "coverage_unit_verdicts"
    aud.mkdir(parents=True, exist_ok=True)
    safe = unit_id.replace(".", "-").replace("::", "--")
    (aud / f"{safe}.json").write_text(
        json.dumps({"schema": "auditooor.coverage_unit_verdict.v1",
                    "unit_id": unit_id, "verdict": "mechanical-hunt-no-finding"}),
        encoding="utf-8",
    )


# ============================ EDGE 5 =========================================
class TestEdge5ResidualSmells(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_absent_slice_no_smells_byte_identical_keys(self):
        cert = BUILD.build_certificate(self.ws)
        self.assertNotIn("dataflow_residual_smells", cert)
        self.assertNotIn("dataflow_residual_smells_count", cert)

    def test_unguarded_uncovered_path_becomes_smell(self):
        _write_slice(self.ws, [
            _path("dfp-1", unguarded=True, call_depth=2, sink_kind="transfer",
                  sink_fn="Vault.withdraw(uint256)"),
        ])
        cert = BUILD.build_certificate(self.ws)
        self.assertEqual(cert.get("dataflow_residual_smells_count"), 1)
        smell = cert["dataflow_residual_smells"][0]
        self.assertEqual(smell["source"], "dataflow_unguarded_path")
        self.assertEqual(smell["path_id"], "dfp-1")
        self.assertEqual(smell["sink_file_line"], "src/Vault.sol:42")
        # surfaced in the gate-facing incomplete deltas too
        deltas = [d for d in cert["incomplete_guard_deltas"]
                  if d.get("source") == "dataflow_unguarded_path"]
        self.assertEqual(len(deltas), 1)
        # an undisposed smell keeps the candidate-gap count non-zero
        self.assertGreaterEqual(cert["candidate_gaps_undisposed"], 1)

    def test_guarded_path_is_not_a_smell(self):
        _write_slice(self.ws, [
            _path("dfp-2", unguarded=False, call_depth=2, sink_kind="transfer",
                  sink_fn="Vault.adminWithdraw(uint256)",
                  guard_nodes=[{"file": "src/Vault.sol", "line": 40,
                                "expr": "require(msg.sender==owner)"}]),
        ])
        cert = BUILD.build_certificate(self.ws)
        self.assertNotIn("dataflow_residual_smells", cert)

    def test_covered_sink_fn_excluded(self):
        _write_slice(self.ws, [
            _path("dfp-3", unguarded=True, call_depth=2, sink_kind="transfer",
                  sink_fn="Vault.withdraw(uint256)"),
        ])
        # a coverage verdict for the sink fn => NOT a residual smell
        _write_coverage_verdict(self.ws, "Vault.sol::withdraw")
        cert = BUILD.build_certificate(self.ws)
        self.assertNotIn("dataflow_residual_smells", cert)

    def test_go_module_cache_sink_excluded_vendored(self):
        # NUVA 2026-07-09: a value-flow sink in the Go MODULE CACHE (~/go/pkg/mod/...) is a
        # third-party Go dependency (provenance-io/provenance x/marker Mint/Burn) = OOS, the
        # Go analog of node_modules/@openzeppelin - must NOT become an in-scope residual smell.
        _write_slice(self.ws, [
            _path("go-dep", unguarded=True, call_depth=2, sink_kind="burn",
                  sink_fn="(github.com/provenance-io/provenance/x/marker/keeper.msgServer).Burn",
                  sink_file="/root/go/pkg/mod/github.com/provenance-io/provenance@v1.3.2/x/marker/keeper/msg_server.go",
                  sink_line=319),
        ])
        cert = BUILD.build_certificate(self.ws)
        self.assertNotIn("dataflow_residual_smells", cert,
                         "a Go module-cache (vendored) sink must not be an in-scope depth gap")

    def test_single_hop_and_read_sink_excluded(self):
        _write_slice(self.ws, [
            # single-hop (call_depth 0) -> not multi-hop
            _path("dfp-4", unguarded=True, call_depth=0, sink_kind="transfer",
                  sink_fn="A.f()"),
            # read sink -> not a value mover
            _path("dfp-5", unguarded=True, call_depth=2, sink_kind="state_var_read",
                  sink_fn="B.g()"),
            # heuristic confidence -> advisory, excluded
            _path("dfp-6", unguarded=True, call_depth=2, sink_kind="transfer",
                  sink_fn="C.h()", confidence="heuristic"),
        ])
        cert = BUILD.build_certificate(self.ws)
        self.assertNotIn("dataflow_residual_smells", cert)


# ============================ EDGE 9 =========================================
class TestEdge9AttackClass(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        # synthetic taxonomy with ALL four canonical concept names present so the
        # mapping is testable independent of corpus evolution.
        self.tax = Path(self._tmp.name) / "tax.json"
        self.tax.write_text(json.dumps({"classes": [
            {"attack_class": "fund-transfer"},
            {"attack_class": "supply-manipulation"},
            {"attack_class": "accounting-balance-corruption"},
            {"attack_class": "access-control"},
        ]}), encoding="utf-8")
        ACMAP.canonical_classes.cache_clear()

    def tearDown(self):
        ACMAP.canonical_classes.cache_clear()
        self._tmp.cleanup()

    def test_each_sink_kind_maps_to_canonical_class(self):
        tp = str(self.tax)
        self.assertEqual(ACMAP.suggest_attack_class("transfer", taxonomy_path=tp), "fund-transfer")
        self.assertEqual(ACMAP.suggest_attack_class("transferFrom", taxonomy_path=tp), "fund-transfer")
        self.assertEqual(ACMAP.suggest_attack_class("call", taxonomy_path=tp), "fund-transfer")
        self.assertEqual(ACMAP.suggest_attack_class("low_level_call", taxonomy_path=tp), "fund-transfer")
        self.assertEqual(ACMAP.suggest_attack_class("mint", taxonomy_path=tp), "supply-manipulation")
        self.assertEqual(ACMAP.suggest_attack_class("burn", taxonomy_path=tp), "supply-manipulation")
        self.assertEqual(ACMAP.suggest_attack_class("_mint", taxonomy_path=tp), "supply-manipulation")
        self.assertEqual(ACMAP.suggest_attack_class("storage-value", taxonomy_path=tp), "accounting-balance-corruption")
        self.assertEqual(ACMAP.suggest_attack_class("authority", taxonomy_path=tp), "access-control")

    def test_unknown_or_read_sink_omits(self):
        tp = str(self.tax)
        self.assertIsNone(ACMAP.suggest_attack_class("state_var_read", taxonomy_path=tp))
        self.assertIsNone(ACMAP.suggest_attack_class("", taxonomy_path=tp))
        self.assertIsNone(ACMAP.suggest_attack_class("nonsense", taxonomy_path=tp))

    def test_no_invention_when_taxonomy_lacks_class(self):
        # taxonomy WITHOUT the general names -> omit (never invent a class)
        tax2 = Path(self._tmp.name) / "tax2.json"
        tax2.write_text(json.dumps({"classes": [{"attack_class": "reentrancy"}]}),
                        encoding="utf-8")
        ACMAP.canonical_classes.cache_clear()
        self.assertIsNone(ACMAP.suggest_attack_class("transfer", taxonomy_path=str(tax2)))
        self.assertIsNone(ACMAP.suggest_attack_class("mint", taxonomy_path=str(tax2)))

    def test_callee_fallback_for_generic_call(self):
        tp = str(self.tax)
        # kind="call" already maps; but a kind not in the map can fall back to callee
        self.assertEqual(
            ACMAP.suggest_attack_class("HighLevelCall", callee="transferFrom", taxonomy_path=tp),
            "fund-transfer",
        )

    def test_real_taxonomy_authority_maps_to_access_control(self):
        # against the REAL in-repo taxonomy, authority -> access-control (verbatim)
        ACMAP.canonical_classes.cache_clear()
        self.assertEqual(ACMAP.suggest_attack_class("authority"), "access-control")


class TestEdge9FlowSeededQuestionIntegration(unittest.TestCase):
    """The flow-seeded question carries the additive attack_class suggestion."""

    def test_question_carries_attack_class_when_taxonomy_matches(self):
        # authority sink -> access-control is in the REAL taxonomy, so the
        # flow-seeded question must carry attack_class + provenance.
        seedable = [_path("dfp-9", unguarded=True, call_depth=1, sink_kind="authority",
                          sink_fn="Cfg.setOwner(address)")]
        qs = PFHQ.gen_flow_seeded_questions(seedable)
        self.assertEqual(len(qs), 1)
        self.assertEqual(qs[0]["attack_class"], "access-control")
        self.assertEqual(qs[0]["attack_class_provenance"], "dataflow_sink_kind")

    def test_question_omits_attack_class_when_no_verbatim_match(self):
        # transfer has no verbatim general class in the real corpus today -> the
        # question is emitted WITHOUT an attack_class key (never invented).
        seedable = [_path("dfp-10", unguarded=True, call_depth=1, sink_kind="transfer",
                          sink_fn="Vault.withdraw()")]
        qs = PFHQ.gen_flow_seeded_questions(seedable)
        self.assertEqual(len(qs), 1)
        self.assertNotIn("attack_class", qs[0])
        self.assertNotIn("attack_class_provenance", qs[0])

    def test_empty_seedable_byte_identical(self):
        self.assertEqual(PFHQ.gen_flow_seeded_questions([]), [])


# ==================== UNSAFE-DOWNCAST attack-class (R38) ======================
class TestDowncastAttackClass(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        ACMAP.canonical_classes.cache_clear()

    def tearDown(self):
        ACMAP.canonical_classes.cache_clear()
        self._tmp.cleanup()

    def test_truncation_specific_class_preferred_when_present(self):
        tax = Path(self._tmp.name) / "tax_t.json"
        tax.write_text(json.dumps({"classes": [
            {"attack_class": "integer-truncation"},
            {"attack_class": "integer-overflow"},
        ]}), encoding="utf-8")
        ACMAP.canonical_classes.cache_clear()
        self.assertEqual(
            ACMAP.suggest_downcast_attack_class("transfer", taxonomy_path=str(tax)),
            "integer-truncation",
        )

    def test_falls_back_to_integer_overflow(self):
        tax = Path(self._tmp.name) / "tax_o.json"
        tax.write_text(json.dumps({"classes": [
            {"attack_class": "integer-overflow"},
        ]}), encoding="utf-8")
        ACMAP.canonical_classes.cache_clear()
        self.assertEqual(
            ACMAP.suggest_downcast_attack_class("storage-value", taxonomy_path=str(tax)),
            "integer-overflow",
        )

    def test_no_invention_when_taxonomy_lacks_class(self):
        tax = Path(self._tmp.name) / "tax_n.json"
        tax.write_text(json.dumps({"classes": [{"attack_class": "reentrancy"}]}),
                       encoding="utf-8")
        ACMAP.canonical_classes.cache_clear()
        self.assertIsNone(
            ACMAP.suggest_downcast_attack_class("transfer", taxonomy_path=str(tax)))

    def test_real_taxonomy_maps_to_integer_overflow(self):
        # against the REAL in-repo taxonomy: integer-overflow exists verbatim today,
        # so a downcast path maps to it (the general faithful fallback).
        ACMAP.canonical_classes.cache_clear()
        self.assertEqual(
            ACMAP.suggest_downcast_attack_class("transfer"), "integer-overflow")

    def test_question_carries_downcast_attack_class(self):
        # the downcast question carries the attack_class + provenance from the
        # REAL taxonomy (integer-overflow).
        ACMAP.canonical_classes.cache_clear()
        p = _path("dfp-DC", unguarded=False, call_depth=0, sink_kind="transfer",
                  sink_fn="Vault.pay(uint256)")
        p["downcast_suspect"] = True
        p["downcast"] = {"var": "amount", "from": "uint256", "to": "uint64",
                         "kind": "narrowing", "at_fn": "pay", "at_end": "source",
                         "line": 31}
        qs = PFHQ.gen_downcast_suspect_questions([p])
        self.assertEqual(len(qs), 1)
        self.assertEqual(qs[0]["attack_class"], "integer-overflow")
        self.assertEqual(qs[0]["attack_class_provenance"], "dataflow_downcast_suspect")

    def test_empty_downcast_byte_identical(self):
        self.assertEqual(PFHQ.gen_downcast_suspect_questions([]), [])


if __name__ == "__main__":
    unittest.main()


class TestVendoredSinkFilter(unittest.TestCase):
    """Edge-5 must EXCLUDE vendored / dependency sinks from in-scope residual
    smells. Surfaced by real SSV use: 8 node_modules/@openzeppelin Address.sol
    delegatecall sinks were folded into undisposed depth gaps (OOS vendored code).
    Never-false-pass: only vendored paths are dropped; a project's own
    contracts/libraries/ and src sinks are preserved."""

    def test_vendored_paths_detected(self):
        for p in (
            "src/ssv-network/node_modules/@openzeppelin/contracts/utils/Address.sol",
            "/abs/node_modules/@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol",
            "lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol",
            "lib/forge-std/src/Test.sol",
        ):
            self.assertTrue(BUILD._is_vendored_sink_path(p), f"vendored: {p}")

    def test_project_paths_preserved(self):
        for p in (
            "src/ssv-network/contracts/libraries/ClusterLib.sol",   # SSV's OWN libraries/
            "src/ssv-network/contracts/modules/SSVOperators.sol",
            "contracts/libraries/OperatorLib.sol",
        ):
            self.assertFalse(BUILD._is_vendored_sink_path(p), f"in-scope must be preserved: {p}")

    def test_residual_smells_drop_vendored_sink(self):
        # Isolate the vendored filter by patching the path reader (the real
        # reader schema-validates; this unit-tests the filter logic directly).
        rows = [
            {"path_id": "dfp-v", "unguarded": True, "call_depth": 2, "confidence": "semantic-ssa",
             "sink": {"kind": "call", "fn": "functionDelegateCall",
                      "file": "src/ssv-network/node_modules/@openzeppelin/contracts/utils/Address.sol", "line": 135}},
            {"path_id": "dfp-s", "unguarded": True, "call_depth": 2, "confidence": "semantic-ssa",
             "sink": {"kind": "call", "fn": "someTransfer",
                      "file": "src/ssv-network/contracts/modules/SSVOperators.sol", "line": 90}},
        ]
        orig_read = BUILD._read_dataflow_paths
        orig_cov = BUILD._covered_sink_fn_keys
        BUILD._read_dataflow_paths = lambda ws: rows
        BUILD._covered_sink_fn_keys = lambda ws: set()
        try:
            smells = BUILD._dataflow_residual_smells(Path(tempfile.mkdtemp()))
        finally:
            BUILD._read_dataflow_paths = orig_read
            BUILD._covered_sink_fn_keys = orig_cov
        ids = {s.get("path_id") for s in smells}
        self.assertNotIn("dfp-v", ids, "vendored OZ sink must NOT be a residual smell")
        self.assertIn("dfp-s", ids, "in-scope SSV sink must remain a residual smell")

    def test_covered_sink_credited_via_hunt_findings_sidecar(self):
        """strata 2026-07-01 (loop-caught): _covered_sink_fn_keys must credit
        .auditooor/hunt_findings_sidecars/*.json, not just the (often-empty)
        coverage_unit_verdicts/ dir - on strata that dir was empty while 163 real
        R76-verified hunt sidecars existed, so a genuinely-hunted sink function
        (Tranche._deposit) was treated as uncovered and could never be disposed."""
        ws = Path(tempfile.mkdtemp())
        sc = ws / ".auditooor" / "hunt_findings_sidecars"
        sc.mkdir(parents=True)
        (sc / "hunt__Tranche.sol__deposit.json").write_text(json.dumps({
            "function_anchor": {"file": "Tranche.sol:267",
                                "fn": "Tranche._deposit(address,address,address,uint256,uint256,uint256,bytes)"},
            "result": {"verdict": "kill"},
        }))
        keys = BUILD._covered_sink_fn_keys(ws)
        self.assertIn("_deposit", keys, "hunt sidecar's function_anchor.fn must credit coverage")

    def test_residual_smell_disposed_when_hunt_sidecar_covers_sink(self):
        """End-to-end: an unguarded multi-hop path into a sink WITH a real hunt
        sidecar must NOT be surfaced as a residual smell (it is genuinely covered),
        even when coverage_unit_verdicts/ is absent/empty."""
        ws = Path(tempfile.mkdtemp())
        sc = ws / ".auditooor" / "hunt_findings_sidecars"
        sc.mkdir(parents=True)
        (sc / "hunt__Tranche.sol__deposit.json").write_text(json.dumps({
            "function_anchor": {"file": "Tranche.sol:267", "fn": "Tranche._deposit(...)"},
            "result": {"verdict": "kill"},
        }))
        rows = [_path("dfp-covered", unguarded=True, call_depth=1,
                      sink_kind="safeTransferFrom",
                      sink_fn="Tranche._deposit(address,address,address,uint256,uint256,uint256,bytes)",
                      sink_file="src/contracts/contracts/tranches/Tranche.sol", sink_line=267)]
        _write_slice(ws, rows)
        smells = BUILD._dataflow_residual_smells(ws)
        ids = {s.get("path_id") for s in smells}
        self.assertNotIn("dfp-covered", ids,
                         "a sink with a real hunt_findings_sidecar must be credited as covered")

    def test_residual_smell_drops_out_of_scope_sink(self):
        """strata 2026-07-01 (loop-caught): a dataflow sink OUTSIDE the workspace's
        enumerated in-scope target set (e.g. test/Mock*.sol, a strategies/ dir not
        in SCOPE.md's 13 targets) must be dropped, not surfaced as an
        undisposable residual gap. Reuses scope_authority (same authority
        inscope-disposition-guard.py uses)."""
        ws = Path(tempfile.mkdtemp())
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        (aud / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/contracts/contracts/tranches/Tranche.sol",
                       "function": "deposit"}) + "\n", encoding="utf-8")
        rows = [
            _path("dfp-oos", unguarded=True, call_depth=1, sink_kind="safeTransferFrom",
                 sink_fn="MockSingleStrategy.foo(uint256)",
                 sink_file="src/contracts/contracts/test/MockSingleStrategy.sol", sink_line=10),
            _path("dfp-inscope", unguarded=True, call_depth=1, sink_kind="safeTransferFrom",
                 sink_fn="Tranche.deposit(uint256,address)",
                 sink_file="src/contracts/contracts/tranches/Tranche.sol", sink_line=209),
        ]
        _write_slice(ws, rows)
        smells = BUILD._dataflow_residual_smells(ws)
        ids = {s.get("path_id") for s in smells}
        self.assertNotIn("dfp-oos", ids, "an out-of-scope sink file must be dropped")
        self.assertIn("dfp-inscope", ids, "an uncovered in-scope sink must remain a smell")

    def test_residual_smell_no_manifest_stays_conservative(self):
        """Absent inscope_units.jsonl -> cannot assert OOS -> nothing is dropped
        on scope grounds (false-green-safe default)."""
        ws = Path(tempfile.mkdtemp())
        rows = [_path("dfp-noscope", unguarded=True, call_depth=1, sink_kind="safeTransferFrom",
                      sink_fn="Whatever.foo()", sink_file="src/anything/Whatever.sol", sink_line=1)]
        _write_slice(ws, rows)
        smells = BUILD._dataflow_residual_smells(ws)
        ids = {s.get("path_id") for s in smells}
        self.assertIn("dfp-noscope", ids, "no manifest -> stay conservative, do not drop")


if __name__ == "__main__":
    unittest.main()
