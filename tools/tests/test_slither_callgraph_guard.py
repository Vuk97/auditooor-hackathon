#!/usr/bin/env python3
"""Burn-down item #5 — Slither callgraph guard regression tests.

Slither has a callgraph but hand-written/wave17 Solidity detectors mostly
operate per-contract: they iterate ``self.contracts`` and match a single
function's syntactic shape. When a detector's docstring / HELP / WIKI_*
claims inter-contract semantics ("cross-contract reentrancy", "factory
deploys", "proxy implementation", "callgraph", ...) but the source body
never reads any Slither callgraph API, the detector is under-specified.

These tests pin the classifier added in ``tools/detector-lint.py``:

1. Synthetic detector docstrings × source bodies — confirm the matrix
   {claim, no claim} × {evidence, no evidence} classifies as expected.
2. Real-corpus sanity — at least one wave17 detector that DOES use the
   callgraph (cross-contract-reentrancy-view-exposed via the
   ``function.has_high_level_call_named`` predicate-engine key) is
   surfaced under check 8b, not 8.
3. The multi-contract fixture under
   ``detectors/_fixtures/cross_contract_reentrancy_view_exposed/`` is
   present and contains both `Pool_*.sol` and `Oracle.sol` so the lint
   guard has a regression-pin even if the detector source moves.
4. The CLI flag ``--fail-inter-contract-claim-without-callgraph`` is
   opt-in: default lint must still exit 0 (advisory) when only the
   inter-contract cohort fires.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_PATH = REPO_ROOT / "tools" / "detector-lint.py"
FIXTURE_DIR = (
    REPO_ROOT
    / "detectors"
    / "_fixtures"
    / "cross_contract_reentrancy_view_exposed"
)


def _load_lint_module():
    """Import tools/detector-lint.py despite the hyphen in the filename."""
    spec = importlib.util.spec_from_file_location("detector_lint", LINT_PATH)
    assert spec and spec.loader, f"could not load {LINT_PATH}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ─── Synthetic detector source matrix ───────────────────────────────────────

_DET_NO_CLAIM_NO_EVIDENCE = textwrap.dedent('''
    """plain-old-detector — flag a permissive role grant on a single contract."""

    from slither.detectors.abstract_detector import AbstractDetector


    class PlainOldDetector(AbstractDetector):
        ARGUMENT = "plain-old-detector"
        HELP = "Function lacks an admin role guard before mutating storage."
        WIKI = "https://example/plain-old-detector"
        WIKI_TITLE = "Missing admin role guard"
        WIKI_DESCRIPTION = (
            "Single-function role check; flags state writes without "
            "onlyOwner / onlyRole modifiers."
        )

        def _detect(self):
            results = []
            for c in self.contracts:
                for f in c.functions:
                    if "admin" in f.name.lower():
                        results.append(self.generate_result([f, " — flagged"]))
            return results
''')

_DET_CLAIM_NO_EVIDENCE = textwrap.dedent('''
    """cross-contract-claim-no-evidence — claims to walk inter-contract paths."""

    from slither.detectors.abstract_detector import AbstractDetector


    class CrossContractClaimNoEvidence(AbstractDetector):
        ARGUMENT = "cross-contract-claim-no-evidence"
        HELP = "Cross-contract reentrancy: view exposes mid-mutation state."
        WIKI = "https://example/cross-contract-claim-no-evidence"
        WIKI_TITLE = "Read-only cross-contract reentrancy"
        WIKI_DESCRIPTION = "Sibling contract reads this view during a callback in another contract. Read-only reentrancy across deployments."
        WIKI_EXPLOIT_SCENARIO = "Factory deploys a Pool, sibling Oracle reads getReserves() mid-callback."

        def _detect(self):
            results = []
            # NO callgraph reference — pure per-contract iteration.
            for c in self.contracts:
                for f in c.functions:
                    if "view" in str(f.visibility):
                        results.append(self.generate_result([f, " — flagged"]))
            return results
''')

_DET_CLAIM_WITH_EVIDENCE = textwrap.dedent('''
    """cross-contract-claim-with-evidence — walks high_level_calls."""

    from slither.detectors.abstract_detector import AbstractDetector


    class CrossContractClaimWithEvidence(AbstractDetector):
        ARGUMENT = "cross-contract-claim-with-evidence"
        HELP = "Cross-contract reentrancy: view exposes mid-mutation state."
        WIKI = "https://example/cross-contract-claim-with-evidence"
        WIKI_TITLE = "Read-only cross-contract reentrancy"
        WIKI_DESCRIPTION = "Sibling contract reads getReserves() mid-callback."

        def _detect(self):
            results = []
            for c in self.contracts:
                for f in c.functions:
                    # Walk the callgraph to find the cross-contract edge.
                    for hc in f.high_level_calls:
                        callee = hc[1] if isinstance(hc, tuple) else hc
                        if getattr(callee, "name", "") == "getReserves":
                            results.append(self.generate_result([f, " — flagged"]))
                    for ic in f.internal_calls:
                        _ = ic
            return results
''')

_DET_NO_CLAIM_WITH_EVIDENCE = textwrap.dedent('''
    """helper-call-detector — flags helper writes within one contract."""

    from slither.detectors.abstract_detector import AbstractDetector


    class HelperCallDetector(AbstractDetector):
        ARGUMENT = "helper-call-detector"
        HELP = "Function invokes a private helper that mutates storage."
        WIKI = "https://example/helper-call-detector"
        WIKI_TITLE = "Internal helper write"
        WIKI_DESCRIPTION = (
            "Single-function helper-invocation shape; flags state writes "
            "reachable through a private helper within one contract."
        )

        def _detect(self):
            results = []
            for c in self.contracts:
                for f in c.functions:
                    for ic in f.internal_calls:
                        _ = ic
            return results
''')


class ClaimSignalTest(unittest.TestCase):
    """Unit-level: the claim phrase regexes match what we expect."""

    def setUp(self):
        self.mod = _load_lint_module()

    def test_explicit_cross_contract_phrase_matches(self):
        labels = self.mod.inter_contract_claim_signals(
            "Read-only cross-contract reentrancy via exposed view."
        )
        self.assertIn("cross-contract phrase", labels)

    def test_callgraph_phrase_matches(self):
        labels = self.mod.inter_contract_claim_signals(
            "We walk the callgraph from caller to callee."
        )
        self.assertIn("callgraph reference", labels)

    def test_factory_deploy_phrase_matches(self):
        labels = self.mod.inter_contract_claim_signals(
            "Factory deploys a Pool; siblings share state."
        )
        # Either the factory phrase or sibling phrase suffices. Both are
        # legitimate cross-contract claims; we just need one match.
        self.assertTrue(
            any(
                lbl in labels
                for lbl in ("factory.*deploy phrase", "sibling-contract phrase")
            ),
            f"expected a factory or sibling label, got: {labels}",
        )

    def test_proxy_implementation_phrase_matches(self):
        labels = self.mod.inter_contract_claim_signals(
            "Proxy upgrade points to a fresh implementation."
        )
        self.assertIn("proxy.*implementation phrase", labels)

    def test_per_contract_prose_does_not_match(self):
        # A detector that talks about its single-contract shape must not
        # accidentally trigger because of generic words like "function".
        labels = self.mod.inter_contract_claim_signals(
            "Function lacks an admin role guard before mutating storage."
        )
        self.assertEqual(labels, [])

    def test_upstream_callers_pass_wei_does_not_match(self):
        # Regression: an early version of the regex matched "Upstream
        # callers pass wei" inside a unit-conversion detector, which is
        # not an inter-contract claim. The current narrowed regex must
        # not match generic prose like this.
        labels = self.mod.inter_contract_claim_signals(
            "Upstream callers pass wei, so the multiply re-converts."
        )
        self.assertEqual(labels, [])


class EvidenceSignalTest(unittest.TestCase):
    """Unit-level: callgraph evidence regexes match the right surface."""

    def setUp(self):
        self.mod = _load_lint_module()

    def test_high_level_calls_is_evidence(self):
        code = "for hc in f.high_level_calls: pass"
        labels = self.mod.callgraph_evidence_signals(code)
        self.assertIn("high_level_calls", labels)

    def test_internal_calls_is_evidence(self):
        code = "for ic in f.internal_calls: pass"
        labels = self.mod.callgraph_evidence_signals(code)
        self.assertIn("internal_calls", labels)

    def test_predicate_engine_key_is_evidence(self):
        # DSL-compiled detectors don't import slither directly — they
        # express the callgraph requirement via the predicate-engine
        # key `function.has_high_level_call_named`. The lint must
        # treat that key as evidence.
        code = "_MATCH = [{'function.has_high_level_call_named': 'totalSupply'}]"
        labels = self.mod.callgraph_evidence_signals(code)
        self.assertIn(
            "predicate-engine has_high_level_call key", labels
        )

    def test_self_contracts_alone_is_not_evidence(self):
        # Every detector iterates self.contracts. That alone is not
        # evidence of callgraph use.
        code = "for c in self.contracts: pass"
        labels = self.mod.callgraph_evidence_signals(code)
        self.assertEqual(labels, [])

    def test_relation_count_is_total_references(self):
        code = textwrap.dedent('''
            for hc in f.high_level_calls:
                pass
            for hc2 in f.high_level_calls:
                pass
            for ic in f.internal_calls:
                pass
        ''')
        # 2x high_level_calls + 1x internal_calls = 3 references.
        self.assertEqual(self.mod.callgraph_relation_count(code), 3)


class ExtractClaimAndCodeTest(unittest.TestCase):
    """The claim/code split must correctly separate prose from executable."""

    def setUp(self):
        self.mod = _load_lint_module()

    def test_claim_includes_module_docstring_and_class_attrs(self):
        claim = self.mod._extract_claim_text(_DET_CLAIM_NO_EVIDENCE)
        self.assertIn("cross-contract", claim.lower())
        self.assertIn("read-only cross-contract reentrancy", claim.lower())
        self.assertIn("sibling", claim.lower())

    def test_code_excludes_class_attribute_strings(self):
        # The claim text says "cross-contract" but the code body must
        # not — we strip HELP/WIKI_* before scanning for evidence.
        code = self.mod._extract_code_text(_DET_CLAIM_NO_EVIDENCE)
        self.assertNotIn("Sibling contract", code)
        self.assertNotIn("Read-only cross-contract reentrancy", code)
        # The executable iteration must still be present.
        self.assertIn("for c in self.contracts", code)

    def test_code_keeps_callgraph_references(self):
        code = self.mod._extract_code_text(_DET_CLAIM_WITH_EVIDENCE)
        self.assertIn("high_level_calls", code)
        self.assertIn("internal_calls", code)


class SyntheticMatrixTest(unittest.TestCase):
    """End-to-end: scan synthetic detectors in a temp folder."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _scan(self, files: dict[str, str]) -> tuple[list, list]:
        """Drop synthetic detectors into a temp folder and run both checks."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for name, src in files.items():
                (tmp / name).write_text(src)
            unsupported = self.mod.inter_contract_claim_without_callgraph(
                folders=[tmp]
            )
            supported = self.mod.inter_contract_claim_with_callgraph(
                folders=[tmp]
            )
            # Convert to plain-name lists so callers don't deal with temp paths.
            return (
                [p.name for p, _, _ in unsupported],
                [(p.name, c) for p, _, c in supported],
            )

    def test_no_claim_no_evidence_passes(self):
        unsupported, supported = self._scan(
            {"plain.py": _DET_NO_CLAIM_NO_EVIDENCE}
        )
        self.assertEqual(unsupported, [])
        self.assertEqual(supported, [])

    def test_claim_no_evidence_is_flagged(self):
        unsupported, supported = self._scan(
            {"bad.py": _DET_CLAIM_NO_EVIDENCE}
        )
        self.assertEqual(unsupported, ["bad.py"])
        self.assertEqual(supported, [])

    def test_claim_with_evidence_is_inventoried(self):
        unsupported, supported = self._scan(
            {"good.py": _DET_CLAIM_WITH_EVIDENCE}
        )
        self.assertEqual(unsupported, [])
        # Inventory tuple: (name, callgraph_relation_count). The
        # detector body has 1x high_level_calls + 1x internal_calls,
        # so the count must be at least 2.
        self.assertEqual(len(supported), 1)
        name, count = supported[0]
        self.assertEqual(name, "good.py")
        self.assertGreaterEqual(count, 2)

    def test_no_claim_with_evidence_is_silent(self):
        # A detector that uses the callgraph but does not claim
        # cross-contract semantics is fine — neither check fires.
        unsupported, supported = self._scan(
            {"silent.py": _DET_NO_CLAIM_WITH_EVIDENCE}
        )
        self.assertEqual(unsupported, [])
        self.assertEqual(supported, [])

    def test_full_matrix_in_one_folder(self):
        unsupported, supported = self._scan(
            {
                "plain.py": _DET_NO_CLAIM_NO_EVIDENCE,
                "bad.py": _DET_CLAIM_NO_EVIDENCE,
                "good.py": _DET_CLAIM_WITH_EVIDENCE,
                "silent.py": _DET_NO_CLAIM_WITH_EVIDENCE,
            }
        )
        self.assertEqual(unsupported, ["bad.py"])
        self.assertEqual([n for n, _ in supported], ["good.py"])


class RealCorpusSanityTest(unittest.TestCase):
    """The wave17 detector that pioneered the predicate-engine callgraph
    keys must surface under check 8b (DOES use callgraph), not 8."""

    def setUp(self):
        self.mod = _load_lint_module()

    def test_cross_contract_reentrancy_view_exposed_uses_callgraph(self):
        supported = self.mod.inter_contract_claim_with_callgraph()
        names = {p.name for p, _, _ in supported}
        # The wave17 detector that uses `function.has_high_level_call_named`
        # is the canonical callgraph user. If this disappears, either the
        # detector was removed (update the test) or the predicate-engine
        # key naming changed (update the evidence regex).
        self.assertIn(
            "cross_contract_reentrancy_view_exposed.py", names,
            f"expected the cross-contract reentrancy view-exposed detector "
            f"to surface as a callgraph user; got {sorted(names)}",
        )

    def test_check_strings_are_well_formed(self):
        # The check_* entrypoints used by main() must return list[str].
        unsupported = self.mod.check_inter_contract_claim_without_callgraph()
        supported = self.mod.check_inter_contract_callgraph_users()
        self.assertIsInstance(unsupported, list)
        self.assertIsInstance(supported, list)
        for s in unsupported + supported:
            self.assertIsInstance(s, str)


class FixturePresenceTest(unittest.TestCase):
    """The multi-contract fixture is the regression-pin for item #5."""

    def test_fixture_directory_exists(self):
        self.assertTrue(
            FIXTURE_DIR.is_dir(),
            f"expected fixture directory at {FIXTURE_DIR}",
        )

    def test_fixture_has_pool_vulnerable_clean_and_oracle(self):
        names = {p.name for p in FIXTURE_DIR.iterdir() if p.is_file()}
        for required in ("Pool_vulnerable.sol", "Pool_clean.sol", "Oracle.sol"):
            self.assertIn(
                required, names,
                f"fixture is missing {required}; got {sorted(names)}",
            )

    def test_oracle_reads_pool_view(self):
        # Sanity: the Oracle file must contain a cross-contract read so the
        # fixture actually exercises a callgraph edge.
        oracle = (FIXTURE_DIR / "Oracle.sol").read_text(encoding="utf-8")
        self.assertIn("pool.getReserves()", oracle)

    def test_pool_vulnerable_has_unguarded_view(self):
        vuln = (FIXTURE_DIR / "Pool_vulnerable.sol").read_text(encoding="utf-8")
        self.assertIn("getReserves", vuln)
        # Vulnerable pool MUST NOT carry a nonReentrantView modifier on the view.
        # (Clean pool does.)
        self.assertNotIn("nonReentrantView", vuln)

    def test_pool_clean_has_guarded_view(self):
        clean = (FIXTURE_DIR / "Pool_clean.sol").read_text(encoding="utf-8")
        self.assertIn("nonReentrantView", clean)


class CliFlagTest(unittest.TestCase):
    """The new flag is opt-in: default lint must pass when only this
    cohort fires."""

    def setUp(self):
        self.mod = _load_lint_module()

    def _stub_other_checks(self):
        """Silence every other check so we isolate the new flag."""
        self.mod.check_missing_fixtures = lambda: []
        self.mod.check_script_disk_mismatch = lambda: ([], [])
        self.mod.check_terse_docstrings = lambda: []
        self.mod.check_yaml_missing_fields = lambda: []
        self.mod.check_placeholder_fp_guards = lambda *args, **kwargs: []
        self.mod.check_high_tier_regex_only = lambda: []
        self.mod.check_parity_gaps = lambda: []
        self.mod.check_bad_wclass = lambda: []
        self.mod.check_function_kind_unknown = lambda: []
        self.mod.check_inter_contract_callgraph_users = lambda: []
        self.mod.check_invalid_backend = lambda: []

    def test_flag_is_opt_in(self):
        self._stub_other_checks()
        self.mod.check_inter_contract_claim_without_callgraph = (
            lambda: ["wave17/foo.py: claim without evidence"]
        )

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.mod.main([]), 0)
            self.assertEqual(
                self.mod.main(
                    ["--fail-inter-contract-claim-without-callgraph"]
                ),
                1,
            )

    def test_flag_passes_when_inventory_clean(self):
        self._stub_other_checks()
        self.mod.check_inter_contract_claim_without_callgraph = lambda: []

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                self.mod.main(
                    ["--fail-inter-contract-claim-without-callgraph"]
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
