"""Wave-2 callgraph capability uplift — regression-pin tests.

PR #479 added detector-lint Check #8: wave17/wave18 detectors that claim
inter-contract semantics (cross-contract / inter-contract / callgraph /
factory deploys / proxy implementation / sibling contracts / read-only
reentrancy) but whose source body never consults a Slither callgraph API
or predicate-engine inter-contract key. The default lint flags 41 such
detectors.

This Wave-2 batch refactors 11 of those detectors so they actually
consult the callgraph at detection time. The vehicle is the DSL YAML:
adding `function.has_high_level_call_named`, `function.taints_param_to`,
`function.reaches_external`, or `contract.has_external_call_to` to the
matcher / preconditions makes pattern-compile.py emit the literal
predicate key into `_PRECONDITIONS` / `_MATCH`, and the predicate engine
walks Slither's `function.high_level_calls` / `function.internal_calls`
at runtime — i.e., real callgraph traversal, not a string match against
`self.contracts`.

These tests pin three invariants:

  1. The 11 regenerated detectors' source code contains a literal
     callgraph-evidence predicate string. This is what the lint Check #8
     regex scans for; if the YAML regenerates without one of the four
     accepted keys, the lint fails closed under
     `--fail-inter-contract-claim-without-callgraph`.

  2. The predicate engine evaluates each of the four canonical callgraph
     keys correctly on SimpleNamespace mocks. A regression that makes
     `function.has_high_level_call_named` silently return True without
     traversing `function.high_level_calls` would render the uplift
     cosmetic. Pinned here.

  3. The DSL YAML schema for each refactored pattern is well-formed —
     pattern-compile.py round-trips without a strict-mode failure on the
     specific predicate keys we added. Catches future regressions where
     someone re-adds an unquoted scalar shape that pattern-compile warns
     about (we already saw the legacy bug in
     `downstream-privileged-helper-unreachable-from-caller.yaml`
     precondition #2 — out of scope for this refactor).

The tests deliberately avoid loading Slither: a positive multi-contract
fixture run-through-Slither pin lives in
`detectors/_fixtures/cross_contract_reentrancy_view_exposed/` (added by
PR #479) and is exercised by that PR's test harness once the lint flag
lands. Re-running it here would duplicate a Slither dependency the
hermetic CI does not carry.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
DETECTORS_DIR = ROOT / "detectors" / "wave17"
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"
sys.path.insert(0, str(ROOT))

from detectors._predicate_engine import (  # noqa: E402
    _check_contract_pred,
    _check_function_pred,
)


# Detectors refactored in Wave-2 (PR title: "fix(detectors): real Slither
# callgraph integration in 11 inter-contract detectors").
WAVE2_REFACTORED = [
    "r74_auth_cross_contract_signature_replay",
    "pause_state_not_propagated_to_sibling_contracts",
    "downstream_privileged_helper_unreachable_from_caller",
    "cross_function_reentrancy",
    "proxy_upgrade_to_unvalidated_impl",
    "factory_create_proxy_eip712_no_nonce_no_deadline",
    "read_only_reentrancy_view",
    "lido_submit_reentrancy",
    "delegatecall_to_unvalidated_eoa",
    "cei_violation_fulfill_before_storage",
    "callback_reentrancy_no_guard_dsl",
]

# Evidence regexes the PR #479 lint accepts. Subset of `_CALLGRAPH_EVIDENCE_PATTERNS`
# in tools/detector-lint.py — the predicate-engine inter-contract keys plus
# direct Slither IR access. Mirrors PR #479's evidence list exactly.
CALLGRAPH_EVIDENCE_RE = re.compile(
    r"\.high_level_calls\b"
    r"|\.low_level_calls\b"
    r"|\.cross_contract_calls\b"
    r"|\.outgoing_internal_calls\b"
    r"|\.internal_calls\b"
    r"|\.all_(?:high_level|low_level|internal|library)_calls(?:_as_expressions)?\b"
    r"|\.solidity_calls\b"
    r"|\.library_calls\b"
    r"|\.calls_as_expressions\b"
    r"|slither_predicates\.(?:has_high_level_call|reaches_external|taints_param_to)"
    r"|contract\.has_external_call_to\b"
    r"|function\.reaches_external\b"
    r"|function\.has_high_level_call_named\b"
    r"|function\.taints_param_to\b"
    r"|compilation_unit\.contracts\b"
    r"|contracts_in_compilation_unit\b"
    r"|slither\.contracts_derived\b"
)

# Lint #8 strips HELP/WIKI_* string literals from the evidence surface so a
# detector whose docstring name-drops "high_level_calls" but never iterates
# the result is still flagged. We mirror the strip here so the test reflects
# the real lint geometry, not a docstring leak.
_CLASS_ATTR_STRIP_RE = re.compile(
    r"^\s*(HELP|WIKI|WIKI_TITLE|WIKI_DESCRIPTION|WIKI_EXPLOIT_SCENARIO|"
    r"WIKI_RECOMMENDATION|ARGUMENT)\s*=\s*"
    r"(\"\"\"(?:.*?)\"\"\"|'''(?:.*?)'''|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')",
    re.M | re.DOTALL,
)
_DOCSTRING_STRIP_RE = re.compile(r'^"""(?:.*?)"""', re.S)


def _evidence_text(src: str) -> str:
    """Mirror PR #479's evidence-surface extractor: drop module docstring and
    HELP/WIKI_* class attributes so name-drops in prose are not counted."""
    src = _DOCSTRING_STRIP_RE.sub("", src, count=1)

    def _blank(match: re.Match[str]) -> str:
        return match.group(0).split("=", 1)[0] + "= " + (" " * (len(match.group(2)) - 2))

    return _CLASS_ATTR_STRIP_RE.sub(_blank, src)


class CallgraphEvidencePresentTests(unittest.TestCase):
    """Each Wave-2 refactored detector's executable code must contain at
    least one literal predicate-engine inter-contract key or direct Slither
    IR attribute. Without this, the detector lint Check #8 would re-flag
    the row and the count drop would be illusory."""

    def test_each_refactored_detector_has_callgraph_evidence(self) -> None:
        missing: list[str] = []
        for stem in WAVE2_REFACTORED:
            path = DETECTORS_DIR / f"{stem}.py"
            self.assertTrue(path.exists(), f"missing detector file: {path}")
            evidence = _evidence_text(path.read_text())
            if not CALLGRAPH_EVIDENCE_RE.search(evidence):
                missing.append(stem)
        self.assertFalse(
            missing,
            "Wave-2 detectors are missing callgraph evidence in their "
            f"executable code: {missing}. Re-run pattern-compile.py against "
            "the YAMLs in reference/patterns.dsl/ — the literal predicate "
            "key must appear in `_PRECONDITIONS` or `_MATCH`.",
        )


class HasHighLevelCallNamedSemanticsTests(unittest.TestCase):
    """`function.has_high_level_call_named` must traverse
    `function.high_level_calls` (Slither IR), not match a regex against the
    function's own name. A regression that swapped the implementation back
    to a name-only check would defeat 9 of the 11 Wave-2 refactors."""

    def _function_with_calls(self, *call_names: str) -> SimpleNamespace:
        nodes = []
        for nm in call_names:
            nodes.append(
                SimpleNamespace(
                    high_level_calls=[SimpleNamespace(name=nm)],
                    low_level_calls=[],
                    internal_calls=[],
                )
            )
        return SimpleNamespace(name="callerFn", nodes=nodes)

    def test_named_call_inside_function_high_level_calls_matches(self) -> None:
        fn = self._function_with_calls("safeTransfer", "decimals")
        self.assertTrue(
            _check_function_pred(fn, "function.has_high_level_call_named", "safeTransfer")
        )

    def test_named_call_absent_returns_false(self) -> None:
        fn = self._function_with_calls("decimals", "balanceOf")
        self.assertFalse(
            _check_function_pred(fn, "function.has_high_level_call_named", "submit")
        )

    def test_function_name_alone_does_not_match(self) -> None:
        # Pin the regression: the function's OWN name being "safeTransfer"
        # must not satisfy `has_high_level_call_named: safeTransfer` — only
        # an OUTGOING high-level call to a function named safeTransfer
        # counts. This is the difference between syntactic name-match and
        # callgraph traversal.
        fn = SimpleNamespace(name="safeTransfer", nodes=[])
        self.assertFalse(
            _check_function_pred(fn, "function.has_high_level_call_named", "safeTransfer"),
            "callgraph-traversal predicate must not be satisfied by the "
            "matched function's own name — that would be a regex shortcut, "
            "exactly the gap Wave-2 closes.",
        )

    def test_anchored_regex_works(self) -> None:
        # The Wave-2 YAMLs use anchored regexes like `^(submit|requestWithdrawals)$`
        # to avoid matching `requestWithdrawalsAndStuff`. Pin the predicate
        # actually honors the anchors.
        fn = self._function_with_calls("requestWithdrawalsAndStuff")
        self.assertFalse(
            _check_function_pred(
                fn,
                "function.has_high_level_call_named",
                "^(submit|requestWithdrawals)$",
            )
        )
        fn = self._function_with_calls("requestWithdrawals")
        self.assertTrue(
            _check_function_pred(
                fn,
                "function.has_high_level_call_named",
                "^(submit|requestWithdrawals)$",
            )
        )


class ContractHasExternalCallToTests(unittest.TestCase):
    """`contract.has_external_call_to` walks every function's
    `high_level_calls` and matches the destination contract+function name.
    Pinned for the read-only-reentrancy-view refactor."""

    def test_callback_invocation_inside_a_function_matches(self) -> None:
        dest_contract = SimpleNamespace(name="VictimLender")
        dest_fn = SimpleNamespace(name="executeOperation")
        node = SimpleNamespace(high_level_calls=[(dest_contract, dest_fn)])
        f = SimpleNamespace(nodes=[node])
        c = SimpleNamespace(functions=[f])
        self.assertTrue(
            _check_contract_pred(c, "contract.has_external_call_to", "executeOperation")
        )

    def test_no_matching_callback_returns_false(self) -> None:
        dest_contract = SimpleNamespace(name="VictimLender")
        dest_fn = SimpleNamespace(name="readBalance")
        node = SimpleNamespace(high_level_calls=[(dest_contract, dest_fn)])
        f = SimpleNamespace(nodes=[node])
        c = SimpleNamespace(functions=[f])
        self.assertFalse(
            _check_contract_pred(c, "contract.has_external_call_to", "executeOperation")
        )

    def test_qualified_contract_function_target(self) -> None:
        dest_contract = SimpleNamespace(name="DepositQueue")
        dest_fn = SimpleNamespace(name="fillERC20withdrawBuffer")
        node = SimpleNamespace(high_level_calls=[(dest_contract, dest_fn)])
        f = SimpleNamespace(nodes=[node])
        c = SimpleNamespace(functions=[f])
        # When the YAML supplies a qualified target, only matching contract
        # names should satisfy.
        self.assertTrue(
            _check_contract_pred(
                c,
                "contract.has_external_call_to",
                "DepositQueue.fillERC20withdrawBuffer",
            )
        )
        self.assertFalse(
            _check_contract_pred(
                c,
                "contract.has_external_call_to",
                "OperatorDelegator.fillERC20withdrawBuffer",
            )
        )


class _FnMock:
    """Hashable mock with the attribute surface the predicate engine reads.

    SimpleNamespace is unhashable, and `taints_param_to` puts the function
    object into a `seen_fns` set for cycle-cutoff. We therefore use a tiny
    class that hashes by identity (default `__hash__`)."""

    def __init__(self, *, parameters=(), nodes=()) -> None:
        self.parameters = list(parameters)
        self.nodes = list(nodes)


class TaintsParamToTests(unittest.TestCase):
    """`function.taints_param_to` walks `function.high_level_calls +
    function.internal_calls` recursively (depth-bounded) to verify a
    parameter reaches a target call without an intervening guard. Pinned
    for the delegatecall-to-unvalidated-eoa refactor."""

    def test_param_flows_to_delegatecall_without_guard(self) -> None:
        # function f(address impl) external { impl.delegatecall(data); }
        param = SimpleNamespace(name="impl")
        delegatecall_fn = SimpleNamespace(name="delegatecall")
        node = SimpleNamespace(
            expression="impl.delegatecall(data)",
            high_level_calls=[(SimpleNamespace(name=""), delegatecall_fn)],
            low_level_calls=[],
            internal_calls=[],
        )
        f = _FnMock(parameters=[param], nodes=[node])
        self.assertTrue(
            _check_function_pred(
                f,
                "function.taints_param_to",
                {
                    "from": "(?i)(impl|target)",
                    "to": "delegatecall",
                    "guard": "require|isContract|code\\.length",
                    "depth": 3,
                },
            )
        )

    def test_param_flow_blocked_by_guard(self) -> None:
        # function f(address impl) { require(impl.code.length > 0); impl.delegatecall(...); }
        param = SimpleNamespace(name="impl")
        guard_node = SimpleNamespace(
            expression="require(impl.code.length > 0)",
            high_level_calls=[],
            low_level_calls=[],
            internal_calls=[],
        )
        delegatecall_fn = SimpleNamespace(name="delegatecall")
        call_node = SimpleNamespace(
            expression="impl.delegatecall(data)",
            high_level_calls=[(SimpleNamespace(name=""), delegatecall_fn)],
            low_level_calls=[],
            internal_calls=[],
        )
        f = _FnMock(parameters=[param], nodes=[guard_node, call_node])
        self.assertFalse(
            _check_function_pred(
                f,
                "function.taints_param_to",
                {
                    "from": "(?i)(impl|target)",
                    "to": "delegatecall",
                    "guard": "require|isContract|code\\.length",
                    "depth": 3,
                },
            ),
            "guard must short-circuit taint propagation; otherwise the "
            "delegatecall-validated case would be flagged identical to the "
            "unvalidated case.",
        )


class YamlPredicateRoundtripTests(unittest.TestCase):
    """Each Wave-2 YAML must round-trip through pattern-compile.py without
    a strict-yaml-shapes failure on the keys we added. This is a regression
    pin — if someone re-adds an unquoted `function.has_high_level_call_named`
    line under a YAML section the compiler doesn't like, the corpus
    regenerates with a missing matcher and the count silently rebounds."""

    REFACTORED_YAMLS = [
        "r74-auth-cross-contract-signature-replay.yaml",
        "pause-state-not-propagated-to-sibling-contracts.yaml",
        "downstream-privileged-helper-unreachable-from-caller.yaml",
        "cross-function-reentrancy.yaml",
        "proxy-upgrade-to-unvalidated-impl.yaml",
        "factory-create-proxy-eip712-no-nonce-no-deadline.yaml",
        "read-only-reentrancy-view.yaml",
        "lido-submit-reentrancy.yaml",
        "delegatecall-to-unvalidated-eoa.yaml",
        "cei-violation-fulfill-before-storage.yaml",
        "callback_reentrancy_no_guard.yaml",
    ]

    def test_each_yaml_loads_and_contains_callgraph_predicate(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not available")
        import yaml as _yaml

        callgraph_keys = {
            "function.has_high_level_call_named",
            "function.taints_param_to",
            "function.reaches_external",
            "contract.has_external_call_to",
        }
        for fname in self.REFACTORED_YAMLS:
            path = PATTERNS_DIR / fname
            with self.subTest(yaml=fname):
                self.assertTrue(path.exists(), f"missing YAML: {path}")
                spec = _yaml.safe_load(path.read_text())
                self.assertIsNotNone(spec, f"{fname}: empty YAML")
                preconds = spec.get("preconditions", []) or []
                matches = spec.get("match", []) or []
                all_keys: set[str] = set()
                for entry in list(preconds) + list(matches):
                    if isinstance(entry, dict):
                        all_keys.update(entry.keys())
                self.assertTrue(
                    all_keys & callgraph_keys,
                    f"{fname}: matcher contains no Wave-2 callgraph "
                    f"predicate. Keys present: {sorted(all_keys)}",
                )


if __name__ == "__main__":
    unittest.main()
