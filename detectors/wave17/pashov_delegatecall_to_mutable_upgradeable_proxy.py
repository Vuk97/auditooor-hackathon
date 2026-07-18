"""
pashov-delegatecall-to-mutable-upgradeable-proxy

Narrow fixture-smoke detector for wrapper/vault contracts that expose a
public reward-claim entrypoint and forward it through `delegatecall` to an
owner-mutable rewards proxy address.

Submission posture: NOT_SUBMIT_READY. This row proves only the owned fixture
pair and does not establish corpus-backed exploit coverage.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_CONTEXT_RE = re.compile(
    r"(?is)\b(?:claimRewards|rewardsProxy|RewardsProxy|Wrapped|Wrapper|Vault)\b"
)
_ENTRYPOINT_RE = re.compile(r"(?i)^(?:claimRewards|claim|forwardRewards|delegateRewards)$")
_DELEGATECALL_RE = re.compile(
    r"(?is)(?:address\s*\(\s*)?_?rewardsProxy(?:\s*\))?\s*\.\s*delegatecall\s*\("
)
_MUTABLE_PROXY_SETTER_RE = re.compile(
    r"(?is)function\s+(?:set|update|change|configure)\w*RewardsProxy\w*\s*\([^)]*\)"
    r"[\s\S]{0,500}?(?:_?rewardsProxy\s*=|emit\s+RewardsProxyUpdated)"
)
_IMMUTABLE_PROXY_RE = re.compile(
    r"(?is)\b(?:immutable|constant)\b[^;=\n]*\b_?rewardsProxy\b|"
    r"\b_?rewardsProxy\b[^;=\n]*\b(?:immutable|constant)\b"
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PashovDelegatecallToMutableUpgradeableProxy(AbstractDetector):
    ARGUMENT = "pashov-delegatecall-to-mutable-upgradeable-proxy"
    HELP = (
        "Wrapper reward-claim entrypoint delegatecalls into an owner-mutable "
        "rewards proxy address"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "pashov-delegatecall-to-mutable-upgradeable-proxy.yaml"
    )
    WIKI_TITLE = "Wrapper delegatecalls into owner-mutable rewards proxy"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row flags the owned "
        "`claimRewards` wrapper shape where a public entrypoint "
        "delegatecalls into `_rewardsProxy` and the same contract also "
        "exposes a rewards-proxy setter. That proves only the standing "
        "arbitrary-code-execution surface of a mutable delegatecall target, "
        "so the row remains NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A wrapped vault stores `_rewardsProxy`, lets governance update that "
        "address via `setRewardsProxy`, and exposes public `claimRewards` "
        "that executes `_rewardsProxy.delegatecall(...)`. Once the proxy "
        "address is redirected to attacker-controlled code, any caller can "
        "trigger arbitrary storage writes and token transfers in the wrapper "
        "context."
    )
    WIKI_RECOMMENDATION = (
        "Prefer a plain `call` into a fixed rewards implementation, or harden "
        "the design so the delegated target is immutable and tightly scoped. "
        "Do not promote this row from fixture smoke alone."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not contract_source or not _CONTEXT_RE.search(contract_source):
                continue
            if not _MUTABLE_PROXY_SETTER_RE.search(contract_source):
                continue
            if _IMMUTABLE_PROXY_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not _ENTRYPOINT_RE.match(getattr(function, "name", "") or ""):
                    continue

                function_source = _source_of(function)
                if not function_source:
                    continue
                if not _DELEGATECALL_RE.search(function_source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    (
                        " delegatecalls reward claiming into a mutable "
                        "`_rewardsProxy` target set on the same contract. "
                        "NOT_SUBMIT_READY: fixture-smoke/source-shape proof "
                        "only.\n"
                    ),
                ]
                results.append(self.generate_result(info))

        return results
