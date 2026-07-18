"""
vote-power-stale-source-double-count

Generalized detector for vote source reassignment bugs where a function reads an
old delegate/source, credits the new delegate/source, and does not debit or
remove the old source before that credit. NOT_SUBMIT_READY.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_CONTEXT_RE = re.compile(
    r"(?i)(vote|voting|govern|proposal|ballot|quorum|checkpoint|delegate|delegat)"
)

_SOURCE_UPDATE_FN_RE = re.compile(
    r"(?i)(delegate|delegat|redelegate|representative|votesource|vote_source|"
    r"setdelegate|set_delegate|changedelegate|change_delegate|moveDelegation|"
    r"move_delegation|assignDelegate|assign_delegate|updateDelegate|"
    r"update_delegate|updateValidator|changeBalance|reassign|revote)"
)

_OLD_SOURCE_RE = re.compile(
    r"(?i)\b(oldDelegate|olddelegate|currentDelegate|currentdelegate|"
    r"previousDelegate|previousdelegate|priorDelegate|priordelegate|"
    r"existingDelegate|existingdelegate|fromDelegate|fromdelegate|"
    r"oldSource|oldsource|currentSource|currentsource|previousSource|"
    r"previoussource)\b"
)

_OLD_SOURCE_LOOKUP_RE = re.compile(
    r"(?i)(delegateOf|delegates|delegatedTo|representativeOf|sourceOf|"
    r"delegateOfSource|sourceDelegate|voteDelegate|delegateSource|voteSource)"
    r"\s*\[[^\]]+\]"
)

_NEW_SOURCE_NAME = (
    r"(?:newDelegate|newdelegate|delegatee|toDelegate|todelegate|toTokenId|"
    r"to|newSource|newsource|representative|newRep|newrep|targetDelegate|"
    r"targetdelegate)"
)

_SOURCE_ASSIGN_RE = re.compile(
    rf"(?is)(delegateOf|delegates|delegatedTo|representativeOf|sourceOf|"
    rf"delegateOfSource|sourceDelegate|voteDelegate|delegateSource|voteSource)"
    rf"\s*\[[^\]]+\]\s*=\s*{_NEW_SOURCE_NAME}\b"
)

_CREDIT_PATTERNS = [
    re.compile(
        rf"(?is)(?:delegate|delegated|delegation|vote|voting|checkpoint|source)"
        rf"[\w]*\s*\[\s*{_NEW_SOURCE_NAME}\b[^\]]*\]\s*\.push\s*\("
    ),
    re.compile(
        rf"(?is)(?:delegatedVotes|delegateVotes|delegateVotePower|delegatedPower|"
        rf"votingPower|votePower|votingWeight|voteWeight|delegateWeight|"
        rf"checkpointVotes|checkpoints|votes)\s*\[\s*{_NEW_SOURCE_NAME}\b[^\]]*\]"
        rf"\s*(?:\+=|=\s*[^;\n]*\+|=\s*[^;\n]*(?:add|safeAdd)\s*\()"
    ),
    re.compile(
        rf"(?is)(?:delegatedSources|delegateSources|delegatedTokenIds|"
        rf"voteSources|sourceIds|checkpointSources)\s*\[\s*{_NEW_SOURCE_NAME}\b"
        rf"[^\]]*\]\s*\.push\s*\("
    ),
]

_DEBIT_OR_REMOVE_RE = re.compile(
    r"(?is)("
    r"(?:delegatedVotes|delegateVotes|delegateVotePower|delegatedPower|votingPower|"
    r"votePower|votingWeight|voteWeight|delegateWeight|checkpointVotes|checkpoints|votes)"
    r"\s*\[\s*(?:oldDelegate|olddelegate|currentDelegate|currentdelegate|"
    r"previousDelegate|previousdelegate|priorDelegate|priordelegate|existingDelegate|"
    r"existingdelegate|fromDelegate|fromdelegate|oldSource|oldsource|currentSource|"
    r"currentsource|previousSource|previoussource)\s*\]\s*(?:-=|=\s*[^;\n]*-)"
    r"|(?:_removeDelegation|removeDelegation|clearOldDelegate|detachDelegate|"
    r"deleteOldDelegate|removeFromOldDelegate|_debitDelegate|debitDelegate|"
    r"_debitSource|debitSource|_moveDelegateVotes|moveDelegateVotes|"
    r"_moveVotingPower|moveVotingPower|_transferVotingUnits)"
    r"\s*\("
    r"|(?:delegatedSources|delegateSources|delegatedTokenIds|voteSources|sourceIds|"
    r"checkpointSources)\s*\[\s*(?:oldDelegate|olddelegate|currentDelegate|"
    r"currentdelegate|previousDelegate|previousdelegate|fromDelegate|fromdelegate|"
    r"oldSource|oldsource|currentSource|currentsource|previousSource|previoussource)"
    r"\s*\][^;]*(?:pop\s*\(|remove\s*\(|swapAndPop\s*\(|swap\s+and\s+pop|"
    r"delete|retain\s*\()"
    r")"
)


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        if "\n" in text:
            return "\n" * text.count("\n")
        return " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _function_source(function) -> str:
    try:
        return function.source_mapping.content or ""
    except Exception:
        return ""


def _contract_source(contract) -> str:
    try:
        return contract.source_mapping.content or ""
    except Exception:
        return ""


def _first_credit(source: str) -> re.Match[str] | None:
    matches = []
    for pattern in _CREDIT_PATTERNS:
        match = pattern.search(source)
        if match:
            matches.append(match)
    if not matches:
        return None
    return min(matches, key=lambda item: item.start())


def _has_old_source_read(source: str) -> bool:
    return bool(_OLD_SOURCE_RE.search(source) and _OLD_SOURCE_LOOKUP_RE.search(source))


def _has_debit_before_credit(source: str, credit_start: int) -> bool:
    return bool(_DEBIT_OR_REMOVE_RE.search(source[:credit_start]))


class VotePowerStaleSourceDoubleCount(AbstractDetector):
    ARGUMENT = "vote-power-stale-source-double-count"
    HELP = "Vote source reassignment credits a new source without first clearing or debiting the stale source"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Vote source reassignment can double-count stale voting power"
    WIKI_DESCRIPTION = (
        "Delegation and vote accounting paths must move a voting unit from the "
        "old delegate/source to the new one atomically. A function that reads "
        "the old source and credits the new source without an old-source debit "
        "or removal can leave both paths live."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A voter reassigns one voting unit across delegates. The new delegate "
        "receives the unit, while the old delegate list or vote-power ledger "
        "still retains it. Later tallying can count the same source through "
        "both delegates."
    )
    WIKI_RECOMMENDATION = (
        "Debit or remove the old delegate/source before crediting the new "
        "delegate/source, preferably through one canonical move helper."
    )

    _INCLUDE_LEAF_HELPERS = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _strip_comments_and_strings(_contract_source(contract))
            if not _CONTEXT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                name = getattr(function, "name", "") or ""
                if not _SOURCE_UPDATE_FN_RE.search(name):
                    continue
                source = _strip_comments_and_strings(_function_source(function))
                if not _has_old_source_read(source):
                    continue
                if not _SOURCE_ASSIGN_RE.search(source):
                    continue
                credit = _first_credit(source)
                if credit is None:
                    continue
                if _has_debit_before_credit(source, credit.start()):
                    continue
                info = [
                    function,
                    (
                        " vote-power-stale-source-double-count: new vote source "
                        "is credited before the stale source is debited or "
                        "removed. See WIKI for details."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
