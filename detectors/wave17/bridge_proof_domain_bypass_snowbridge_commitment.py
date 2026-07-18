"""
bridge-proof-domain-bypass-snowbridge-commitment

Fixture-smoke detector for Snowbridge-style BEEFY/MMR proof consumers that
accept a message commitment but verify the MMR leaf without visibly binding
that commitment through the parachain header digest and parachain header leaf.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_SNOWBRIDGE_PROOF_CONTEXT_RE = re.compile(
    r"\b(?:BEEFY|BeefyClient|MMR|MMRLeaf|leafProof|leafProofOrder|"
    r"parachain|headProof|encodedParaID|SubstrateMerkleProof|"
    r"parachainHeadsRoot|createMMRLeaf)\b",
    re.IGNORECASE,
)
_MMR_PROOF_RE = re.compile(
    r"\b(?:verifyMMRLeafProof|MMRProof\s*\.\s*verifyLeafProof|verifyLeafProof)\s*\(",
    re.IGNORECASE,
)
_MESSAGE_COMMITMENT_PARAM_RE = re.compile(
    r"\bbytes32\s+(?:messageCommitment|settlementCommitment|inboundCommitment|"
    r"commitment)\b",
    re.IGNORECASE,
)
_MESSAGE_COMMITMENT_USE_RE = re.compile(
    r"\b(?:messageCommitment|settlementCommitment|inboundCommitment|commitment)\b",
    re.IGNORECASE,
)

_HEADER_DIGEST_COMMITMENT_BINDING_RE = re.compile(
    r"\bisCommitmentInHeaderDigest\s*\("
    r"|(?:messageCommitment|settlementCommitment|inboundCommitment|commitment)\s*==\s*"
    r"bytes32\s*\([^;{}]*(?:digest|data\s*\[|header)"
    r"|bytes32\s*\([^;{}]*(?:digest|data\s*\[|header)[^;{}]*\)\s*==\s*"
    r"(?:messageCommitment|settlementCommitment|inboundCommitment|commitment)"
    r"|keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\([^;{}]*"
    r"(?:(?:messageCommitment|settlementCommitment|inboundCommitment|commitment)[^;{}]*"
    r"(?:encodedParaID|paraID|parachain|header|digest)"
    r"|(?:encodedParaID|paraID|parachain|header|digest)[^;{}]*"
    r"(?:messageCommitment|settlementCommitment|inboundCommitment|commitment))",
    re.IGNORECASE | re.DOTALL,
)

_PARACHAIN_HEADER_LEAF_BINDING_RE = re.compile(
    r"\bcreateParachainHeaderMerkleLeaf\s*\("
    r"|\bcreateParachainHeader\s*\("
    r"|\bSubstrateMerkleProof\s*\.\s*computeRoot\s*\([^;{}]*"
    r"(?:parachainHeadHash|createParachainHeaderMerkleLeaf|createParachainHeader)",
    re.IGNORECASE | re.DOTALL,
)

_BEEFY_SIGNED_COMMITMENT_SETTLEMENT_RE = re.compile(
    r"\bensureProvidesMMRRoot\s*\(\s*commitment\s*\)"
    r"|\bencodeCommitment\s*\(\s*commitment\s*\)"
    r"|\bcommitment\s*\.\s*(?:payload|validatorSetID|blockNumber)\b",
    re.IGNORECASE,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_snowbridge_commitment_bypass_shape(source: str) -> bool:
    if not _SNOWBRIDGE_PROOF_CONTEXT_RE.search(source):
        return False
    if not _MMR_PROOF_RE.search(source):
        return False
    if not _MESSAGE_COMMITMENT_PARAM_RE.search(source):
        return False
    if not _MESSAGE_COMMITMENT_USE_RE.search(source):
        return False

    # BeefyClient.submitFinal verifies a signed BEEFY commitment and extracts
    # the MMR root from that commitment. It is not the message-commitment path
    # this detector targets.
    if _BEEFY_SIGNED_COMMITMENT_SETTLEMENT_RE.search(source):
        return False

    has_header_commitment_binding = bool(_HEADER_DIGEST_COMMITMENT_BINDING_RE.search(source))
    has_parachain_leaf_binding = bool(_PARACHAIN_HEADER_LEAF_BINDING_RE.search(source))
    return not (has_header_commitment_binding and has_parachain_leaf_binding)


class BridgeProofDomainBypassSnowbridgeCommitment(AbstractDetector):
    ARGUMENT = "bridge-proof-domain-bypass-snowbridge-commitment"
    HELP = (
        "Snowbridge-style BEEFY/MMR proof verifier accepts a message commitment "
        "without visibly binding it through the parachain header digest and "
        "parachain header leaf"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "bridge-proof-domain-bypass-snowbridge-commitment.yaml"
    )
    WIKI_TITLE = "BEEFY/MMR bridge proof omits message commitment binding"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. Snowbridge's verifier first "
        "checks that the expected message commitment appears in the parachain "
        "header digest, then hashes the encoded parachain id and header into "
        "the parachain heads root before verifying the BEEFY MMR leaf. This "
        "detector flags BEEFY/MMR proof consumers that accept a bytes32 message "
        "commitment but verify an MMR leaf without both visible binding steps."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A bridge proof verifier receives a message commitment and a BEEFY MMR "
        "proof. It computes the MMR leaf from caller-supplied proof material "
        "and accepts verifyMMRLeafProof, but never proves the message "
        "commitment was in the parachain header digest that contributed to "
        "the verified parachain heads root. A proof for one settlement root "
        "can be paired with an unproven message commitment."
    )
    WIKI_RECOMMENDATION = (
        "Mirror the Snowbridge chain: require the commitment in the header "
        "digest, compute the parachain header merkle leaf from the encoded "
        "parachain id and header, compute the parachain heads root from that "
        "leaf, and only then verify the BEEFY MMR leaf."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _SNOWBRIDGE_PROOF_CONTEXT_RE.search(_source_of(contract)):
                continue

            for function in contract.functions_and_modifiers_declared:
                source = _source_of(function)
                if not source:
                    continue
                if not _has_snowbridge_commitment_bypass_shape(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " accepts a message commitment while the BEEFY/MMR proof "
                    "path lacks visible header-digest plus parachain-header "
                    "leaf binding for that commitment.\n",
                ]
                results.append(self.generate_result(info))

        return results
