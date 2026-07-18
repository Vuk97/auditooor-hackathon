"""
a-malicious-proposer-can-create-arbitrary-number-of-maliciously-

Local precision repair for the generated draft. The original wave15 skeleton
collapsed into a self-referential name/write/guard match on
`checkNoActiveProp`, which made the clean fixture fire unconditionally.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousProposerCanCreateArbitraryNumberOfMaliciously(AbstractDetector):
    ARGUMENT = "a-malicious-proposer-can-create-arbitrary-number-of-maliciously-"
    HELP = "A malicious proposer can create arbitrary number of maliciously updatable proposals to significantly grief the protocol"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "A malicious proposer can create arbitrary number of maliciously updatable proposals to significantly grief the protocol"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context\n- `NounsDAOV3Proposals.sol#L783-L798`\n- `NounsDAOV3Proposals.sol#L171`\n- `NounsDAOV3Proposals.sol#L818-L823`\n- `NounsDAOV3Proposals.sol#L269-L423`\n\n## Description\n`checkNoActiveProp()` is documented as: \n> \"This is a spam protection mechanism to limit the number"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #21324: ## Severity: Medium Risk\n\n## Context\n- `NounsDAOV3Proposals.sol#L783-L798`\n- `NounsDAOV3Proposals.sol#L171`\n- `NounsDAOV3Proposals.sol#L818-L823`\n- `NounsDAOV3Proposals.sol#L269-L423`\n\n## Description"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _CONTRACT_SOURCE_REGEX = re.compile(r"(updateProposal|updatable|updateable)", re.IGNORECASE)
    _FN_NAME_REGEX = re.compile(r"^checkNoActiveProp$", re.IGNORECASE)
    _READ_VAR_REGEX = re.compile(r"(latestProposal|proposalState|proposals)", re.IGNORECASE)
    _REQUIRED_BODY_REGEX = re.compile(r"\b(Pending|Active)\b", re.IGNORECASE)
    _FORBIDDEN_BODY_REGEX = re.compile(r"\b(Updatable|Updateable)\b", re.IGNORECASE)

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            contract_src = ""
            try:
                contract_src = c.source_mapping.content or ""
            except Exception:
                contract_src = ""
            if not self._CONTRACT_SOURCE_REGEX.search(contract_src):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._FN_NAME_REGEX.search(f.name):
                    continue

                reads_target = False
                for sv in f.state_variables_read:
                    if self._READ_VAR_REGEX.search(sv.name):
                        reads_target = True
                        break
                if not reads_target:
                    continue

                try:
                    src = f.source_mapping.content or ""
                except Exception:
                    src = ""
                if not self._REQUIRED_BODY_REGEX.search(src):
                    continue
                if self._FORBIDDEN_BODY_REGEX.search(src):
                    continue

                info = [
                    f,
                    " — a-malicious-proposer-can-create-arbitrary-number-of-maliciously-: ",
                    "active-proposal gate ignores the updatable proposal state. ",
                ]
                results.append(self.generate_result(info))
        return results
