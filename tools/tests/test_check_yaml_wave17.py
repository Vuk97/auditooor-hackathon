"""Regression test for V5-P0-17 / foot-gun #14: yaml-wave17-consistency wiring.

Worker-R wired 6 previously-missing wave17 .py companions on 2026-05-07
(loop after 3767f9e18). This test asserts that those YAML <-> wave17 .py
mates remain present so the missing-py bucket cannot silently regress past
the 15-pattern boundary on subsequent compiler / migration runs.

Companion documentation: ``docs/next-loop/yaml_wave17_wiring_2026-05-06.md``.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PATTERNS_DSL = REPO / "reference" / "patterns.dsl"
WAVE17 = REPO / "detectors" / "wave17"


# (kebab-pattern-id, expected-underscore-py-stem)
WIRED_BY_WORKER_R = [
    (
        "eip712-domain-separator-used-without-chainid-thus-introducing-cross-ch",
        "eip712_domain_separator_used_without_chainid_thus_introducing_cross_ch",
    ),
    (
        "erc4626-first-depositor-attack-share-price-manipulation",
        "erc4626_first_depositor_attack_share_price_manipulation",
    ),
    (
        "exploitable-missing-delegatecall-context-check-in-uups-module-upgrade",
        "exploitable_missing_delegatecall_context_check_in_uups_module_upgrade_",
    ),
    (
        "impossible-quorum-in-dao-governance",
        "impossible_quorum_in_dao_governance",
    ),
    (
        "inverted-signature-merkle-proofs-access-control-verification-passes-wh",
        "inverted_signature_merkle_proofs_access_control_verification_passes_wh",
    ),
    (
        "missing-zero-address-validation-in-constructor",
        "missing_zero_address_validation_in_constructor",
    ),
]


def _load_closeout_module():
    """Import tools/audit-closeout-check.py despite the dashed filename."""
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_check_under_test",
        REPO / "tools" / "audit-closeout-check.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WiredCompanionsStayWiredTest(unittest.TestCase):
    """The 6 wave17 .py files Worker-R generated must remain present."""

    def test_yaml_sources_exist(self) -> None:
        for kebab, _under in WIRED_BY_WORKER_R:
            yaml_path = PATTERNS_DSL / f"{kebab}.yaml"
            self.assertTrue(
                yaml_path.is_file(),
                f"YAML source-of-truth missing: {yaml_path}",
            )

    def test_wave17_companions_exist(self) -> None:
        for _kebab, under in WIRED_BY_WORKER_R:
            py_path = WAVE17 / f"{under}.py"
            self.assertTrue(
                py_path.is_file(),
                (
                    f"wave17 companion missing: {py_path}; "
                    "regenerate via "
                    "`python3 tools/pattern-compile.py "
                    f"reference/patterns.dsl/{_kebab}.yaml`"
                ),
            )

    def test_missing_py_bucket_has_not_regressed(self) -> None:
        """The 6 wired patterns must NOT appear in the closeout missing_py list."""
        m = _load_closeout_module()
        records = m._yaml_pattern_records(REPO)
        documentation_only = {
            n for n, r in records.items()
            if r.get("status") == "documentation-only"
        }
        yaml_under = set(records) - documentation_only
        wave17 = m._wave17_pattern_names(REPO)
        missing_py = yaml_under - wave17

        for _kebab, under in WIRED_BY_WORKER_R:
            self.assertNotIn(
                under,
                missing_py,
                (
                    f"{under} regressed into missing_py bucket; the "
                    "wave17 .py mate disappeared after Worker-R wired it"
                ),
            )


if __name__ == "__main__":
    unittest.main()
