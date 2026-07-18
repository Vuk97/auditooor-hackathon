"""Sibling test for tools/hackerman-etl-from-graph-protocol-sources.py.

CAP-D4 lane completion-audit test (was salvaged as a lone file with no
sibling test). Asserts the Rule 37 emit-time-tier contract and the
real-source-only / M14-trap discipline the miner's own docstring claims:

  * every emitted record carries a FIRST-CLASS ``verification_tier`` field
    (NOT smuggled into ``function_shape.shape_tags``);
  * the ``verification_tier`` value is one of the two tiers the miner
    documents (``tier-1-verified-realtime-api`` for GHSA-linked commits,
    ``tier-2-verified-public-archive`` otherwise);
  * the ``record_source_url`` / ``source_audit_ref`` resolve to a real
    GitHub commit URL whose SHA is taken verbatim from the injected
    ``gh api /commits/<sha>`` payload - never invented;
  * the 11 TG-PAT anchor SHAs are skipped (no double-seeding);
  * commits that touch no protocol source are skipped.

All tests run OFFLINE: ``commit_to_record`` is called directly with a
synthetic ``gh api /commits/<sha>`` detail payload and a fake GHSA lookup,
so no network access is required.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-graph-protocol-sources.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


# A synthetic `gh api /repos/<owner>/<repo>/commits/<sha>` detail payload.
# The SHA is NOT one of the 11 TG-PAT anchors and is clearly a test value.
_FAKE_SHA = "1234567890abcdef1234567890abcdef12345678"
_FAKE_PARENT = "fedcba0987654321fedcba0987654321fedcba09"


def _commit_detail(*, sha: str = _FAKE_SHA, message: str,
                    filename: str = "contracts/staking/Staking.sol",
                    patch: str = "@@ -1,3 +1,4 @@\n+    require(msg.sender == owner);\n"):
    return {
        "sha": sha,
        "parents": [{"sha": _FAKE_PARENT}],
        "commit": {
            "message": message,
            "author": {"date": "2024-06-01T12:00:00Z"},
            "committer": {"date": "2024-06-01T12:00:00Z"},
        },
        "files": [
            {
                "filename": filename,
                "additions": 4,
                "deletions": 1,
                "patch": patch,
            }
        ],
    }


class GraphProtocolEtlRule37Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_graph_protocol_sources")

    # -----------------------------------------------------------------
    # 1. Rule 37: verification_tier is a FIRST-CLASS field, never
    #    smuggled into function_shape.shape_tags.
    # -----------------------------------------------------------------
    def test_verification_tier_is_first_class(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/contracts",
            _commit_detail(message="Fix missing access-control guard on "
                                   "allocation state mutation"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNotNone(rec)
        self.assertIn("verification_tier", rec)
        self.assertNotIn(
            "verification_tier",
            rec["function_shape"]["shape_tags"],
            msg="verification_tier must NOT be smuggled into shape_tags",
        )

    # -----------------------------------------------------------------
    # 2. Rule 37: tier value is one of the two documented tiers; a
    #    non-GHSA commit defaults to tier-2.
    # -----------------------------------------------------------------
    def test_non_ghsa_commit_emits_tier_2(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/contracts",
            _commit_detail(message="Fix rounding error in rewards accounting"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["verification_tier"],
                         "tier-2-verified-public-archive")

    def test_ghsa_linked_commit_emits_tier_1(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/contracts",
            _commit_detail(message="Patch GHSA-aaaa-bbbb-cccc: dispute "
                                   "state-machine bypass"),
            ghsa_lookup=lambda repo, gid: {"ghsa_id": gid,
                                           "summary": "synthetic advisory"},
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["verification_tier"],
                         "tier-1-verified-realtime-api")

    # -----------------------------------------------------------------
    # 3. Real-source-only: the record_source_url / source_audit_ref
    #    resolve to a GitHub commit URL carrying the SHA verbatim from
    #    the injected payload (M14-trap: no invented SHA).
    # -----------------------------------------------------------------
    def test_source_url_carries_verbatim_sha(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/horizon",
            _commit_detail(message="Fix delegation accounting shape"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNotNone(rec)
        expected = f"https://github.com/graphprotocol/horizon/commit/{_FAKE_SHA}"
        self.assertEqual(rec["record_source_url"], expected)
        self.assertEqual(rec["source_audit_ref"], expected)
        self.assertIn(_FAKE_SHA, rec["record_id"])

    # -----------------------------------------------------------------
    # 4. TG-PAT anchor SHAs are skipped (no corpus double-seeding).
    # -----------------------------------------------------------------
    def test_tg_pat_anchor_sha_is_skipped(self) -> None:
        anchor = sorted(self.tool.TG_PAT_SKIP_SHAS)[0]
        rec = self.tool.commit_to_record(
            "graphprotocol/contracts",
            _commit_detail(sha=anchor + "0" * (40 - len(anchor)),
                           message="Fix access-control guard"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNone(rec, msg="TG-PAT anchor SHA must be skipped")

    # -----------------------------------------------------------------
    # 5. Commits touching no protocol source (.sol/.vy) are skipped.
    # -----------------------------------------------------------------
    def test_non_protocol_source_commit_is_skipped(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/contracts",
            _commit_detail(message="Update README docs",
                           filename="README.md"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNone(rec)

    # -----------------------------------------------------------------
    # 6. Emitted record carries the v1.1 hackerman schema version.
    # -----------------------------------------------------------------
    def test_record_uses_v11_schema(self) -> None:
        rec = self.tool.commit_to_record(
            "graphprotocol/issuance-allocator",
            _commit_detail(message="Fix issuance administration drift"),
            ghsa_lookup=lambda repo, gid: None,
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(rec["schema_version"],
                         "auditooor.hackerman_record.v1.1")


if __name__ == "__main__":
    unittest.main()
