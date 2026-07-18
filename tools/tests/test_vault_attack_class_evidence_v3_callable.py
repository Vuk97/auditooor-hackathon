"""Tests for Wave-2 W2.8 ``vault_attack_class_evidence_v3`` MCP callable.

v3 extends v2 with two opt-in flags:

- ``with_fixtures`` (default False): attach a per-record ``fixture`` block
  citing positive/negative fixture paths under
  ``reference/harness-fixture-kits/<lang>/<attack_class>/``.
- ``cross_language_neighbors`` (default False): return a
  ``cross_language_neighbors_records[]`` block listing similar
  attack-class records in OTHER languages via ``target_language``.

Spec: ``docs/WAVE2_W28_MCP_CALLABLE_EXTENSIONS_SPEC_2026-05-16.md`` section 3.

Cases (>=10):

1. v2-parity envelope shape - both flags default false.
2. Missing-attack-class returns degraded envelope.
3. Schema id is ``auditooor.vault_attack_class_evidence.v3``.
4. ``with_fixtures=true`` attaches a ``fixture`` block when a kit dir
   exists; non-null ``positive_fixture_path`` + ``kit_id`` +
   ``coverage_tag``.
5. ``with_fixtures=true`` returns ``fixture=null`` (NOT degraded) when
   the kit dir is absent for that language/class.
6. ``cross_language_neighbors=true`` returns neighbors in OTHER
   languages with ``language`` + ``target_language`` fields populated.
7. ``cross_language_neighbors=true`` returns empty neighbor list when
   the corpus has no records for the requested OTHER language - NOT
   degraded.
8. ``cross_language_neighbors=true`` without ``target_language`` is
   gracefully degraded (extension-level only; base call still
   returns).
9. ``cross_language_neighbors=true`` with unsupported ``target_language``
   is gracefully degraded.
10. Dispatch routing: ``VaultQuery.call("vault_attack_class_evidence_v3",
    args)`` returns the v3 schema.
11. v2 callable continues to work after v3 lands (regression guard).
12. ``neighbor_limit`` cap is honoured (clamped 1..20).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_v3_attack_class_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record_yaml(
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
    *,
    target_language: str = "go",
    target_domain: str = "consensus",
    target_repo: str = "owner/repo",
) -> str:
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"target_domain: {target_domain}\n"
        f"target_language: {target_language}\n"
        f"target_repo: {target_repo}\n"
        f"target_component: synthetic-{record_id}\n"
        "function_shape:\n"
        "  raw_signature: synthetic\n"
        "  shape_tags:\n"
        f"{tag_lines}\n"
        f"bug_class: {attack_class}\n"
        f"attack_class: {attack_class}\n"
        "attacker_role: unprivileged\n"
        "attacker_action_sequence: synthetic\n"
        "required_preconditions:\n"
        "  - synthetic\n"
        "impact_class: dos\n"
        "impact_actor: validator-set\n"
        "severity_at_finding: medium\n"
        "year: 2024\n"
        "record_tier: public-corpus\n"
        "record_quality_score: 3.0\n"
        "source_extraction_method: synthetic-test\n"
        "source_extraction_confidence: 0.9\n"
    )


class _V3CorpusFixture:
    """Helper to build a synthetic hackerman corpus on disk."""

    def __init__(self, tmpdir: Path) -> None:
        self.root = tmpdir
        self.tags_dir = (
            tmpdir / "audit" / "corpus_tags" / "tags" / "synthetic"
        )
        self.tags_dir.mkdir(parents=True)
        self.index_dir = tmpdir / "audit" / "corpus_tags" / "index"
        self.index_dir.mkdir(parents=True)
        self.derived_dir = tmpdir / "audit" / "corpus_tags" / "derived"
        self.derived_dir.mkdir(parents=True)
        (tmpdir / "obsidian-vault").mkdir()
        self.vault = vault_mcp_server.VaultQuery(
            tmpdir / "obsidian-vault", tmpdir
        )
        # Empty sidecars - optional.
        (self.derived_dir / "record_quality.jsonl").write_text(
            "", encoding="utf-8"
        )
        (self.derived_dir / "proof_hardening.jsonl").write_text(
            "", encoding="utf-8"
        )

    def add_record(
        self,
        record_id: str,
        attack_class: str,
        shape_tags: list[str],
        *,
        target_language: str = "rust",
    ) -> None:
        yaml_path = self.tags_dir / f"{record_id}.yaml"
        yaml_path.write_text(
            _record_yaml(
                record_id,
                attack_class,
                shape_tags,
                target_language=target_language,
            ),
            encoding="utf-8",
        )
        row = {
            "attack_class": attack_class,
            "bug_class": attack_class,
            "key": attack_class,
            "record_id": record_id,
            "severity_at_finding": "medium",
            "source_audit_ref": f"synthetic:{record_id}",
            "tag_file": str(yaml_path),
            "target_domain": "consensus",
            "target_language": target_language,
            "target_repo": "owner/repo",
            "year": 2024,
        }
        path = self.index_dir / "by_attack_class.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    def base_kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "attack_class": "reentrancy-class",
            "index_dir": str(self.index_dir),
            "tags_dir": str(self.tags_dir.parent),
            "quality_sidecar": str(
                self.derived_dir / "record_quality.jsonl"
            ),
            "proof_hardening_sidecar": str(
                self.derived_dir / "proof_hardening.jsonl"
            ),
        }
        base.update(overrides)
        return base


class AttackClassEvidenceV3DegradedAndShapeTests(unittest.TestCase):
    """Envelope shape, degraded path, schema-id, dispatch routing."""

    def test_missing_attack_class_returns_degraded_envelope(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            result = fx.vault.vault_attack_class_evidence_v3(
                attack_class=""
            )
        self.assertEqual(
            result["schema"],
            vault_mcp_server.ATTACK_CLASS_EVIDENCE_V3_SCHEMA,
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "missing_attack_class")
        self.assertEqual(result["records"], [])
        self.assertEqual(result["cross_language_neighbors_records"], [])
        self.assertIn("degraded_extensions", result)

    def test_schema_id_and_context_pack_envelope(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-tier1-rust",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs()
            )
        self.assertEqual(
            result["schema"],
            vault_mcp_server.ATTACK_CLASS_EVIDENCE_V3_SCHEMA,
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.ATTACK_CLASS_EVIDENCE_V3_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        # Both flags default false; degraded_extensions present + false.
        self.assertEqual(
            result["degraded_extensions"],
            {"with_fixtures": False, "cross_language_neighbors": False},
        )
        self.assertIn("records", result)
        self.assertIn("by_tier", result)
        self.assertIn("cross_language_neighbors_records", result)

    def test_v2_parity_when_flags_off(self) -> None:
        """With both new flags off, records[] mirrors v2 shape."""
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-tier1-rust",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            fx.add_record(
                "rec-tier2-rust",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-2-verified-public-archive",
                ],
                target_language="rust",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs()
            )
        for rec in result["records"]:
            # No `fixture` key should be attached when with_fixtures=False.
            self.assertNotIn("fixture", rec)
        self.assertEqual(result["cross_language_neighbors_records"], [])

    def test_dispatch_routing_returns_v3_schema(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            result = fx.vault.call(
                "vault_attack_class_evidence_v3",
                {"attack_class": ""},
            )
        self.assertEqual(
            result["schema"],
            vault_mcp_server.ATTACK_CLASS_EVIDENCE_V3_SCHEMA,
        )

    def test_v2_still_callable_after_v3_lands(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            result = fx.vault.vault_attack_class_evidence_v2(
                attack_class=""
            )
        self.assertEqual(
            result["schema"],
            vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA,
        )
        self.assertTrue(result["degraded"])


class AttackClassEvidenceV3FixtureFlagTests(unittest.TestCase):
    """Tests for ``with_fixtures=true`` per-record attachment."""

    def test_fixture_attached_when_kit_present(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-tier1-rust",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            # Lay down a fixture kit on disk:
            #   reference/harness-fixture-kits/rust/reentrancy-class/
            kit_root = (
                Path(td)
                / "reference"
                / "harness-fixture-kits"
                / "rust"
                / "reentrancy-class"
            )
            kit_root.mkdir(parents=True)
            (kit_root / "positive.rs").write_text("// positive\n")
            (kit_root / "negative.rs").write_text("// negative\n")

            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(with_fixtures=True)
            )
        self.assertFalse(result["degraded"])
        self.assertEqual(
            result["degraded_extensions"]["with_fixtures"], False
        )
        rec = result["records"][0]
        self.assertIn("fixture", rec)
        fx_block = rec["fixture"]
        self.assertIsNotNone(fx_block)
        self.assertTrue(
            fx_block["positive_fixture_path"].endswith(
                "reference/harness-fixture-kits/rust/reentrancy-class/positive.rs"
            )
        )
        self.assertTrue(
            fx_block["negative_fixture_path"].endswith(
                "reference/harness-fixture-kits/rust/reentrancy-class/negative.rs"
            )
        )
        self.assertEqual(fx_block["kit_id"], "rust.reentrancy-class.v1")
        self.assertEqual(fx_block["coverage_tag"], "cargo_test")

    def test_fixture_null_when_kit_missing_no_degrade(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-rust-orphan",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            # Root exists but no per-class subdir for reentrancy-class.
            (
                Path(td) / "reference" / "harness-fixture-kits"
            ).mkdir(parents=True)
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(with_fixtures=True)
            )
        self.assertEqual(
            result["degraded_extensions"]["with_fixtures"], False
        )
        rec = result["records"][0]
        self.assertIn("fixture", rec)
        self.assertIsNone(rec["fixture"])


class AttackClassEvidenceV3CrossLanguageTests(unittest.TestCase):
    """Tests for ``cross_language_neighbors=true``."""

    def test_neighbors_present_when_corpus_has_other_languages(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            # Primary-language record:
            fx.add_record(
                "rec-rust-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            # Neighbor-language records (solidity + move):
            fx.add_record(
                "rec-sol-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="solidity",
            )
            fx.add_record(
                "rec-move-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-2-verified-public-archive",
                ],
                target_language="move",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(
                    cross_language_neighbors=True,
                    target_language="rust",
                    neighbor_limit=5,
                )
            )
        self.assertFalse(result["degraded"])
        self.assertEqual(
            result["degraded_extensions"][
                "cross_language_neighbors"
            ],
            False,
        )
        neighbor_ids = [
            r.get("record_id")
            for r in result["cross_language_neighbors_records"]
        ]
        self.assertIn("rec-sol-1", neighbor_ids)
        self.assertIn("rec-move-1", neighbor_ids)
        self.assertNotIn("rec-rust-1", neighbor_ids)
        # Tier-1 (sol) ranked before tier-2 (move).
        self.assertEqual(neighbor_ids[0], "rec-sol-1")
        # Each neighbor carries language + target_language fields.
        for n in result["cross_language_neighbors_records"]:
            self.assertIn(n["language"], {"solidity", "move"})
            self.assertEqual(n["target_language"], "rust")

    def test_neighbors_empty_when_no_records_for_other_languages(
        self,
    ) -> None:
        """When EVERY record is in target_language (no records in OTHER
        languages), the neighbor list is empty and the call is NOT
        degraded - per spec section 3.6 case 6.
        """
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            # ALL records share target_language=move so move-targeted
            # neighbor walk returns no OTHER-language rows.
            fx.add_record(
                "rec-move-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="move",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(
                    cross_language_neighbors=True,
                    target_language="move",
                )
            )
        self.assertFalse(result["degraded"])
        # Empty list is NOT a degrade per spec section 3.6 case 6.
        self.assertEqual(
            result["degraded_extensions"][
                "cross_language_neighbors"
            ],
            False,
        )
        self.assertEqual(
            result["cross_language_neighbors_records"], []
        )

    def test_neighbors_requires_target_language(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-rust-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(cross_language_neighbors=True)
            )
        # Base call still returns; extension surfaces a degraded reason.
        self.assertFalse(result["degraded"])
        self.assertEqual(
            result["degraded_extensions"][
                "cross_language_neighbors"
            ],
            "cross_language_neighbors_requires_target_language",
        )
        self.assertEqual(
            result["cross_language_neighbors_records"], []
        )

    def test_neighbors_unsupported_target_language(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-rust-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(
                    cross_language_neighbors=True,
                    target_language="malbolge",
                )
            )
        self.assertFalse(result["degraded"])
        deg = result["degraded_extensions"]["cross_language_neighbors"]
        self.assertTrue(
            isinstance(deg, str)
            and deg.startswith("unsupported_target_language")
        )

    def test_neighbor_limit_clamped(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            fx.add_record(
                "rec-rust-1",
                "reentrancy-class",
                [
                    "foo",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
                target_language="rust",
            )
            for i in range(8):
                fx.add_record(
                    f"rec-sol-{i}",
                    "reentrancy-class",
                    [
                        "foo",
                        "verification_tier:tier-1-verified-realtime-api",
                    ],
                    target_language="solidity",
                )
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(
                    cross_language_neighbors=True,
                    target_language="rust",
                    neighbor_limit=3,
                )
            )
        self.assertLessEqual(
            len(result["cross_language_neighbors_records"]), 3
        )

    def test_neighbor_limit_out_of_range_clamped_to_max(self) -> None:
        """neighbor_limit=999 should clamp to MAX=20."""
        with tempfile.TemporaryDirectory(
            prefix="aud-mcp-v3-ac-"
        ) as td:
            fx = _V3CorpusFixture(Path(td))
            result = fx.vault.vault_attack_class_evidence_v3(
                **fx.base_kwargs(
                    cross_language_neighbors=True,
                    target_language="rust",
                    neighbor_limit=999,
                )
            )
        self.assertEqual(result["neighbor_limit"], 20)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
