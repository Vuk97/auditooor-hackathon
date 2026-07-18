"""Tests for tools/wave2-w21-post-migration-validator.py.

Synthetic fixtures only. Every YAML written here carries the
``synthetic_fixture: true`` field per real-source-only discipline so the
records are unambiguously NOT corpus material.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-w21-post-migration-validator.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_w21_post_migration_validator", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


VALIDATOR = _load_module()


# --------------------------------------------------------------------------- #
# Fixture helpers
# --------------------------------------------------------------------------- #


def _v1_1_record_yaml(
    record_id: str,
    *,
    schema_version: str = "auditooor.hackerman_record.v1.1",
    verification_tier: str = "tier-2-verified-public-archive",
    attack_class: str = "reentrancy-attack",
    target_repo: str = "synthetic/repo",
    include_shape_tag_tier: bool = True,
) -> str:
    shape_tag_lines = []
    if include_shape_tag_tier:
        shape_tag_lines.append(f"    - verification_tier:{verification_tier}")
    body = [
        f"schema_version: {schema_version}",
        f"record_id: {record_id}",
        f"verification_tier: {verification_tier}",
        f"attack_class: {attack_class}",
        f"target_repo: {target_repo}",
        "synthetic_fixture: true",
        "function_shape:",
        '  raw_signature: "function f()"',
        "  shape_tags:",
        "    - reentrancy",
        *shape_tag_lines,
        "",
    ]
    return "\n".join(body)


def _v1_record_yaml(record_id: str) -> str:
    return "\n".join(
        [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
            "attack_class: reentrancy-attack",
            "target_repo: synthetic/repo",
            "synthetic_fixture: true",
            "function_shape:",
            '  raw_signature: "function f()"',
            "  shape_tags:",
            "    - reentrancy",
            "    - verification_tier:tier-2-verified-public-archive",
            "",
        ]
    )


def _write_workspace(root: Path) -> Path:
    tags_dir = root / "audit" / "corpus_tags" / "tags"
    index_dir = root / "audit" / "corpus_tags" / "index"
    tags_dir.mkdir(parents=True, exist_ok=True)
    index_dir.mkdir(parents=True, exist_ok=True)
    return tags_dir


def _write_indexes(
    root: Path,
    *,
    by_cve_id_lines=(),
    by_ghsa_id_lines=(),
    by_firm_lines=(),
    by_verification_tier_lines=(),
    by_incident_date_lines=(),
) -> None:
    index_dir = root / "audit" / "corpus_tags" / "index"
    index_dir.mkdir(parents=True, exist_ok=True)
    pairs = [
        ("by_cve_id.jsonl", by_cve_id_lines),
        ("by_ghsa_id.jsonl", by_ghsa_id_lines),
        ("by_firm.jsonl", by_firm_lines),
        ("by_verification_tier.jsonl", by_verification_tier_lines),
        ("by_incident_date.jsonl", by_incident_date_lines),
    ]
    for name, lines in pairs:
        path = index_dir / name
        with path.open("w", encoding="utf-8") as fh:
            for row in lines:
                if isinstance(row, dict):
                    fh.write(json.dumps(row, sort_keys=True))
                else:
                    fh.write(row)
                fh.write("\n")


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


class AllV11PassTest(unittest.TestCase):
    """Case (a): all-v1.1-PASS synthetic fixture."""

    def test_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            (tags_dir / "rec_a.yaml").write_text(
                _v1_1_record_yaml("synthetic:rec_a"),
                encoding="utf-8",
            )
            (tags_dir / "rec_b.yaml").write_text(
                _v1_1_record_yaml(
                    "synthetic:rec_b",
                    verification_tier="tier-3-synthetic-taxonomy-anchored",
                ),
                encoding="utf-8",
            )
            _write_indexes(
                root,
                by_cve_id_lines=[{"record_id": "synthetic:rec_a", "key": "CVE-2099-0001", "tag_file": "rec_a.yaml"}],
                by_ghsa_id_lines=[{"record_id": "synthetic:rec_b", "key": "GHSA-xxxx-yyyy-zzzz", "tag_file": "rec_b.yaml"}],
                by_firm_lines=[{"record_id": "synthetic:rec_a", "key": "synthetic-firm", "tag_file": "rec_a.yaml"}],
                by_verification_tier_lines=[
                    {"record_id": "synthetic:rec_a", "key": "tier-2-verified-public-archive", "tag_file": "rec_a.yaml"},
                    {"record_id": "synthetic:rec_b", "key": "tier-3-synthetic-taxonomy-anchored", "tag_file": "rec_b.yaml"},
                ],
                by_incident_date_lines=[
                    {"record_id": "synthetic:rec_a", "key": "2024-01-01", "tag_file": "rec_a.yaml"},
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "PASS", payload)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["v1_record_count"], 0)
            self.assertEqual(payload["v1_1_record_count"], 2)
            self.assertEqual(payload["verification_tier_populated"], 2)
            self.assertEqual(payload["verification_tier_missing"], 0)
            self.assertEqual(payload["index_health"]["by_cve_id"]["status"], "OK")
            self.assertEqual(payload["quarantine_leak_check"]["status"], "OK")


class MixedV1V11FailTest(unittest.TestCase):
    """Case (b): mixed v1 + v1.1 records → migration incomplete → FAIL."""

    def test_v1_remnant_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            (tags_dir / "rec_a.yaml").write_text(
                _v1_1_record_yaml("synthetic:rec_a"),
                encoding="utf-8",
            )
            (tags_dir / "rec_b.yaml").write_text(
                _v1_record_yaml("synthetic:rec_b_stale_v1"),
                encoding="utf-8",
            )
            _write_indexes(
                root,
                by_verification_tier_lines=[
                    {"record_id": "synthetic:rec_a", "key": "tier-2-verified-public-archive", "tag_file": "rec_a.yaml"},
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "FAIL", payload)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["v1_record_count"], 1)
            self.assertEqual(payload["v1_1_record_count"], 1)
            self.assertTrue(
                any("still at v1" in f for f in payload["failures"]),
                payload["failures"],
            )


class QuarantineLeakFailTest(unittest.TestCase):
    """Case (c): quarantine record_id leaks into by_cve_id.jsonl → FAIL."""

    def test_quarantine_leak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            quarantine_dir = tags_dir / "_QUARANTINE_FABRICATED_CVE" / "vyper_fab"
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            (tags_dir / "rec_clean.yaml").write_text(
                _v1_1_record_yaml("synthetic:rec_clean"),
                encoding="utf-8",
            )
            quarantine_yaml = quarantine_dir / "fab_record.yaml"
            quarantine_yaml.write_text(
                "\n".join(
                    [
                        "schema_version: auditooor.hackerman_record.v1.1",
                        "record_id: synthetic-quarantine:fab_vyper_cve",
                        "verification_tier: tier-5-quarantine",
                        "attack_class: fabricated",
                        "target_repo: quarantine/fab",
                        "synthetic_fixture: true",
                        "function_shape:",
                        '  raw_signature: "function fab()"',
                        "  shape_tags:",
                        "    - verification_tier:tier-5-quarantine",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            _write_indexes(
                root,
                by_cve_id_lines=[
                    {
                        "record_id": "synthetic-quarantine:fab_vyper_cve",
                        "key": "CVE-2099-9999",
                        "tag_file": "_QUARANTINE_FABRICATED_CVE/vyper_fab/fab_record.yaml",
                    },
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "FAIL", payload)
            self.assertEqual(rc, 1)
            leak = payload["quarantine_leak_check"]
            self.assertEqual(leak["status"], "FAIL")
            self.assertEqual(leak["by_cve_id_leak_count"], 1)
            self.assertEqual(
                leak["by_cve_id_leaks"][0]["record_id"],
                "synthetic-quarantine:fab_vyper_cve",
            )


class MissingVerificationTierFailTest(unittest.TestCase):
    """Case (d): v1.1 record without the v1.1 top-level verification_tier
    field → FAIL with `verification_tier_missing` accounted."""

    def test_missing_tier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            # Record at v1.1 schema but lacking the top-level field. The
            # legacy shape_tag value is intentionally absent so the failure
            # is unambiguous.
            yaml_text = "\n".join(
                [
                    "schema_version: auditooor.hackerman_record.v1.1",
                    "record_id: synthetic:rec_no_tier",
                    "attack_class: reentrancy-attack",
                    "target_repo: synthetic/repo",
                    "synthetic_fixture: true",
                    "function_shape:",
                    '  raw_signature: "function g()"',
                    "  shape_tags:",
                    "    - reentrancy",
                    "",
                ]
            )
            (tags_dir / "rec_no_tier.yaml").write_text(yaml_text, encoding="utf-8")
            _write_indexes(root)
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "FAIL", payload)
            self.assertEqual(rc, 1)
            self.assertEqual(payload["verification_tier_missing"], 1)
            self.assertTrue(
                any(
                    "missing verification_tier" in f for f in payload["failures"]
                ),
                payload["failures"],
            )
            self.assertTrue(
                any(
                    s.get("verdict") == "missing-verification-tier"
                    for s in payload["sample_failed_records"]
                ),
                payload["sample_failed_records"],
            )


class TierTaxonomyAcceptanceTest(unittest.TestCase):
    """Bonus: ``no_tier`` sentinel is acceptable; arbitrary string is not."""

    def test_no_tier_sentinel_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            (tags_dir / "rec.yaml").write_text(
                _v1_1_record_yaml(
                    "synthetic:rec_no_tier",
                    verification_tier="no_tier",
                    include_shape_tag_tier=False,
                ),
                encoding="utf-8",
            )
            _write_indexes(root)
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "PASS", payload)
            self.assertEqual(payload["verification_tier_populated"], 1)
            self.assertEqual(payload["verification_tier_missing"], 0)

    def test_garbage_tier_value_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            (tags_dir / "rec.yaml").write_text(
                _v1_1_record_yaml(
                    "synthetic:rec_bad",
                    verification_tier="not-a-real-tier",
                    include_shape_tag_tier=False,
                ),
                encoding="utf-8",
            )
            _write_indexes(root)
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "FAIL", payload)
            self.assertEqual(payload["verification_tier_invalid_value"], 1)


class TagsDirOverrideTest(unittest.TestCase):
    """Wave-2 PR-A cap-gap #1: validator must accept ``--tags-dir`` so it
    works against arbitrary workspaces (not only ones whose layout matches
    ``<workspace>/audit/corpus_tags/tags``)."""

    def test_tags_dir_override_uses_explicit_path(self) -> None:
        # Workspace #1 = bogus tags layout (validator would FAIL if it tried
        # to resolve workspace-derived path); workspace #2 = arbitrary tags
        # dir at a non-standard location. Override must redirect there.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bogus_ws = root / "bogus_ws"
            bogus_ws.mkdir(parents=True, exist_ok=True)
            # Arbitrary tags dir layout (not the standard
            # audit/corpus_tags/tags subpath). Sibling index/ is required.
            arbitrary_root = root / "graph_ws_v11"
            tags_dir = arbitrary_root / "tags"
            index_dir = arbitrary_root / "index"
            tags_dir.mkdir(parents=True, exist_ok=True)
            index_dir.mkdir(parents=True, exist_ok=True)
            (tags_dir / "rec_a.yaml").write_text(
                _v1_1_record_yaml("synthetic:rec_a"),
                encoding="utf-8",
            )
            # Write a minimal set of indexes alongside the override tags
            # dir, NOT under the bogus workspace. Use the helper but pass
            # arbitrary_root as if it were the workspace root by writing
            # under arbitrary_root/audit/corpus_tags/index; for the
            # override case we instead write under the override sibling
            # index/.
            for name in (
                "by_cve_id.jsonl",
                "by_ghsa_id.jsonl",
                "by_firm.jsonl",
                "by_verification_tier.jsonl",
                "by_incident_date.jsonl",
            ):
                (index_dir / name).write_text(
                    json.dumps(
                        {
                            "record_id": "synthetic:rec_a",
                            "key": "synthetic-key",
                            "tag_file": "rec_a.yaml",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            rc, payload = VALIDATOR.validate(bogus_ws, tags_dir=tags_dir)
            self.assertEqual(payload["overall_status"], "PASS", payload)
            self.assertEqual(rc, 0)
            # The resolved tags_dir_used field is what the agent / operator
            # reads back to confirm which path actually ran.
            self.assertEqual(payload["tags_dir_used"], str(tags_dir.resolve()))
            self.assertEqual(payload["v1_1_record_count"], 1)
            self.assertEqual(payload["verification_tier_populated"], 1)

    def test_tags_dir_default_falls_back_to_workspace(self) -> None:
        # No --tags-dir supplied → behaviour identical to the legacy
        # workspace-only path. This guards backward compat for the
        # canonical /Users/wolf/auditooor-702-full call site.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            (tags_dir / "rec_a.yaml").write_text(
                _v1_1_record_yaml("synthetic:rec_a"),
                encoding="utf-8",
            )
            _write_indexes(
                root,
                by_verification_tier_lines=[
                    {
                        "record_id": "synthetic:rec_a",
                        "key": "tier-2-verified-public-archive",
                        "tag_file": "rec_a.yaml",
                    },
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "PASS", payload)
            self.assertEqual(rc, 0)
            expected_tags_dir = (root / "audit" / "corpus_tags" / "tags")
            self.assertEqual(payload["tags_dir_used"], str(expected_tags_dir))
            # Same value mirrored into the legacy ``tags_dir`` key.
            self.assertEqual(payload["tags_dir"], str(expected_tags_dir))

    def test_tags_dir_nonexistent_emits_clean_error(self) -> None:
        # --tags-dir pointing at a non-existent path must produce a clean
        # ERROR verdict (rc=2) with a precise failure message, NOT crash.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bogus_ws = root / "ws"
            bogus_ws.mkdir(parents=True, exist_ok=True)
            missing_tags = root / "definitely" / "does" / "not" / "exist" / "tags"
            rc, payload = VALIDATOR.validate(bogus_ws, tags_dir=missing_tags)
            self.assertEqual(payload["overall_status"], "ERROR", payload)
            self.assertEqual(rc, 2)
            self.assertTrue(
                any("tags dir missing" in f for f in payload["failures"]),
                payload["failures"],
            )
            # tags_dir_used must reflect what the user actually asked for so
            # the operator can debug the typo.
            self.assertIn("definitely", payload["tags_dir_used"])


class TestCliExitCodeHarmonization(unittest.TestCase):
    """Wave-2 PR-A capability-gap #2: validator CLI exit codes must agree
    with ``tools/hackerman-schema-v1-to-v1.1-runner.py``.

    Convention (mirrors the runner):

      * exit 0 - PASS (or non-strict FAIL)
      * exit 1 - FAIL (only when ``--strict``)
      * exit 2 - ERROR (missing tags dir; bypasses --strict)

    These tests assert the CLI subprocess exit code directly so a wrapper
    shell script can rely on the contract.
    """

    def test_cli_missing_tags_dir_exits_2(self) -> None:
        # Synthetic fixture: nonexistent --tags-dir.
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "synthetic_fixture_nonexistent_tags_dir"
            self.assertFalse(bogus.exists())
            res = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(bogus),
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                res.returncode,
                2,
                msg=(
                    "missing tags-dir must return CLI exit 2; got "
                    f"rc={res.returncode}\nstdout={res.stdout}\n"
                    f"stderr={res.stderr}"
                ),
            )
            # ERROR bypasses --strict — the same rc is returned even
            # without it.
            res2 = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(bogus),
                    "--strict",
                    "--json",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res2.returncode, 2)


def _v1_1_record_with_cve_yaml(
    record_id: str,
    cve_id: str,
    *,
    verification_tier: str = "tier-2-verified-public-archive",
) -> str:
    """v1.1 record carrying a top-level ``cve_id`` field. Used for the
    W2.5-followup index_drift_check tests (synthetic_fixture-marked)."""
    return "\n".join(
        [
            "schema_version: auditooor.hackerman_record.v1.1",
            f"record_id: {record_id}",
            f"verification_tier: {verification_tier}",
            f"cve_id: {cve_id}",
            "attack_class: reentrancy-attack",
            "target_repo: synthetic/repo",
            "synthetic_fixture: true",
            "function_shape:",
            '  raw_signature: "function f()"',
            "  shape_tags:",
            "    - reentrancy",
            f"    - verification_tier:{verification_tier}",
            "",
        ]
    )


class IndexDriftDetectedFailTest(unittest.TestCase):
    """W2.5-followup case: corpus has 5 records with top-level ``cve_id``
    but the by_cve_id.jsonl index only carries rows for 2 of them.
    Expected verdict: index_drift_check FAILs with corpus_only=3 on
    ``by_cve_id``, overall_status=FAIL."""

    def test_drift_detected_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            specs = [
                ("synthetic:rec_cve_a", "CVE-2099-0001"),
                ("synthetic:rec_cve_b", "CVE-2099-0002"),
                ("synthetic:rec_cve_c", "CVE-2099-0003"),
                ("synthetic:rec_cve_d", "CVE-2099-0004"),
                ("synthetic:rec_cve_e", "CVE-2099-0005"),
            ]
            for i, (rid, cve) in enumerate(specs):
                (tags_dir / f"rec_cve_{i}.yaml").write_text(
                    _v1_1_record_with_cve_yaml(rid, cve),
                    encoding="utf-8",
                )
            _write_indexes(
                root,
                by_cve_id_lines=[
                    {
                        "record_id": "synthetic:rec_cve_a",
                        "key": "CVE-2099-0001",
                        "tag_file": "rec_cve_0.yaml",
                    },
                    {
                        "record_id": "synthetic:rec_cve_b",
                        "key": "CVE-2099-0002",
                        "tag_file": "rec_cve_1.yaml",
                    },
                ],
                by_verification_tier_lines=[
                    {
                        "record_id": rid,
                        "key": "tier-2-verified-public-archive",
                        "tag_file": f"rec_cve_{i}.yaml",
                    }
                    for i, (rid, _) in enumerate(specs)
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "FAIL", payload)
            self.assertEqual(rc, 1)
            drift = payload["index_drift_check"]
            self.assertEqual(drift["status"], "FAIL", drift)
            cve_per = drift["per_index"]["by_cve_id"]
            self.assertEqual(cve_per["status"], "FAIL", cve_per)
            self.assertEqual(cve_per["expected_record_count"], 5)
            self.assertEqual(cve_per["actual_record_count"], 2)
            self.assertEqual(cve_per["corpus_only_record_count"], 3)
            self.assertTrue(
                any("index drift:" in f for f in payload["failures"]),
                payload["failures"],
            )


class IndexDriftAbsentPassTest(unittest.TestCase):
    """W2.5-followup case: every corpus cve_id record has a matching
    index row. Expected verdict: index_drift_check OK; overall_status
    PASS."""

    def test_drift_absent_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags_dir = _write_workspace(root)
            specs = [
                ("synthetic:rec_cve_a", "CVE-2099-0010"),
                ("synthetic:rec_cve_b", "CVE-2099-0011"),
                ("synthetic:rec_cve_c", "CVE-2099-0012"),
            ]
            for i, (rid, cve) in enumerate(specs):
                (tags_dir / f"rec_cve_{i}.yaml").write_text(
                    _v1_1_record_with_cve_yaml(rid, cve),
                    encoding="utf-8",
                )
            _write_indexes(
                root,
                by_cve_id_lines=[
                    {
                        "record_id": rid,
                        "key": cve,
                        "tag_file": f"rec_cve_{i}.yaml",
                    }
                    for i, (rid, cve) in enumerate(specs)
                ],
                by_verification_tier_lines=[
                    {
                        "record_id": rid,
                        "key": "tier-2-verified-public-archive",
                        "tag_file": f"rec_cve_{i}.yaml",
                    }
                    for i, (rid, _) in enumerate(specs)
                ],
            )
            rc, payload = VALIDATOR.validate(root)
            self.assertEqual(payload["overall_status"], "PASS", payload)
            self.assertEqual(rc, 0)
            drift = payload["index_drift_check"]
            self.assertEqual(drift["status"], "OK", drift)
            cve_per = drift["per_index"]["by_cve_id"]
            self.assertEqual(cve_per["status"], "OK", cve_per)
            self.assertEqual(cve_per["expected_record_count"], 3)
            self.assertEqual(cve_per["actual_record_count"], 3)
            self.assertEqual(cve_per["corpus_only_record_count"], 0)


if __name__ == "__main__":
    unittest.main()
