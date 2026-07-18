"""Tests for ``tools/hackerman-subtree-readme-scaffolder.py``.

Cases (>=8):

 1. empty tags-dir -> totals all zero, no files written
 2. subtree without any README and no records -> README still created
    (with record_count=0 and the "no resolvable https://" sample-URL
    fallback block)
 3. subtree with ``_MINER_README.md`` already -> skipped, no overwrite
 4. subtree with ``README.md`` already -> skipped, no overwrite
 5. ``_QUARANTINE_FABRICATED_CVE`` -> excluded by prefix rule
 6. ``_deprecated`` -> excluded by prefix rule
 7. dry-run path -> envelope reports ``created`` but no file lands on disk
 8. nested record.yaml layout (``<subtree>/<slug>/record.yaml``) is walked,
    URLs extracted, README references the record count and tier
 9. flat-record layout (``<subtree>/<slug>.yaml`` directly at subtree root,
    e.g. cve_db) is walked too
10. record.yaml wins over record.json at the same dir (precedence)
11. URLs in ``required_preconditions`` + ``attacker_action_sequence`` are
    extracted and deduped; sample-URL block caps at 5 distinct URLs
12. JSON envelope schema is ``auditooor.hackerman_subtree_readme_scaffold.v1``
13. ``--dry-run`` CLI flag exits rc=0 and emits an envelope
14. context_pack_id / context_pack_hash from CLI args propagate into the
    rendered README body verbatim
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-subtree-readme-scaffolder.py"


def _load_tool() -> Any:
    name = "_hackerman_subtree_readme_scaffolder_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _write_record_yaml(path: Path, **overrides: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "synthetic:test:001",
        "source_audit_ref": "https://example.test/advisory/synthetic-001",
        "target_domain": "vault",
        "target_language": "solidity",
        "target_repo": "synthetic/test",
        "target_component": "synthetic test",
        "function_shape": {
            "raw_signature": "synthetic",
            "shape_tags": ["verification_tier:tier-2-verified-public-archive"],
        },
        "bug_class": "synthetic-bug-class",
        "attack_class": "synthetic-attack-class",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "See https://example.test/postmortem/synthetic-001 for details.",
        "required_preconditions": [
            "Reference advisory at https://example.test/advisory/synthetic-001",
        ],
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "<$10K",
        "severity_at_finding": "high",
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
    }
    body.update(overrides)
    # Write as a minimal YAML-ish doc that PyYAML and the fallback parser both load.
    lines: list[str] = []
    for k, v in body.items():
        if isinstance(v, list):
            lines.append(f"{k}:")
            for item in v:
                lines.append(f"  - {json.dumps(item)}")
        elif isinstance(v, dict):
            lines.append(f"{k}:")
            for kk, vv in v.items():
                if isinstance(vv, list):
                    lines.append(f"  {kk}:")
                    for item in vv:
                        lines.append(f"    - {json.dumps(item)}")
                else:
                    lines.append(f"  {kk}: {json.dumps(vv)}")
        else:
            lines.append(f"{k}: {json.dumps(v)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ScaffolderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_tool()
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tags = Path(self._td.name) / "tags"
        self.tags.mkdir()

    # 1
    def test_empty_tags_dir_zero_totals(self) -> None:
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"], {"created": 0, "skipped": 0, "excluded": 0})
        self.assertEqual(env["schema"], "auditooor.hackerman_subtree_readme_scaffold.v1")

    # 2
    def test_empty_subtree_still_scaffolds_readme(self) -> None:
        (self.tags / "empty_subtree").mkdir()
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 1)
        readme = (self.tags / "empty_subtree" / "README.md").read_text()
        self.assertIn("Record count at scaffold time: 0", readme)
        self.assertIn("no resolvable https://", readme)

    # 3
    def test_skip_when_miner_readme_exists(self) -> None:
        sub = self.tags / "with_miner_readme"
        sub.mkdir()
        (sub / "_MINER_README.md").write_text("hand-written\n")
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 0)
        self.assertEqual(env["totals"]["skipped"], 1)
        self.assertFalse((sub / "README.md").exists())
        self.assertEqual((sub / "_MINER_README.md").read_text(), "hand-written\n")

    # 4
    def test_skip_when_readme_md_exists(self) -> None:
        sub = self.tags / "with_readme"
        sub.mkdir()
        (sub / "README.md").write_text("pre-existing\n")
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 0)
        self.assertEqual(env["totals"]["skipped"], 1)
        self.assertEqual((sub / "README.md").read_text(), "pre-existing\n")

    # 5
    def test_excluded_quarantine_prefix(self) -> None:
        (self.tags / "_QUARANTINE_FABRICATED_CVE").mkdir()
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["excluded"], 1)
        self.assertEqual(env["excluded"][0]["subtree"], "_QUARANTINE_FABRICATED_CVE")
        self.assertFalse(
            (self.tags / "_QUARANTINE_FABRICATED_CVE" / "README.md").exists()
        )

    # 6
    def test_excluded_deprecated_prefix(self) -> None:
        (self.tags / "_deprecated").mkdir()
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["excluded"], 1)
        self.assertEqual(env["excluded"][0]["subtree"], "_deprecated")

    # 7
    def test_dry_run_no_files_written(self) -> None:
        (self.tags / "needs_readme").mkdir()
        env = self.mod.scaffold(self.tags, dry_run=True)
        self.assertEqual(env["totals"]["created"], 1)
        self.assertTrue(env["created"][0]["dry_run"])
        self.assertFalse((self.tags / "needs_readme" / "README.md").exists())

    # 8
    def test_nested_record_yaml_walked(self) -> None:
        sub = self.tags / "nested_layout"
        _write_record_yaml(sub / "slug_a" / "record.yaml", target_domain="vault")
        _write_record_yaml(sub / "slug_b" / "record.yaml", target_domain="dex")
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 1)
        readme = (sub / "README.md").read_text()
        self.assertIn("Record count at scaffold time: 2", readme)
        self.assertIn("`vault`", readme)
        self.assertIn("`dex`", readme)
        self.assertIn("tier-2-verified-public-archive", readme)

    # 9
    def test_flat_record_yaml_walked(self) -> None:
        sub = self.tags / "flat_layout"
        _write_record_yaml(sub / "cve-001.yaml")
        _write_record_yaml(sub / "cve-002.yaml")
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 1)
        readme = (sub / "README.md").read_text()
        self.assertIn("Record count at scaffold time: 2", readme)

    # 10
    def test_record_yaml_wins_over_json_in_same_dir(self) -> None:
        sub = self.tags / "yaml_vs_json"
        _write_record_yaml(sub / "slug" / "record.yaml", bug_class="from-yaml")
        (sub / "slug" / "record.json").write_text(
            json.dumps({"bug_class": "from-json", "record_tier": "json-tier"}),
            encoding="utf-8",
        )
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 1)
        readme = (sub / "README.md").read_text()
        self.assertIn("from-yaml", readme)
        self.assertNotIn("from-json", readme)

    # 11
    def test_urls_extracted_deduped_and_capped_at_5(self) -> None:
        sub = self.tags / "url_cap"
        for i in range(7):
            _write_record_yaml(
                sub / f"slug_{i}" / "record.yaml",
                record_id=f"synthetic:test:{i:03d}",
                source_audit_ref=f"https://example.test/advisory/{i}",
                attacker_action_sequence=f"See https://example.test/postmortem/{i}",
            )
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["totals"]["created"], 1)
        readme = (sub / "README.md").read_text()
        # Sample-URL block caps at 5 distinct URLs.
        url_count = readme.count("https://example.test/advisory/")
        url_count += readme.count("https://example.test/postmortem/")
        self.assertLessEqual(url_count, 5)
        self.assertGreaterEqual(url_count, 1)

    # 12
    def test_json_envelope_schema(self) -> None:
        env = self.mod.scaffold(self.tags)
        self.assertEqual(env["schema"], "auditooor.hackerman_subtree_readme_scaffold.v1")
        self.assertIn("tags_dir", env)
        self.assertIn("created", env)
        self.assertIn("skipped", env)
        self.assertIn("excluded", env)
        self.assertIn("totals", env)

    # 13
    def test_cli_dry_run_exits_zero_and_emits_envelope(self) -> None:
        (self.tags / "cli_subtree").mkdir()
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--tags-dir",
                str(self.tags),
                "--dry-run",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        envelope = json.loads(proc.stdout)
        self.assertEqual(
            envelope["schema"], "auditooor.hackerman_subtree_readme_scaffold.v1"
        )
        self.assertEqual(envelope["totals"]["created"], 1)
        self.assertFalse((self.tags / "cli_subtree" / "README.md").exists())

    # 14
    def test_context_pack_id_and_hash_propagate(self) -> None:
        (self.tags / "ctx_subtree").mkdir()
        self.mod.scaffold(
            self.tags,
            context_pack_id="auditooor.vault_context_pack.v1:resume:deadbeef",
            context_pack_hash="0123456789abcdef" * 4,
        )
        readme = (self.tags / "ctx_subtree" / "README.md").read_text()
        self.assertIn("auditooor.vault_context_pack.v1:resume:deadbeef", readme)
        self.assertIn("0123456789abcdef0123456789abcdef" * 2, readme)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
