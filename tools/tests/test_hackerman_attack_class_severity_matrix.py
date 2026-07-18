"""Tests for ``tools/hackerman-attack-class-severity-matrix.py``.

Wave-1 hackerman capability lift (PR #726). The tool walks
``audit/corpus_tags/tags/**/record.{yaml,json}`` plus flat
``audit/corpus_tags/tags/*.yaml`` files and emits a per-attack-class
severity histogram matrix with severity-mode + tier-1+2-only severity-mode.

Cases (>=8):

 1. empty tags-dir -> total_records=0, no classes/severities; render_human
    survives.
 2. single subdir record -> one class with histogram[crit]=1, severity_mode
    == "critical", and tier-1+2 severity_mode == "critical".
 3. multi-record aggregation: severity_mode picks the most common severity
    for the class.
 4. tier-1+2-only severity_mode: when low/info would otherwise win for a
    class that's mostly-low with one high, the tier-1+2 mode points at
    "high" (cross-validation knob).
 5. tier-1+2-only severity_mode is None when class has zero critical/high
    records.
 6. ``<missing-attack-class>`` sentinel used when ``attack_class`` is
    missing AND ``attack_classes_to_try`` is absent.
 7. flat dsl_pattern with ``attack_classes_to_try`` (list) splits across
    multiple class buckets.
 8. JSON envelope schema id is
    ``auditooor.hackerman_attack_class_severity_matrix.v1`` and contains
    the required keys.
 9. classes_by_mode("critical") returns classes whose severity_mode==
    "critical" sorted by total desc.
10. CLI ``--json`` exits 0 and prints a parseable envelope.
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
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-attack-class-severity-matrix.py"


def _load_tool() -> Any:
    name = "_hackerman_attack_class_severity_matrix_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_subdir_record(
    tags_dir: Path,
    subtree: str,
    record_id: str,
    *,
    attack_class: str | None = None,
    severity_at_finding: str | None = None,
    fmt: str = "yaml",
) -> Path:
    rec_dir = tags_dir / subtree / record_id
    rec_dir.mkdir(parents=True, exist_ok=True)
    if fmt == "yaml":
        lines = [
            "schema_version: auditooor.hackerman_record.v1",
            f"record_id: {record_id}",
            "target_repo: synthetic/test",
        ]
        if attack_class is not None:
            lines.append(f"attack_class: {attack_class}")
        if severity_at_finding is not None:
            lines.append(f"severity_at_finding: {severity_at_finding}")
        path = rec_dir / "record.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path
    obj: dict[str, Any] = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "target_repo": "synthetic/test",
    }
    if attack_class is not None:
        obj["attack_class"] = attack_class
    if severity_at_finding is not None:
        obj["severity_at_finding"] = severity_at_finding
    path = rec_dir / "record.json"
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def _write_flat_dsl_list(
    tags_dir: Path,
    filename: str,
    *,
    attack_classes_to_try: list[str],
    severity_at_finding: str | None,
) -> Path:
    lines = ["schema_version: auditooor.hackerman_record.v1"]
    if severity_at_finding is not None:
        lines.append(f"severity_at_finding: {severity_at_finding}")
    lines.append("attack_classes_to_try:")
    for ac in attack_classes_to_try:
        lines.append(f"  - {ac}")
    path = tags_dir / filename
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class HackermanAttackClassSeverityMatrixTests(unittest.TestCase):
    def test_01_empty_tags_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            matrix = tool.build_matrix(tags)
            self.assertEqual(matrix["total_records"], 0)
            self.assertEqual(matrix["total_classes"], 0)
            self.assertEqual(matrix["classes"], [])
            self.assertEqual(matrix["severities"], [])
            # human render must not crash on empty corpus
            human = tool.render_human(matrix)
            self.assertIn("total_records: 0", human)
            self.assertIn("total_classes: 0", human)

    def test_02_single_subdir_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags,
                "lending_protocols",
                "rec_a",
                attack_class="reentrancy",
                severity_at_finding="critical",
            )
            matrix = tool.build_matrix(tags)
            self.assertEqual(matrix["total_records"], 1)
            self.assertEqual(matrix["total_classes"], 1)
            self.assertEqual(matrix["classes"], ["reentrancy"])
            self.assertEqual(
                matrix["severity_histogram_by_class"]["reentrancy"]["critical"],
                1,
            )
            self.assertEqual(
                matrix["severity_mode_by_class"]["reentrancy"], "critical"
            )
            self.assertEqual(
                matrix["tier_1_2_severity_mode_by_class"]["reentrancy"],
                "critical",
            )

    def test_03_severity_mode_picks_most_common(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # 3 medium + 1 critical for reentrancy -> mode = medium
            for i in range(3):
                _write_subdir_record(
                    tags, "lending_protocols", f"rm{i}",
                    attack_class="reentrancy",
                    severity_at_finding="medium",
                )
            _write_subdir_record(
                tags, "lending_protocols", "rc1",
                attack_class="reentrancy",
                severity_at_finding="critical",
            )
            matrix = tool.build_matrix(tags)
            self.assertEqual(matrix["class_totals"]["reentrancy"], 4)
            self.assertEqual(
                matrix["severity_mode_by_class"]["reentrancy"], "medium"
            )
            # tier-1+2 mode looks only at critical+high -> critical wins
            # because it's the only non-zero of the two
            self.assertEqual(
                matrix["tier_1_2_severity_mode_by_class"]["reentrancy"],
                "critical",
            )

    def test_04_tier_1_2_mode_cross_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # 5 low + 1 high -> full-mode = low; tier-1+2 mode = high
            for i in range(5):
                _write_subdir_record(
                    tags, "lending_protocols", f"rl{i}",
                    attack_class="oracle-manipulation",
                    severity_at_finding="low",
                )
            _write_subdir_record(
                tags, "lending_protocols", "rh1",
                attack_class="oracle-manipulation",
                severity_at_finding="high",
            )
            matrix = tool.build_matrix(tags)
            self.assertEqual(
                matrix["severity_mode_by_class"]["oracle-manipulation"],
                "low",
            )
            self.assertEqual(
                matrix["tier_1_2_severity_mode_by_class"][
                    "oracle-manipulation"
                ],
                "high",
            )

    def test_05_tier_1_2_mode_none_when_no_high_plus(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            for i in range(2):
                _write_subdir_record(
                    tags, "lending_protocols", f"rl{i}",
                    attack_class="cosmetic-class",
                    severity_at_finding="low",
                )
            _write_subdir_record(
                tags, "lending_protocols", "ri1",
                attack_class="cosmetic-class",
                severity_at_finding="info",
            )
            matrix = tool.build_matrix(tags)
            self.assertEqual(
                matrix["severity_mode_by_class"]["cosmetic-class"], "low"
            )
            self.assertIsNone(
                matrix["tier_1_2_severity_mode_by_class"]["cosmetic-class"]
            )

    def test_06_missing_attack_class_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r_no_ac",
                attack_class=None,
                severity_at_finding="high",
            )
            matrix = tool.build_matrix(tags)
            self.assertEqual(matrix["total_records"], 1)
            self.assertIn(tool.MISSING_AC, matrix["classes"])
            self.assertEqual(
                matrix["severity_histogram_by_class"][tool.MISSING_AC]["high"],
                1,
            )

    def test_07_flat_attack_classes_to_try_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_flat_dsl_list(
                tags,
                "dsl_pattern_reentrancy_oracle.yaml",
                attack_classes_to_try=["reentrancy", "oracle-manipulation"],
                severity_at_finding="critical",
            )
            matrix = tool.build_matrix(tags)
            # One record contributes to two classes; total_records=1 but
            # each class gets a histogram cell.
            self.assertEqual(matrix["total_records"], 1)
            self.assertEqual(matrix["class_totals"]["reentrancy"], 1)
            self.assertEqual(
                matrix["class_totals"]["oracle-manipulation"], 1
            )
            self.assertEqual(
                matrix["severity_histogram_by_class"]["reentrancy"][
                    "critical"
                ],
                1,
            )
            self.assertEqual(
                matrix["severity_mode_by_class"]["reentrancy"], "critical"
            )

    def test_08_json_envelope_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                attack_class="reentrancy",
                severity_at_finding="critical",
            )
            matrix = tool.build_matrix(tags)
            payload = json.loads(tool.render_json(matrix))
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_attack_class_severity_matrix.v1",
            )
            for key in (
                "total_records",
                "total_classes",
                "classes",
                "severities",
                "severity_histogram_by_class",
                "class_totals",
                "severity_totals",
                "severity_mode_by_class",
                "tier_1_2_severity_mode_by_class",
                "classes_mode_critical",
                "classes_tier12_mode_critical",
            ):
                self.assertIn(key, payload, msg=f"missing {key} in payload")

    def test_09_classes_by_mode_critical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            # class A: 3 crit (mode=critical), class B: 1 crit + 5 low
            # (mode=low, tier-1+2 mode=critical)
            for i in range(3):
                _write_subdir_record(
                    tags, "lending_protocols", f"a{i}",
                    attack_class="aaa",
                    severity_at_finding="critical",
                )
            _write_subdir_record(
                tags, "lending_protocols", "b1",
                attack_class="bbb",
                severity_at_finding="critical",
            )
            for i in range(5):
                _write_subdir_record(
                    tags, "lending_protocols", f"b_low{i}",
                    attack_class="bbb",
                    severity_at_finding="low",
                )
            matrix = tool.build_matrix(tags)
            full_mode_crit = tool.classes_by_mode(matrix, "critical")
            full_mode_crit_names = [r["attack_class"] for r in full_mode_crit]
            self.assertIn("aaa", full_mode_crit_names)
            self.assertNotIn("bbb", full_mode_crit_names)
            t12_mode_crit = tool.classes_by_mode(
                matrix, "critical", tier_1_2_only=True
            )
            t12_mode_crit_names = [r["attack_class"] for r in t12_mode_crit]
            self.assertIn("aaa", t12_mode_crit_names)
            self.assertIn("bbb", t12_mode_crit_names)

    def test_10_cli_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp)
            _write_subdir_record(
                tags, "lending_protocols", "r1",
                attack_class="reentrancy",
                severity_at_finding="critical",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--tags-dir",
                    str(tags),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["schema"],
                "auditooor.hackerman_attack_class_severity_matrix.v1",
            )
            self.assertEqual(payload["total_records"], 1)
            self.assertEqual(payload["total_classes"], 1)
            self.assertEqual(
                payload["severity_mode_by_class"]["reentrancy"], "critical"
            )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
