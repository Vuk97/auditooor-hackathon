"""Regression tests for cross-language analogue sidecar emission."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-cross-language-analogues.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(tags_dir: Path) -> list[dict]:
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--tags-dir", str(tags_dir), "--out", "-"],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    rows: list[dict] = []
    for line in proc.stdout.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _run_writeback(tags_dir: Path, out: Path, summary: Path) -> dict:
    subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--tags-dir",
            str(tags_dir),
            "--out",
            str(out),
            "--writeback-tags",
            "--writeback-summary",
            str(summary),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(summary.read_text(encoding="utf-8"))


class HackermanCrossLanguageAnaloguesTest(unittest.TestCase):
    def test_emits_cross_language_rows_and_translation_templates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-xlang-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            records = [
                (
                    "sol-access",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: sol/access-control
source_audit_ref: audit:sol:access
target_language: solidity
target_repo: example/solidity
target_component: contracts/Vault.sol
bug_class: access-control
attack_class: access-control
notes: solidity access control
""".lstrip(),
                ),
                (
                    "go-access",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: go/access-control
source_audit_ref: audit:go:access
target_language: go
target_repo: cosmos/sdk
target_component: x/bank/keeper/msg_server.go
bug_class: access-control
attack_class: access-control
notes: cosmos keeper auth
""".lstrip(),
                ),
                (
                    "sol-account",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: sol/accounting-drift
source_audit_ref: audit:sol:accounting
target_language: solidity
target_repo: example/solidity
target_component: contracts/Pool.sol
bug_class: accounting
attack_class: state-accounting-drift
notes: accounting drift
""".lstrip(),
                ),
                (
                    "go-account",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: go/accounting-drift
source_audit_ref: audit:go:accounting
target_language: go
target_repo: cosmos/sdk
target_component: x/distribution/keeper/keeper.go
bug_class: accounting
attack_class: state-accounting-drift
notes: cosmos accounting drift
""".lstrip(),
                ),
                (
                    "sol-replay",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: sol/replay-domain
source_audit_ref: audit:sol:replay
target_language: solidity
target_repo: example/solidity
target_component: contracts/Sig.sol
bug_class: signature-replay
attack_class: signature-replay
notes: eip712 replay
""".lstrip(),
                ),
                (
                    "go-replay",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: go/replay-domain
source_audit_ref: audit:go:replay
target_language: go
target_repo: cosmos/sdk
target_component: x/auth/tx/signing.go
bug_class: signature-replay
attack_class: signature-replay
notes: sign bytes replay
""".lstrip(),
                ),
                (
                    "sol-oracle",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: sol/oracle
source_audit_ref: audit:sol:oracle
target_language: solidity
target_repo: example/solidity
target_component: contracts/Oracle.sol
bug_class: oracle-manipulation
attack_class: stale-or-manipulated-oracle
notes: stale price feed
""".lstrip(),
                ),
                (
                    "go-oracle",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: go/oracle
source_audit_ref: audit:go:oracle
target_language: go
target_repo: cosmos/sdk
target_component: x/oracle/keeper/keeper.go
bug_class: oracle-manipulation
attack_class: stale-or-manipulated-oracle
notes: freshness guard
""".lstrip(),
                ),
                (
                    "sol-consensus",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: sol/consensus-state
source_audit_ref: audit:sol:consensus
target_language: solidity
target_repo: example/solidity
target_component: contracts/State.sol
bug_class: consensus
attack_class: consensus-state
notes: state transition before finality
""".lstrip(),
                ),
                (
                    "go-consensus",
                    """
schema_version: auditooor.hackerman_record.v1
record_id: go/consensus-state
source_audit_ref: audit:go:consensus
target_language: go
target_repo: cosmos/sdk
target_component: x/consensus/keeper/end_block.go
bug_class: consensus
attack_class: consensus-state
notes: endblock gate
""".lstrip(),
                ),
            ]
            for name, text in records:
                _write(tags_dir / f"{name}.yaml", text)

            rows = _run(tags_dir)

            self.assertEqual(len(rows), 10)
            rows_by_source = {row["source_record_id"]: row for row in rows}
            self.assertEqual(rows_by_source["sol/access-control"]["target_language"], "go")
            self.assertEqual(rows_by_source["go/access-control"]["target_language"], "solidity")
            self.assertIn("authority check", rows_by_source["sol/access-control"]["pattern_translation"])
            self.assertIn("bank/reward bookkeeping reconciliation", rows_by_source["sol/accounting-drift"]["pattern_translation"])
            self.assertIn("chain-id binding", rows_by_source["sol/replay-domain"]["pattern_translation"])
            self.assertIn("freshness/quorum guard", rows_by_source["sol/oracle"]["pattern_translation"])
            self.assertIn("EndBlock/consensus-state gate", rows_by_source["sol/consensus-state"]["pattern_translation"])
            self.assertTrue(all(row["confidence"] >= 0.85 for row in rows))

    def test_same_language_only_records_emit_no_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-xlang-empty-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            _write(
                tags_dir / "solo.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: go/solo
source_audit_ref: audit:go:solo
target_language: go
target_repo: cosmos/sdk
target_component: x/auth/keeper/keeper.go
bug_class: access-control
attack_class: access-control
notes: no analogue
""".lstrip(),
            )

            rows = _run(tags_dir)

            self.assertEqual(rows, [])

    def test_v1_1_records_are_included(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-xlang-v11-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            _write(
                tags_dir / "sol.yaml",
                """
schema_version: auditooor.hackerman_record.v1.1
record_id: sol/v1-1-access
source_audit_ref: audit:sol:v1-1-access
target_language: solidity
target_repo: example/solidity
target_component: contracts/Vault.sol
bug_class: access-control
attack_class: access-control
record_tier: submission-derived
source_extraction_method: human-curated
source_extraction_confidence: 0.9
notes: solidity access control
""".lstrip(),
            )
            _write(
                tags_dir / "go.yaml",
                """
schema_version: auditooor.hackerman_record.v1.1
record_id: go/v1-1-access
source_audit_ref: audit:go:v1-1-access
target_language: go
target_repo: cosmos/sdk
target_component: x/bank/keeper/msg_server.go
bug_class: access-control
attack_class: access-control
record_tier: submission-derived
source_extraction_method: human-curated
source_extraction_confidence: 0.9
notes: cosmos keeper auth
""".lstrip(),
            )

            rows = _run(tags_dir)

            self.assertEqual(len(rows), 2)
            self.assertEqual({row["source_record_id"] for row in rows}, {"sol/v1-1-access", "go/v1-1-access"})

    def test_writeback_populates_schema_native_record_field(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-xlang-writeback-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            _write(
                tags_dir / "sol.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: sol/access-control
source_audit_ref: audit:sol:access
target_language: solidity
target_repo: example/solidity
target_component: contracts/Vault.sol
bug_class: access-control
attack_class: access-control
attacker_role: unprivileged
attacker_action_sequence: prove access bypass
required_preconditions:
  - role gate exists
impact_class: privilege-escalation
impact_actor: arbitrary-user
impact_dollar_class: non-financial
fix_pattern: check role
fix_anti_pattern_avoided: trusting caller
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )
            _write(
                tags_dir / "go.yaml",
                """
schema_version: auditooor.hackerman_record.v1
record_id: go/access-control
source_audit_ref: audit:go:access
target_language: go
target_repo: cosmos/sdk
target_component: x/bank/keeper/msg_server.go
bug_class: access-control
attack_class: access-control
attacker_role: unprivileged
attacker_action_sequence: prove authority bypass
required_preconditions:
  - keeper method accepts sender
impact_class: privilege-escalation
impact_actor: arbitrary-user
impact_dollar_class: non-financial
fix_pattern: check authority
fix_anti_pattern_avoided: trusting message field
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            )

            summary = _run_writeback(tags_dir, root / "xlang.jsonl", root / "summary.json")

            self.assertEqual(summary["records_changed"], 2)
            sol_text = (tags_dir / "sol.yaml").read_text(encoding="utf-8")
            self.assertIn("cross_language_analogues:\n  - target_language: go", sol_text)
            self.assertIn("pattern_translation:", sol_text)
            self.assertNotIn("analogue_record_id:", sol_text)
            self.assertNotIn("confidence:", sol_text)
            self.assertLess(sol_text.index("cross_language_analogues:"), sol_text.index("related_records:"))


class HackermanCrossLanguageAnaloguesShardingTest(unittest.TestCase):
    """J3e sharding tests: emit + shard-aware consumer load + monolith back-compat."""

    def _make_tags(self, tags_dir: Path) -> None:
        """Write a minimal two-record cross-language fixture."""
        _write(
            tags_dir / "sol.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: sol/shard-access
source_audit_ref: audit:sol:shard-access
target_language: solidity
target_repo: example/solidity
target_component: contracts/Vault.sol
bug_class: access-control
attack_class: access-control
notes: shard test solidity
""".lstrip(),
        )
        _write(
            tags_dir / "go.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: go/shard-access
source_audit_ref: audit:go:shard-access
target_language: go
target_repo: cosmos/sdk
target_component: x/bank/keeper/msg_server.go
bug_class: access-control
attack_class: access-control
notes: shard test go
""".lstrip(),
        )

    def test_shard_emit_creates_manifest_and_shard_dir(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xlang-shard-emit-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            out = root / "derived" / "cross_language_analogues.jsonl"
            self._make_tags(tags_dir)

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--tags-dir", str(tags_dir),
                 "--out", str(out), "--shard-target-mb", "0.001"],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )
            summary = json.loads(proc.stdout.strip())
            self.assertEqual(summary["schema"], "auditooor.hackerman.cross_language_analogues.manifest.v1")
            self.assertGreater(summary["shard_count"], 0)
            self.assertGreater(summary["records_emitted"], 0)

            manifest_path = out.with_name("cross_language_analogues.manifest.json")
            shard_dir = out.with_name("cross_language_analogues.d")
            self.assertTrue(manifest_path.is_file(), "manifest.json must exist")
            self.assertTrue(shard_dir.is_dir(), "shard dir must exist")
            self.assertEqual(out.stat().st_size, 0, "monolith must be 0-byte stub")

            shards = list(shard_dir.glob("shard-*.jsonl"))
            self.assertGreater(len(shards), 0)
            for shard in shards:
                self.assertLessEqual(shard.stat().st_size, int(0.001 * 1024 * 1024 * 2),
                                     "each shard must be near the target size")

    def test_shard_aware_read_jsonl_loads_all_rows(self) -> None:
        """read_jsonl (hackerman_query_common) must load rows from shards transparently."""
        import sys as _sys
        _sys.path.insert(0, str(REPO_ROOT / "tools"))
        from hackerman_query_common import read_jsonl  # noqa: PLC0415

        with tempfile.TemporaryDirectory(prefix="xlang-shard-read-") as tmp:
            root = Path(tmp)
            tags_dir = root / "tags"
            out = root / "cross_language_analogues.jsonl"
            self._make_tags(tags_dir)

            subprocess.run(
                [sys.executable, str(TOOL), "--tags-dir", str(tags_dir),
                 "--out", str(out), "--shard-target-mb", "0.001"],
                cwd=REPO_ROOT, text=True, capture_output=True, check=True,
            )

            rows = read_jsonl(out)
            self.assertGreater(len(rows), 0, "read_jsonl must return rows from shards")
            self.assertTrue(all(isinstance(r, dict) for r in rows))
            record_ids = {r.get("source_record_id") for r in rows}
            self.assertTrue(record_ids, "rows must have source_record_id")

    def test_monolith_back_compat_no_manifest(self) -> None:
        """read_jsonl must still read plain JSONL when no manifest exists."""
        import sys as _sys
        _sys.path.insert(0, str(REPO_ROOT / "tools"))
        from hackerman_query_common import read_jsonl  # noqa: PLC0415

        with tempfile.TemporaryDirectory(prefix="xlang-monolith-compat-") as tmp:
            root = Path(tmp)
            out = root / "cross_language_analogues.jsonl"
            rows_in = [
                {"source_record_id": "a", "analogue_record_id": "b", "attack_class": "x"},
                {"source_record_id": "c", "analogue_record_id": "d", "attack_class": "y"},
            ]
            out.write_text("\n".join(json.dumps(r) for r in rows_in) + "\n", encoding="utf-8")
            rows_out = read_jsonl(out)
            self.assertEqual(len(rows_out), 2)
            self.assertEqual(rows_out[0]["source_record_id"], "a")


if __name__ == "__main__":
    unittest.main()
