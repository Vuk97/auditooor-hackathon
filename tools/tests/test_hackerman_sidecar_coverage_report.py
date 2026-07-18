from __future__ import annotations

import json
import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-sidecar-coverage-report.py"
SPEC = importlib.util.spec_from_file_location("hackerman_sidecar_coverage_report", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class HackermanSidecarCoverageReportTests(unittest.TestCase):
    def test_reports_recursive_coverage_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            (tags / "nested").mkdir(parents=True)
            derived.mkdir()
            (tags / "flat.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: flat\n",
                encoding="utf-8",
            )
            (tags / "nested" / "record.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: nested\n",
                encoding="utf-8",
            )
            (derived / "exploit_predicates.jsonl").write_text(
                json.dumps(
                    {
                        "schema_version": "meta",
                        "corpus_file_count": 1,
                        "records_emitted": 1,
                    }
                )
                + "\n"
                + json.dumps({"record_id": "flat"})
                + "\n",
                encoding="utf-8",
            )

            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=1.0,
                size_warn_bytes=10_000,
                size_hard_bytes=20_000,
            )

        self.assertEqual(payload["corpus"]["record_files_seen"], 2)
        self.assertEqual(payload["corpus"]["active_records"], 2)
        exploit = next(row for row in payload["sidecars"] if row["name"] == "exploit_predicates")
        self.assertEqual(exploit["canonical_file_coverage_ratio"], 0.5)
        self.assertIn("sidecar_not_recursive_corpus_parity", exploit["blockers"])
        missing = next(row for row in payload["sidecars"] if row["name"] == "chain_candidates")
        self.assertIn("sidecar_missing", missing["blockers"])

    def test_main_strict_fails_on_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            (tags / "flat.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: flat\n",
                encoding="utf-8",
            )
            with redirect_stdout(io.StringIO()):
                rc = report.main(
                    [
                        "--tag-dir",
                        str(tags),
                        "--derived-dir",
                        str(derived),
                        "--strict",
                        "--json",
                    ]
                )
        self.assertEqual(rc, 1)

    def test_reports_blocked_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            (tags / "flat.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: flat\n",
                encoding="utf-8",
            )
            (derived / "exploit_predicates.jsonl.blocked.json").write_text(
                json.dumps(
                    {
                        "schema_version": "blocked",
                        "status": "blocked",
                        "blockers": ["sidecar_size_hard_limit"],
                        "next_action": "shard exploit predicates",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=1.0,
                size_warn_bytes=10_000,
                size_hard_bytes=20_000,
            )

        exploit = next(row for row in payload["sidecars"] if row["name"] == "exploit_predicates")
        self.assertIn("sidecar_missing", exploit["blockers"])
        self.assertIn("sidecar_size_hard_limit", exploit["blockers"])
        self.assertEqual(exploit["blocked_manifest"]["status"], "blocked")

    def test_exploit_predicates_manifest_satisfies_recursive_parity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            shard_dir = derived / "exploit_predicates.d"
            (tags / "nested").mkdir(parents=True)
            shard_dir.mkdir(parents=True)
            (tags / "flat.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: flat\n",
                encoding="utf-8",
            )
            (tags / "nested" / "record.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: nested\n",
                encoding="utf-8",
            )
            (shard_dir / "shard-00000.jsonl").write_text(
                json.dumps({"record_id": "flat"}) + "\n"
                + json.dumps({"record_id": "nested"}) + "\n",
                encoding="utf-8",
            )
            (derived / "exploit_predicates.manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.hackerman_exploit_predicates_sidecar.manifest.v1",
                        "sidecar_schema": "auditooor.hackerman_exploit_predicates_sidecar.v1",
                        "sidecar_layout": "sharded-jsonl",
                        "shard_dir": "exploit_predicates.d",
                        "shard_count": 1,
                        "shard_total_size_bytes": 48,
                        "corpus_file_count": 2,
                        "records_emitted": 2,
                        "shards": [
                            {
                                "path": "shard-00000.jsonl",
                                "records_emitted": 2,
                                "size_bytes": 48,
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=1.0,
                size_warn_bytes=10_000,
                size_hard_bytes=20_000,
            )

        exploit = next(row for row in payload["sidecars"] if row["name"] == "exploit_predicates")
        self.assertEqual(exploit["status"], "ok")
        self.assertEqual(exploit["sidecar_layout"], "sharded-jsonl")
        self.assertEqual(exploit["canonical_file_coverage_ratio"], 1.0)
        self.assertNotIn("sidecar_not_recursive_corpus_parity", exploit["blockers"])

    def test_exploit_predicates_manifest_reports_missing_shard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            (tags / "flat.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: flat\n",
                encoding="utf-8",
            )
            (derived / "exploit_predicates.manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.hackerman_exploit_predicates_sidecar.manifest.v1",
                        "sidecar_layout": "sharded-jsonl",
                        "shard_dir": "exploit_predicates.d",
                        "corpus_file_count": 1,
                        "records_emitted": 1,
                        "shards": [{"path": "missing.jsonl", "records_emitted": 1}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=1.0,
                size_warn_bytes=10_000,
                size_hard_bytes=20_000,
            )

        exploit = next(row for row in payload["sidecars"] if row["name"] == "exploit_predicates")
        self.assertIn("sidecar_shard_missing", exploit["blockers"])


    def _make_sharded_sidecar(
        self,
        derived: Path,
        name: str,
        schema_version: str,
        records_key: str,
        record_count: int,
        corpus_file_count: int,
    ) -> None:
        """Helper: create a 0-byte root .jsonl marker, manifest, and one shard."""
        shard_dir = derived / f"{name}.d"
        shard_dir.mkdir(parents=True, exist_ok=True)
        # 0-byte root marker (as on disk)
        (derived / f"{name}.jsonl").write_bytes(b"")
        shard_path = shard_dir / "shard-00000.jsonl"
        shard_path.write_text(
            "\n".join(json.dumps({"record_id": f"r{i}"}) for i in range(record_count)) + "\n",
            encoding="utf-8",
        )
        manifest = {
            "schema_version": schema_version,
            "shard_dir": f"{name}.d",
            "shard_count": 1,
            "shard_total_size_bytes": shard_path.stat().st_size,
            records_key: record_count,
            "corpus_file_count": corpus_file_count,
            "shards": [{"path": "shard-00000.jsonl", "size_bytes": shard_path.stat().st_size}],
        }
        (derived / f"{name}.manifest.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8"
        )

    def test_chain_candidates_sharded_reports_nonzero_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            for i in range(3):
                (tags / f"record{i}.yaml").write_text(
                    f"schema_version: auditooor.hackerman_record.v1.1\nrecord_id: r{i}\n",
                    encoding="utf-8",
                )
            self._make_sharded_sidecar(
                derived,
                "chain_candidates",
                "auditooor.hackerman_chain_candidates_sidecar.manifest.v1",
                "records_emitted",
                3,
                3,
            )
            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=0.98,
                size_warn_bytes=10_000_000,
                size_hard_bytes=95_000_000,
            )
        row = next(r for r in payload["sidecars"] if r["name"] == "chain_candidates")
        self.assertGreater(row["canonical_file_coverage_ratio"], 0.0)
        self.assertEqual(row["emitted_record_count"], 3)
        self.assertNotIn("sidecar_not_recursive_corpus_parity", row["blockers"])

    def test_detector_relationship_records_sharded_reports_nonzero_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            for i in range(4):
                (tags / f"record{i}.yaml").write_text(
                    f"schema_version: auditooor.hackerman_record.v1.1\nrecord_id: r{i}\n",
                    encoding="utf-8",
                )
            self._make_sharded_sidecar(
                derived,
                "detector_relationship_records",
                "auditooor.hackerman_detector_relationship_records_sidecar.manifest.v1",
                "records_loaded",
                4,
                4,
            )
            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=0.98,
                size_warn_bytes=10_000_000,
                size_hard_bytes=95_000_000,
            )
        row = next(r for r in payload["sidecars"] if r["name"] == "detector_relationship_records")
        self.assertGreater(row["canonical_file_coverage_ratio"], 0.0)
        self.assertEqual(row["emitted_record_count"], 4)
        self.assertNotIn("sidecar_not_recursive_corpus_parity", row["blockers"])

    def test_sharded_sidecar_missing_shard_reports_blocker(self) -> None:
        """A sharded spec whose shard file is absent reports sidecar_shard_missing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tags = root / "tags"
            derived = root / "derived"
            tags.mkdir()
            derived.mkdir()
            (tags / "r0.yaml").write_text(
                "schema_version: auditooor.hackerman_record.v1.1\nrecord_id: r0\n",
                encoding="utf-8",
            )
            # 0-byte root marker
            (derived / "chain_candidates.jsonl").write_bytes(b"")
            manifest = {
                "schema_version": "auditooor.hackerman_chain_candidates_sidecar.manifest.v1",
                "shard_dir": "chain_candidates.d",
                "shard_count": 1,
                "records_emitted": 1,
                "corpus_file_count": 1,
                "shards": [{"path": "shard-00000.jsonl"}],
            }
            (derived / "chain_candidates.manifest.json").write_text(
                json.dumps(manifest) + "\n", encoding="utf-8"
            )
            payload = report.build_report(
                tags,
                derived,
                min_file_coverage=0.98,
                size_warn_bytes=10_000_000,
                size_hard_bytes=95_000_000,
            )
        row = next(r for r in payload["sidecars"] if r["name"] == "chain_candidates")
        self.assertIn("sidecar_shard_missing", row["blockers"])


if __name__ == "__main__":
    unittest.main()
