"""Tests for tools/hooks/auditooor-corpus-change-refresh.sh - LIFT-9.

R36: pathspec lane=LIFT-9-ENFORCEMENT-HOOK declared via tools/agent-pathspec-register.py.

The hook is a PostToolUse handler that fires on Edit/Write/MultiEdit when the
target file path matches one of the corpus globs. When it fires it runs the
refresh body in the background (or synchronously when
``AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC=1``) and appends NDJSON status records
to a log file. The throttle is configurable via
``AUDITOOOR_CORPUS_REFRESH_THROTTLE_SECONDS`` and the throttle timestamp
file via ``AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE``.

The tests below exercise:

- non-corpus paths -> hook exits 0 without logging a ``fired`` event
- corpus path -> hook logs ``fired`` and ``refresh-complete``
- two rapid corpus writes -> only the first fires; the second logs ``skipped-throttled``
- disable kill-switch -> hook exits 0 without logging anything (verbose=0)
- non-write tool (Read) -> hook exits 0
- malformed payload -> hook exits 0
- log file is valid NDJSON
- hook file is executable
- obsidian + reference-patterns paths fire
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HOOK_PATH = REPO_ROOT / "tools" / "hooks" / "auditooor-corpus-change-refresh.sh"


def _run_hook(payload: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(HOOK_PATH)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def _payload(tool_name: str, file_path: str) -> str:
    return json.dumps(
        {
            "tool_name": tool_name,
            "tool_input": {"file_path": file_path},
        }
    )


def _read_log_records(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    out = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


class CorpusChangeRefreshHookTests(unittest.TestCase):
    def test_hook_is_executable(self) -> None:
        self.assertTrue(HOOK_PATH.is_file(), f"hook missing: {HOOK_PATH}")
        mode = HOOK_PATH.stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR, "hook must be executable by owner")

    def test_corpus_path_fires_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("Write", corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertIn("fired", events)
            self.assertIn("refresh-complete", events)
            # throttle file should now hold an epoch timestamp.
            self.assertTrue(throttle_file.exists())
            ts_str = throttle_file.read_text(encoding="utf-8").strip()
            self.assertTrue(ts_str.isdigit() and int(ts_str) > 0, f"bad throttle ts: {ts_str!r}")

    def test_non_corpus_path_skips(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            # Use a path that's NOT under any corpus subtree.
            non_corpus_path = str(td_path / "some_unrelated_file.md")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("Write", non_corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertNotIn("fired", events)
            self.assertNotIn("refresh-complete", events)
            self.assertFalse(throttle_file.exists())

    def test_throttle_blocks_second_rapid_fire(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/derived/invariants_pilot.jsonl")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_SECONDS": "600",
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc1 = _run_hook(_payload("Edit", corpus_path), env_extra=env_extra)
            proc2 = _run_hook(_payload("Edit", corpus_path), env_extra=env_extra)
            self.assertEqual(proc1.returncode, 0)
            self.assertEqual(proc2.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertEqual(events.count("fired"), 1, f"expected 1 fired, got events={events}")
            self.assertIn("skipped-throttled", events)

    def test_disable_kill_switch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_DISABLE": "1",
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("Write", corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertNotIn("fired", events)
            self.assertNotIn("refresh-complete", events)

    def test_non_write_tool_skips(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("Read", corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertNotIn("fired", events)

    def test_malformed_payload_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook("this-is-not-json", env_extra=env_extra)
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")

    def test_empty_payload_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook("", env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)

    def test_obsidian_anti_pattern_path_fires(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            # Synthetic path that matches obsidian-vault/anti-patterns/ glob.
            corpus_path = "/some/repo/obsidian-vault/anti-patterns/test_pattern.md"
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("MultiEdit", corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertIn("fired", events)

    def test_reference_patterns_dsl_path_fires(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = "/some/repo/reference/patterns.dsl.v2/fixture.yaml"
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            proc = _run_hook(_payload("Edit", corpus_path), env_extra=env_extra)
            self.assertEqual(proc.returncode, 0)
            recs = _read_log_records(log_file)
            events = [r.get("event") for r in recs]
            self.assertIn("fired", events)

    def test_log_records_are_valid_ndjson(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "corpus_refresh_log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            env_extra = {
                "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
                "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
                "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
            }
            _run_hook(_payload("Write", corpus_path), env_extra=env_extra)
            self.assertTrue(log_file.exists())
            for line in log_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)  # raises on malformed JSON
                self.assertEqual(rec.get("schema_version"), "auditooor.corpus_refresh_log.v1")
                self.assertIn("ts_utc", rec)
                self.assertIn("event", rec)
                self.assertIn("reason", rec)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
