"""Tests for LIFT-24 - extend tools/hooks/auditooor-corpus-change-refresh.sh
matcher to PostToolUse Bash.

R36: pathspec lane=LIFT-24-CORPUS-REFRESH-BASH-MATCHER declared via
tools/agent-pathspec-register.py.

LIFT-9 (PR #194) shipped the hook for Edit/Write/MultiEdit. LIFT-20
audit recommendation (e) flagged that Bash-driven file writes (`cp`,
`sed -i`, `python3 script.py > corpus.jsonl`, `tee`, `rm`, etc.) bypass
the matcher because the hook only registered Write|Edit|MultiEdit.
LIFT-24 extends the hook to also handle PostToolUse Bash payloads by
parsing the command string for write-intent shell shapes that target
the corpus globs.

These tests exercise the Bash extension end-to-end:

- ``cp f.yaml audit/corpus_tags/tags/x/record.yaml`` -> FIRES
- ``sed -i s/x/y/ audit/corpus_tags/tags/x/record.yaml`` -> FIRES
- ``mv /tmp/x audit/corpus_tags/derived/y.jsonl`` -> FIRES
- ``grep foo audit/corpus_tags/tags/x/record.yaml`` -> SKIP (read-only)
- ``cat audit/corpus_tags/derived/global_chain_templates.jsonl`` -> SKIP
- ``python3 build.py > audit/corpus_tags/derived/new.jsonl`` -> FIRES
- ``echo data >> audit/corpus_tags/derived/new.jsonl`` -> FIRES (append)
- ``rm audit/corpus_tags/derived/old.jsonl`` -> FIRES (deletion)
- ``sed -i s/x/y/ /tmp/foo`` -> SKIP (non-corpus path)
- ``ls audit/corpus_tags/`` -> SKIP (read-only directory listing)
- Throttle: two rapid bash writes -> only first FIRES
- Backward compat: Write/Edit/MultiEdit on corpus path still FIRES
"""
from __future__ import annotations

import json
import os
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


def _bash_payload(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})


def _write_payload(tool_name: str, file_path: str) -> str:
    return json.dumps({"tool_name": tool_name, "tool_input": {"file_path": file_path}})


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


class CorpusRefreshBashExtensionTests(unittest.TestCase):
    def _common_env(self, log_file: Path, throttle_file: Path) -> dict:
        return {
            "AUDITOOOR_CORPUS_REFRESH_LOG_FILE": str(log_file),
            "AUDITOOOR_CORPUS_REFRESH_THROTTLE_FILE": str(throttle_file),
            "AUDITOOOR_CORPUS_REFRESH_HOOK_SYNC": "1",
        }

    def test_bash_cp_to_corpus_fires(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "cp /tmp/foo.yaml audit/corpus_tags/tags/sub/record.yaml"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr}")
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")
            self.assertIn("refresh-complete", events, f"events={events}")

    def test_bash_sed_i_on_corpus_fires(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "sed -i s/x/y/ audit/corpus_tags/tags/x/record.yaml"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")

    def test_bash_mv_to_corpus_fires(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "mv /tmp/x audit/corpus_tags/derived/y.jsonl"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")

    def test_bash_redirect_to_corpus_fires(self) -> None:
        """`python3 build.py > audit/corpus_tags/derived/new.jsonl` form."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "python3 build.py > audit/corpus_tags/derived/new.jsonl"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")

    def test_bash_append_redirect_to_corpus_fires(self) -> None:
        """`echo data >> audit/corpus_tags/derived/new.jsonl` form."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "echo data >> audit/corpus_tags/derived/new.jsonl"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")

    def test_bash_rm_on_corpus_fires(self) -> None:
        """Deletion of a corpus file also triggers refresh."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "rm audit/corpus_tags/derived/old.jsonl"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events, f"events={events}")

    def test_bash_grep_on_corpus_skips(self) -> None:
        """Read-only grep on a corpus path must NOT fire a refresh."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "grep foo audit/corpus_tags/tags/x/record.yaml"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events, f"events={events}")
            self.assertNotIn("refresh-complete", events)

    def test_bash_cat_on_corpus_skips(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "cat audit/corpus_tags/derived/global_chain_templates.jsonl"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events)

    def test_bash_ls_on_corpus_skips(self) -> None:
        """`ls audit/corpus_tags/` is a directory listing, not a write."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "ls audit/corpus_tags/derived/"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events)

    def test_bash_sed_non_corpus_path_skips(self) -> None:
        """Write-utility on a NON-corpus path must NOT fire."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "sed -i s/x/y/ /tmp/foo"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events)

    def test_bash_empty_command_skips(self) -> None:
        """Bash payload with empty command body must not crash."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            proc = _run_hook(_bash_payload(""), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events)

    def test_bash_obsidian_path_fires(self) -> None:
        """Bash write to obsidian-vault/anti-patterns/ also fires."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            cmd = "cp /tmp/x.md obsidian-vault/anti-patterns/new_pattern.md"
            proc = _run_hook(_bash_payload(cmd), env_extra=self._common_env(log_file, throttle_file))
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events)

    def test_bash_throttle_blocks_second_rapid_write(self) -> None:
        """Two rapid Bash-driven corpus writes -> only one refresh fires."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            env_extra = self._common_env(log_file, throttle_file)
            env_extra["AUDITOOOR_CORPUS_REFRESH_THROTTLE_SECONDS"] = "600"
            cmd = "cp /tmp/foo audit/corpus_tags/derived/x.jsonl"
            _run_hook(_bash_payload(cmd), env_extra=env_extra)
            _run_hook(_bash_payload(cmd), env_extra=env_extra)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertEqual(events.count("fired"), 1, f"expected 1 fired, got events={events}")
            self.assertIn("skipped-throttled", events)

    def test_backward_compat_write_tool_still_fires(self) -> None:
        """Existing Write/Edit/MultiEdit triggering must remain unchanged."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            proc = _run_hook(
                _write_payload("Write", corpus_path),
                env_extra=self._common_env(log_file, throttle_file),
            )
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertIn("fired", events)
            self.assertIn("refresh-complete", events)

    def test_backward_compat_read_tool_still_skips(self) -> None:
        """Non-write tool (Read) still bypasses the hook."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            log_file = td_path / "log.jsonl"
            throttle_file = td_path / "throttle.ts"
            corpus_path = str(REPO_ROOT / "audit/corpus_tags/tags/dummy.yaml")
            proc = _run_hook(
                _write_payload("Read", corpus_path),
                env_extra=self._common_env(log_file, throttle_file),
            )
            self.assertEqual(proc.returncode, 0)
            events = [r.get("event") for r in _read_log_records(log_file)]
            self.assertNotIn("fired", events)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
