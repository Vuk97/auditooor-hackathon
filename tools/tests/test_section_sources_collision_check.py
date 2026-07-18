#!/usr/bin/env python3
"""Regression tests for tools/section-sources-collision-check.py.

Test cases:
  (a) clean state  → exit 0
  (b) slug collision (path-set changed for a known slug) → exit 1 + stderr
  (c) path duplication (new slug reuses a known path) → exit 1 + stderr
  (d) malformed obsidian-vault-sync.py (no SECTION_SOURCES) → exit 2 + stderr
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "section-sources-collision-check.py"
KNOWN_LAYERS_JSON = REPO_ROOT / "docs" / "section_sources_known_layers.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("_sscc", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _write_vault_sync(tmp: Path, section_sources_body: str) -> Path:
    """Write a minimal obsidian-vault-sync.py stub with the given SECTION_SOURCES body."""
    content = textwrap.dedent(f"""\
        #!/usr/bin/env python3
        from pathlib import Path
        AUDITS_ROOT = Path.home() / "audits"
        SECTION_SOURCES: dict[str, list[str]] = {section_sources_body}
    """)
    path = tmp / "obsidian-vault-sync.py"
    path.write_text(content, encoding="utf-8")
    return path


def _write_vault_sync_malformed(tmp: Path) -> Path:
    """Write a stub with no SECTION_SOURCES at all."""
    content = textwrap.dedent("""\
        #!/usr/bin/env python3
        # intentionally has no SECTION_SOURCES
        X = 1
    """)
    path = tmp / "obsidian-vault-sync.py"
    path.write_text(content, encoding="utf-8")
    return path


class TestSectionSourcesCollisionCheck(unittest.TestCase):

    # ------------------------------------------------------------------ (a)
    def test_a_clean_state_exit_0(self):
        """Tool exits 0 when live SECTION_SOURCES matches known layers exactly."""
        with tempfile.TemporaryDirectory(prefix="sscc-a-") as _tmp:
            tmp = Path(_tmp)
            # Minimal known layers JSON with one slug.
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"patterns": ["reference/patterns.dsl/**/*.yaml"]}}',
                encoding="utf-8",
            )
            # Matching obsidian-vault-sync.py stub.
            vs = _write_vault_sync(
                tmp,
                '{"patterns": ["reference/patterns.dsl/**/*.yaml"]}',
            )
            rc = MOD.main([
                "--vault-sync", str(vs),
                "--known-layers", str(kl_json),
            ])
            self.assertEqual(rc, 0)

    # ------------------------------------------------------------------ (a2)
    def test_a2_clean_real_files(self):
        """Tool exits 0 against the actual repo files (current state must be clean)."""
        rc = MOD.main([
            "--vault-sync", str(REPO_ROOT / "tools" / "obsidian-vault-sync.py"),
            "--known-layers", str(KNOWN_LAYERS_JSON),
        ])
        self.assertEqual(rc, 0, "Live SECTION_SOURCES collides with known layers — update docs/section_sources_known_layers.json if the change is intentional.")

    # ------------------------------------------------------------------ (b)
    def test_b_slug_collision_exit_1(self):
        """Tool exits 1 when a known slug maps to a different path-set."""
        with tempfile.TemporaryDirectory(prefix="sscc-b-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"patterns": ["reference/patterns.dsl/**/*.yaml"]}}',
                encoding="utf-8",
            )
            # Stub with 'patterns' slug but different path.
            vs = _write_vault_sync(
                tmp,
                '{"patterns": ["reference/patterns.dsl.r*/**/*.yaml"]}',
            )
            rc = MOD.main([
                "--vault-sync", str(vs),
                "--known-layers", str(kl_json),
            ])
            self.assertEqual(rc, 1)

    # ------------------------------------------------------------------ (b2)
    def test_b2_slug_collision_stderr(self):
        """Collision output includes SLUG_MISMATCH token on stderr."""
        import io
        with tempfile.TemporaryDirectory(prefix="sscc-b2-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"detectors": ["detectors/_tier_registry.yaml"]}}',
                encoding="utf-8",
            )
            vs = _write_vault_sync(
                tmp,
                '{"detectors": ["detectors/OTHER.yaml"]}',
            )
            old_stderr = sys.stderr
            sys.stderr = captured = io.StringIO()
            try:
                rc = MOD.main([
                    "--vault-sync", str(vs),
                    "--known-layers", str(kl_json),
                ])
            finally:
                sys.stderr = old_stderr

            self.assertEqual(rc, 1)
            output = captured.getvalue()
            self.assertIn("SLUG_MISMATCH", output)
            self.assertIn("detectors", output)

    # ------------------------------------------------------------------ (c)
    def test_c_path_duplication_exit_1(self):
        """Tool exits 1 when a new slug reuses a path already registered to another slug."""
        with tempfile.TemporaryDirectory(prefix="sscc-c-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"patterns": ["reference/patterns.dsl/**/*.yaml"]}}',
                encoding="utf-8",
            )
            # 'mining' is a new slug (not in known_layers) but reuses patterns' path.
            vs = _write_vault_sync(
                tmp,
                '{"patterns": ["reference/patterns.dsl/**/*.yaml"],'
                ' "mining": ["reference/patterns.dsl/**/*.yaml"]}',
            )
            rc = MOD.main([
                "--vault-sync", str(vs),
                "--known-layers", str(kl_json),
            ])
            self.assertEqual(rc, 1)

    # ------------------------------------------------------------------ (c2)
    def test_c2_path_duplication_stderr(self):
        """Collision output includes PATH_DUPE token on stderr for path duplication."""
        import io
        with tempfile.TemporaryDirectory(prefix="sscc-c2-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"tasks": ["docs/CONTINUATION_PLAN.md"]}}',
                encoding="utf-8",
            )
            vs = _write_vault_sync(
                tmp,
                '{"tasks": ["docs/CONTINUATION_PLAN.md"],'
                ' "tasks-alias": ["docs/CONTINUATION_PLAN.md"]}',
            )
            old_stderr = sys.stderr
            sys.stderr = captured = io.StringIO()
            try:
                rc = MOD.main([
                    "--vault-sync", str(vs),
                    "--known-layers", str(kl_json),
                ])
            finally:
                sys.stderr = old_stderr

            self.assertEqual(rc, 1)
            output = captured.getvalue()
            self.assertIn("PATH_DUPE", output)

    # ------------------------------------------------------------------ (d)
    def test_d_malformed_vault_sync_exit_2(self):
        """Tool exits 2 with stderr explanation when SECTION_SOURCES is absent."""
        import io
        with tempfile.TemporaryDirectory(prefix="sscc-d-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text('{"known_layers": {}}', encoding="utf-8")
            vs = _write_vault_sync_malformed(tmp)
            old_stderr = sys.stderr
            sys.stderr = captured = io.StringIO()
            try:
                rc = MOD.main([
                    "--vault-sync", str(vs),
                    "--known-layers", str(kl_json),
                ])
            finally:
                sys.stderr = old_stderr

            self.assertEqual(rc, 2)
            self.assertIn("ERROR", captured.getvalue())

    # ------------------------------------------------------------------ (d2)
    def test_d2_missing_vault_sync_exit_2(self):
        """Tool exits 2 when the vault-sync path does not exist."""
        import io
        with tempfile.TemporaryDirectory(prefix="sscc-d2-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text('{"known_layers": {}}', encoding="utf-8")
            old_stderr = sys.stderr
            sys.stderr = captured = io.StringIO()
            try:
                rc = MOD.main([
                    "--vault-sync", str(tmp / "does_not_exist.py"),
                    "--known-layers", str(kl_json),
                ])
            finally:
                sys.stderr = old_stderr

            self.assertEqual(rc, 2)
            self.assertIn("ERROR", captured.getvalue())

    # ------------------------------------------------------------------ json flag
    def test_json_flag_emits_clean_status(self):
        """--json flag emits parseable JSON with status=clean on a green run."""
        import io
        with tempfile.TemporaryDirectory(prefix="sscc-json-") as _tmp:
            tmp = Path(_tmp)
            kl_json = tmp / "known_layers.json"
            kl_json.write_text(
                '{"known_layers": {"patterns": ["reference/patterns.dsl/**/*.yaml"]}}',
                encoding="utf-8",
            )
            vs = _write_vault_sync(
                tmp,
                '{"patterns": ["reference/patterns.dsl/**/*.yaml"]}',
            )
            old_stdout = sys.stdout
            sys.stdout = captured = io.StringIO()
            try:
                rc = MOD.main([
                    "--vault-sync", str(vs),
                    "--known-layers", str(kl_json),
                    "--json",
                ])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(rc, 0)
            import json as _json
            data = _json.loads(captured.getvalue())
            self.assertEqual(data["status"], "clean")
            self.assertEqual(data["collisions"], [])


if __name__ == "__main__":
    unittest.main()
