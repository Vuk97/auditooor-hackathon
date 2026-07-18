"""Unit tests for ``tools/hackerman-etl-miner-scaffold.py``.

Covers slug validation, source-channel / target-domain enum checks, the
3-file emission, idempotency (refuse to overwrite without ``--force``),
``--force`` overwrite semantics, and the rendered skeleton's basic
structural invariants (TODO markers present, CLI surface importable,
SOURCE_CHANNEL/TARGET_DOMAIN constants match the scaffold arguments).
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-miner-scaffold.py"


def _load_tool():
    name = "_hackerman_etl_miner_scaffold_under_test"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestSlugValidation(unittest.TestCase):
    def test_valid_lower_kebab(self) -> None:
        mod = _load_tool()
        self.assertEqual(mod.validate_slug("npm-advisories"), "npm-advisories")
        self.assertEqual(mod.validate_slug("foo"), "foo")
        self.assertEqual(
            mod.validate_slug("a1b2-c3d4-e5f6"), "a1b2-c3d4-e5f6"
        )

    def test_invalid_uppercase_rejected(self) -> None:
        mod = _load_tool()
        with self.assertRaises(SystemExit):
            mod.validate_slug("Npm-Advisories")

    def test_invalid_underscore_rejected(self) -> None:
        mod = _load_tool()
        with self.assertRaises(SystemExit):
            mod.validate_slug("npm_advisories")

    def test_invalid_leading_digit_rejected(self) -> None:
        mod = _load_tool()
        with self.assertRaises(SystemExit):
            mod.validate_slug("1npm")

    def test_invalid_trailing_hyphen_rejected(self) -> None:
        mod = _load_tool()
        with self.assertRaises(SystemExit):
            mod.validate_slug("npm-")


class TestEnumValidation(unittest.TestCase):
    def test_invalid_source_channel(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                mod.scaffold(
                    name="fake-test",
                    source_channel="not-a-channel",
                    target_domain="vault",
                    force=False,
                    repo_root=Path(tmp),
                )

    def test_invalid_target_domain(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                mod.scaffold(
                    name="fake-test",
                    source_channel="ghsa",
                    target_domain="not-a-domain",
                    force=False,
                    repo_root=Path(tmp),
                )


class TestEmission(unittest.TestCase):
    def test_three_files_emitted(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=False,
                repo_root=Path(tmp),
            )
            for key in ("miner", "test", "readme"):
                self.assertIn(key, paths)
                self.assertTrue(paths[key].exists(), f"missing {key}: {paths[key]}")

    def test_emitted_paths_follow_convention(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="commit-history",
                target_domain="bridge",
                force=False,
                repo_root=Path(tmp),
            )
            self.assertEqual(paths["miner"].name, "hackerman-etl-from-fake-channel.py")
            self.assertEqual(
                paths["test"].name, "test_hackerman_etl_from_fake_channel.py"
            )
            self.assertEqual(paths["readme"].name, "_MINER_README.md")
            self.assertEqual(paths["readme"].parent.name, "fake_channel")

    def test_miner_body_has_todo_markers(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="dex",
                force=False,
                repo_root=Path(tmp),
            )
            body = paths["miner"].read_text(encoding="utf-8")
            self.assertIn("TODO(miner-author)", body)
            self.assertIn("auditooor.hackerman_record.v1", body)
            self.assertIn('SOURCE_CHANNEL = "ghsa"', body)
            self.assertIn('TARGET_DOMAIN = "dex"', body)

    def test_test_body_references_miner(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="lending",
                force=False,
                repo_root=Path(tmp),
            )
            body = paths["test"].read_text(encoding="utf-8")
            self.assertIn("hackerman-etl-from-fake-channel.py", body)
            self.assertIn('"ghsa"', body)
            self.assertIn('"lending"', body)

    def test_readme_has_provenance_section(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="web-scrape",
                target_domain="oracle",
                force=False,
                repo_root=Path(tmp),
            )
            body = paths["readme"].read_text(encoding="utf-8")
            self.assertIn("## Provenance summary", body)
            self.assertIn("Source channel: ``web-scrape``", body)
            self.assertIn("Target domain: ``oracle``", body)
            self.assertIn("M14-trap", body)


class TestIdempotency(unittest.TestCase):
    def test_second_run_without_force_refuses(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=False,
                repo_root=Path(tmp),
            )
            with self.assertRaises(SystemExit):
                mod.scaffold(
                    name="fake-channel",
                    source_channel="ghsa",
                    target_domain="vault",
                    force=False,
                    repo_root=Path(tmp),
                )

    def test_force_overwrites(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=False,
                repo_root=Path(tmp),
            )
            # Mutate the miner file and confirm force re-emits the
            # canonical scaffold.
            paths["miner"].write_text("MUTATED", encoding="utf-8")
            self.assertEqual(paths["miner"].read_text(encoding="utf-8"), "MUTATED")
            mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=True,
                repo_root=Path(tmp),
            )
            body = paths["miner"].read_text(encoding="utf-8")
            self.assertNotEqual(body, "MUTATED")
            self.assertIn("TODO(miner-author)", body)

    def test_partial_conflict_refuses_without_writing(self) -> None:
        # If even ONE of the 3 files exists and --force is not set, no
        # writes should happen (atomic refusal).
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            miner_path = tmp_path / "tools" / "hackerman-etl-from-fake-channel.py"
            miner_path.parent.mkdir(parents=True, exist_ok=True)
            miner_path.write_text("PRE-EXISTING", encoding="utf-8")
            with self.assertRaises(SystemExit):
                mod.scaffold(
                    name="fake-channel",
                    source_channel="ghsa",
                    target_domain="vault",
                    force=False,
                    repo_root=tmp_path,
                )
            # Confirm miner was NOT clobbered + test/readme were not
            # created.
            self.assertEqual(
                miner_path.read_text(encoding="utf-8"), "PRE-EXISTING"
            )
            self.assertFalse(
                (tmp_path / "tools" / "tests" / "test_hackerman_etl_from_fake_channel.py").exists()
            )
            self.assertFalse(
                (tmp_path / "audit" / "corpus_tags" / "tags" / "fake_channel" / "_MINER_README.md").exists()
            )


class TestRenderedSkeletonImportable(unittest.TestCase):
    def test_rendered_miner_imports(self) -> None:
        # Round-trip: emit, then dynamically import the rendered miner
        # under a unique module name to confirm it is at least
        # syntactically valid Python.
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=False,
                repo_root=Path(tmp),
            )
            spec = importlib.util.spec_from_file_location(
                "_rendered_miner_under_test", str(paths["miner"])
            )
            rendered = importlib.util.module_from_spec(spec)
            assert spec.loader
            spec.loader.exec_module(rendered)
            self.assertTrue(hasattr(rendered, "main"))
            self.assertTrue(hasattr(rendered, "parse_args"))
            self.assertEqual(rendered.SOURCE_CHANNEL, "ghsa")
            self.assertEqual(rendered.TARGET_DOMAIN, "vault")

    def test_rendered_miner_cli_surface(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            paths = mod.scaffold(
                name="fake-channel",
                source_channel="ghsa",
                target_domain="vault",
                force=False,
                repo_root=Path(tmp),
            )
            spec = importlib.util.spec_from_file_location(
                "_rendered_miner_cli_check", str(paths["miner"])
            )
            rendered = importlib.util.module_from_spec(spec)
            assert spec.loader
            spec.loader.exec_module(rendered)
            ns = rendered.parse_args([])
            self.assertTrue(hasattr(ns, "out_dir"))
            self.assertTrue(hasattr(ns, "cache_file"))


if __name__ == "__main__":
    unittest.main()
