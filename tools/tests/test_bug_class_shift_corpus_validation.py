#!/usr/bin/env python3
"""Regression test for R38 mechanism->impact corpus early-validation.

Covers validate_mechanism_corpus + the --validate-corpus CLI path:
  - present, non-empty mechanism_to_impacts corpus -> rc 0, ok-corpus-present
  - empty / missing block corpus -> rc 1, typed defect
  - missing file -> rc 1, defect-corpus-missing
The hardcoded MECHANISM_TO_ACHIEVABLE_IMPACTS fallback stays available either way.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "bug-class-shift-check.py"
_spec = importlib.util.spec_from_file_location("bug_class_shift_check", TOOL)
mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(mod)

pytest.importorskip("yaml")
import yaml  # noqa: E402


def _write_corpus(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "impact_hunting_methodology.yaml"
    p.write_text(content, encoding="utf-8")
    return p


def test_present_corpus_passes(tmp_path):
    corpus = _write_corpus(
        tmp_path,
        yaml.safe_dump(
            {"mechanism_to_impacts": {"halt": ["freeze", "dos"], "overflow": ["theft"]}}
        ),
    )
    rc, payload = mod.validate_mechanism_corpus(corpus)
    assert rc == 0, payload
    assert payload["verdict"] == "ok-corpus-present"
    assert payload["mechanism_to_impacts_count"] == 2
    assert payload["fallback_keys"] > 0


def test_empty_block_is_defect(tmp_path):
    corpus = _write_corpus(tmp_path, yaml.safe_dump({"mechanism_to_impacts": {}}))
    rc, payload = mod.validate_mechanism_corpus(corpus)
    assert rc == 1, payload
    assert payload["verdict"] == "defect-corpus-empty"
    assert payload["mechanism_to_impacts_count"] == 0
    assert "defect" in payload


def test_block_with_only_empty_buckets_is_defect(tmp_path):
    corpus = _write_corpus(
        tmp_path, yaml.safe_dump({"mechanism_to_impacts": {"halt": [], "x": None}})
    )
    rc, payload = mod.validate_mechanism_corpus(corpus)
    assert rc == 1, payload
    assert payload["verdict"] == "defect-corpus-empty"


def test_missing_file_is_defect(tmp_path):
    rc, payload = mod.validate_mechanism_corpus(tmp_path / "nope.yaml")
    assert rc == 1, payload
    assert payload["verdict"] == "defect-corpus-missing"
    assert payload["mechanism_to_impacts_count"] == 0


def test_unparseable_corpus_is_defect(tmp_path):
    corpus = _write_corpus(tmp_path, "mechanism_to_impacts: [unterminated\n")
    rc, payload = mod.validate_mechanism_corpus(corpus)
    assert rc == 1, payload
    assert payload["verdict"] == "defect-corpus-unparseable"


def test_real_shipped_corpus_validates():
    # The corpus that actually ships in-tree should pass (drift early-warning green).
    rc, payload = mod.validate_mechanism_corpus(None)
    assert rc == 0, payload
    assert payload["mechanism_to_impacts_count"] > 0


def test_cli_validate_corpus_present(tmp_path, capsys):
    corpus = _write_corpus(
        tmp_path,
        yaml.safe_dump({"mechanism_to_impacts": {"halt": ["freeze"]}}),
    )
    rc = mod.main(["--validate-corpus", "--corpus-path", str(corpus)])
    assert rc == 0
    assert "ok-corpus-present" in capsys.readouterr().out


def test_cli_validate_corpus_defect(tmp_path, capsys):
    corpus = _write_corpus(tmp_path, yaml.safe_dump({"mechanism_to_impacts": {}}))
    rc = mod.main(["--validate-corpus", "--corpus-path", str(corpus)])
    assert rc == 1
    assert "defect-corpus-empty" in capsys.readouterr().out


def test_cli_requires_draft_without_validate(capsys):
    with pytest.raises(SystemExit):
        mod.main([])
