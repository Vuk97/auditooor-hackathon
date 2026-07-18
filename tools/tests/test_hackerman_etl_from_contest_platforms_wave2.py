"""Unit tests for ``tools/hackerman-etl-from-contest-platforms-wave2.py``
and the wave-2 helpers added to ``hackerman-etl-from-contest-platforms.py``.

These tests never call ``gh api``. They drive both tools through the
underlying miner's ``cache_file`` path with synthetic payloads modelled
on real wave-1 outputs, and they validate the new wave-2 hooks:

* ``discover_already_mined`` parses ``<platform>__<contest>__<finding>``
  subdir names into a skip set.
* ``fetch_all(sample_all=True)`` returns every repo in the cache.
* ``fetch_all(skip_already_mined=...)`` excludes wave-1 repos from
  ``platform_block["repos"]`` and records them under
  ``platform_block["skipped_already_mined"]``.
* ``convert(skip_already_mined=True)`` plumbs the skip-set discovery.
* ``convert(sample_offset=N)`` skips the first N most-recent repos.
* Summary carries the ``contests_skipped_already_mined`` block.
* Wave-2 runner CLI plumbs ``--all`` + ``--skip-already-mined`` by default
  and supports ``--no-skip-already-mined`` for debug.
* Wave-2 runner ``--per-contest-cap`` default is 75.
* Wave-2 records still pass schema validation.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INNER_TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-contest-platforms.py"
WAVE2_TOOL_PATH = (
    REPO_ROOT / "tools" / "hackerman-etl-from-contest-platforms-wave2.py"
)
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _inner():
    return _load(
        "_hackerman_etl_from_contest_platforms_wave2_test_inner",
        INNER_TOOL_PATH,
    )


def _wave2():
    return _load(
        "_hackerman_etl_from_contest_platforms_wave2_test_runner",
        WAVE2_TOOL_PATH,
    )


def _validator():
    return _load(
        "_hackerman_record_validate_wave2_test", VALIDATOR_PATH
    )


def _c4_finding(
    *,
    issue_id: int = 7,
    risk: str = "2",
    title: str = "Rounding precision loss in fee calc",
    contest_repo: str = "2021-12-old-contest-findings",
):
    return {
        "id": str(issue_id),
        "severity_raw": risk,
        "title": title,
        "url": (
            f"https://github.com/code-423n4/{contest_repo}/issues/{issue_id}"
        ),
        "body": "",
        "handle": "alice",
        "filename": f"alice-{issue_id}.json",
    }


def _sherlock_finding(
    *,
    issue_id: int = 11,
    severity: str = "M",
    title: str = "Stale oracle data allows price manipulation",
    contest_repo: str = "2022-01-old-contest-judging",
):
    return {
        "id": str(issue_id),
        "severity_raw": severity,
        "title": title,
        "url": (
            f"https://github.com/sherlock-audit/{contest_repo}/blob/main/"
            f"{issue_id:03d}-{severity}/{issue_id:03d}-{severity.lower()}.md"
        ),
        "body": "## Impact\nStale oracle data enables price manipulation.",
        "handle": None,
        "filename": f"{issue_id:03d}-{severity}/{issue_id:03d}-{severity.lower()}.md",
    }


def _wave2_cache(*, include_wave1_repo: bool = True):
    code4rena_repos = {
        "2021-12-old-contest-findings": {
            "updated_at": "2021-12-01T00:00:00Z",
            "html_url": (
                "https://github.com/code-423n4/2021-12-old-contest-findings"
            ),
            "findings": [
                _c4_finding(issue_id=7, risk="2"),
                _c4_finding(
                    issue_id=8,
                    risk="3",
                    title="Reentrancy in withdraw allows fund theft",
                ),
            ],
        },
        "2022-02-vintage-findings": {
            "updated_at": "2022-02-01T00:00:00Z",
            "html_url": (
                "https://github.com/code-423n4/2022-02-vintage-findings"
            ),
            "findings": [
                _c4_finding(
                    issue_id=15,
                    risk="1",
                    title="Missing event emission",
                    contest_repo="2022-02-vintage-findings",
                ),
            ],
        },
    }
    if include_wave1_repo:
        code4rena_repos["2024-08-superposition-findings"] = {
            "updated_at": "2024-09-01T00:00:00Z",
            "html_url": (
                "https://github.com/code-423n4/2024-08-superposition-findings"
            ),
            "findings": [
                _c4_finding(
                    issue_id=159,
                    risk="3",
                    contest_repo="2024-08-superposition-findings",
                ),
            ],
        }
    return {
        "code4rena": {
            "org": "code-423n4",
            "pattern": r".+-findings$",
            "skipped_by_sampling": [],
            "skipped_already_mined": [],
            "repos": code4rena_repos,
        },
        "sherlock": {
            "org": "sherlock-audit",
            "pattern": r".+-judging$",
            "skipped_by_sampling": [],
            "skipped_already_mined": [],
            "repos": {
                "2022-01-old-contest-judging": {
                    "updated_at": "2022-01-01T00:00:00Z",
                    "html_url": (
                        "https://github.com/sherlock-audit/"
                        "2022-01-old-contest-judging"
                    ),
                    "findings": [_sherlock_finding(issue_id=11, severity="M")],
                },
            },
        },
    }


class DiscoverAlreadyMinedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _inner()
        self.tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_empty_dir_returns_empty_map(self) -> None:
        self.assertEqual(self.tool.discover_already_mined(self.out_dir), {})

    def test_missing_dir_returns_empty_map(self) -> None:
        ghost = self.out_dir / "does-not-exist"
        self.assertEqual(self.tool.discover_already_mined(ghost), {})

    def test_parses_platform_and_contest_from_subdir_names(self) -> None:
        for name in (
            "code4rena__2024-08-superposition-findings__159",
            "code4rena__2024-08-superposition-findings__86",
            "code4rena__2023-01-astaria-findings__1",
            "sherlock__2022-08-sentiment-judging__17",
            "sherlock__2022-08-sentiment-judging__23",
        ):
            (self.out_dir / name).mkdir()
        mined = self.tool.discover_already_mined(self.out_dir)
        self.assertEqual(set(mined.keys()), {"code4rena", "sherlock"})
        self.assertEqual(
            mined["code4rena"],
            {"2024-08-superposition-findings", "2023-01-astaria-findings"},
        )
        self.assertEqual(mined["sherlock"], {"2022-08-sentiment-judging"})

    def test_ignores_malformed_subdir_names(self) -> None:
        for name in (
            "not-a-record",
            "only_one__double_underscore",
            "code4rena__contest-only",  # missing finding segment
            ".hidden",
        ):
            (self.out_dir / name).mkdir()
        # Add one real match alongside the noise.
        (self.out_dir / "sherlock__real-contest__1").mkdir()
        mined = self.tool.discover_already_mined(self.out_dir)
        self.assertEqual(mined, {"sherlock": {"real-contest"}})


class FetchAllSkipAlreadyMinedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _inner()

    def test_skip_already_mined_excludes_wave1_repo_from_fetched(self) -> None:
        # The cache_file path short-circuits fetch_all to return the
        # payload as-is, so we exercise the LIVE path with a synthetic
        # repo listing instead. To avoid network calls, monkeypatch
        # list_org_findings_repos and _fetch_contest_findings.
        repos_by_platform = {
            "code-423n4": [
                {"name": "2024-08-superposition-findings", "updated_at": "2024-09"},
                {"name": "2021-12-old-contest-findings", "updated_at": "2021-12"},
            ],
            "sherlock-audit": [
                {"name": "2022-08-sentiment-judging", "updated_at": "2022-08"},
                {"name": "2022-01-old-contest-judging", "updated_at": "2022-01"},
            ],
        }
        orig_list = self.tool.list_org_findings_repos
        orig_fetch = self.tool._fetch_contest_findings
        self.tool.list_org_findings_repos = lambda org, pattern: repos_by_platform[org]
        self.tool._fetch_contest_findings = lambda pid, org, repo, *, per_contest_cap: (
            [
                {
                    "id": "1",
                    "severity_raw": "3" if pid == "code4rena" else "H",
                    "title": f"finding from {repo}",
                    "url": f"https://example.invalid/{org}/{repo}/1",
                    "body": "",
                    "handle": "x",
                    "filename": "x.json",
                }
            ]
        )
        try:
            fetched, tier = self.tool.fetch_all(
                self.tool.PLATFORMS,
                sample_size=10,
                per_contest_cap=75,
                sample_all=True,
                skip_already_mined={
                    "code4rena": {"2024-08-superposition-findings"},
                    "sherlock": {"2022-08-sentiment-judging"},
                },
            )
        finally:
            self.tool.list_org_findings_repos = orig_list
            self.tool._fetch_contest_findings = orig_fetch
        self.assertEqual(tier, "tier-2-verified-public-archive")
        c4_block = fetched["code4rena"]
        self.assertNotIn(
            "2024-08-superposition-findings", c4_block["repos"]
        )
        self.assertIn(
            "2024-08-superposition-findings",
            c4_block["skipped_already_mined"],
        )
        self.assertIn("2021-12-old-contest-findings", c4_block["repos"])
        sherlock_block = fetched["sherlock"]
        self.assertNotIn(
            "2022-08-sentiment-judging", sherlock_block["repos"]
        )
        self.assertIn(
            "2022-08-sentiment-judging",
            sherlock_block["skipped_already_mined"],
        )

    def test_max_contests_caps_new_repos_after_skip_set(self) -> None:
        repos_by_platform = {
            "code-423n4": [
                {"name": "2024-08-superposition-findings", "updated_at": "2024-09"},
                {"name": "2024-07-old-a-findings", "updated_at": "2024-07"},
                {"name": "2024-06-old-b-findings", "updated_at": "2024-06"},
                {"name": "2024-05-old-c-findings", "updated_at": "2024-05"},
            ],
            "sherlock-audit": [],
        }
        orig_list = self.tool.list_org_findings_repos
        orig_fetch = self.tool._fetch_contest_findings
        self.tool.list_org_findings_repos = lambda org, pattern: repos_by_platform[org]
        self.tool._fetch_contest_findings = lambda pid, org, repo, *, per_contest_cap: []
        try:
            fetched, _tier = self.tool.fetch_all(
                self.tool.PLATFORMS,
                sample_size=10,
                per_contest_cap=75,
                sample_all=True,
                skip_already_mined={
                    "code4rena": {"2024-08-superposition-findings"},
                },
                max_contests=2,
            )
        finally:
            self.tool.list_org_findings_repos = orig_list
            self.tool._fetch_contest_findings = orig_fetch
        c4_block = fetched["code4rena"]
        # First entry skipped as already-mined; cap of 2 takes the next
        # TWO new ones; the fourth is parked in skipped_by_sampling.
        self.assertEqual(
            set(c4_block["repos"].keys()),
            {"2024-07-old-a-findings", "2024-06-old-b-findings"},
        )
        self.assertIn(
            "2024-08-superposition-findings",
            c4_block["skipped_already_mined"],
        )
        self.assertIn(
            "2024-05-old-c-findings", c4_block["skipped_by_sampling"]
        )

    def test_sample_offset_skips_first_n_repos(self) -> None:
        repos_by_platform = {
            "code-423n4": [
                {"name": "2024-08-superposition-findings", "updated_at": "2024-09"},
                {"name": "2024-07-old-findings", "updated_at": "2024-07"},
                {"name": "2021-12-vintage-findings", "updated_at": "2021-12"},
            ],
            "sherlock-audit": [],
        }
        orig_list = self.tool.list_org_findings_repos
        orig_fetch = self.tool._fetch_contest_findings
        self.tool.list_org_findings_repos = lambda org, pattern: repos_by_platform[org]
        self.tool._fetch_contest_findings = lambda pid, org, repo, *, per_contest_cap: []
        try:
            fetched, _tier = self.tool.fetch_all(
                self.tool.PLATFORMS,
                sample_size=10,
                per_contest_cap=75,
                sample_all=True,
                sample_offset=2,
            )
        finally:
            self.tool.list_org_findings_repos = orig_list
            self.tool._fetch_contest_findings = orig_fetch
        c4_block = fetched["code4rena"]
        self.assertEqual(
            set(c4_block["repos"].keys()), {"2021-12-vintage-findings"}
        )
        self.assertIn(
            "2024-08-superposition-findings", c4_block["skipped_by_sampling"]
        )
        self.assertIn(
            "2024-07-old-findings", c4_block["skipped_by_sampling"]
        )


class ConvertWave2HookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _inner()
        self.validator = _validator()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"
        self.cache_path = self.tmp_path / "cache.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_cache(self, payload) -> Path:
        self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        return self.cache_path

    def test_convert_emits_skipped_already_mined_in_summary(self) -> None:
        # Plant a wave-1 record subdir, then run with skip-already-mined
        # via cache_file. Cache path does NOT exercise the skip-set fetch
        # filter (cache replays as-is), but the summary still surfaces
        # the empty skipped_already_mined block from the cache payload.
        wave1_subdir = (
            self.out_dir
            / "code4rena__2024-08-superposition-findings__159"
        )
        wave1_subdir.mkdir(parents=True)
        # Drop a stub record so the slug is recognised by discover.
        (wave1_subdir / "record.json").write_text("{}", encoding="utf-8")
        cache = self._write_cache(_wave2_cache(include_wave1_repo=True))
        summary = self.tool.convert(
            self.out_dir,
            cache_file=cache,
            skip_already_mined=True,
            sample_all=True,
            per_contest_cap=75,
        )
        self.assertIn("contests_skipped_already_mined", summary)
        self.assertEqual(summary["per_contest_cap"], 75)
        # Records still emit (cache replays existing repos including
        # wave-1, the dedup happens in build_records via record_id).
        self.assertGreater(summary["records_emitted"], 0)
        # Schema validation across emitted records.
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            yaml_path = sub / "record.yaml"
            if not yaml_path.exists():
                continue
            schema = self.validator.load_schema()
            status, errs = self.validator.validate_file(yaml_path, schema)
            self.assertEqual(
                (status, errs), ("valid", []),
                msg=f"{yaml_path}: {errs}",
            )

    def test_wave2_records_validate_against_schema(self) -> None:
        cache = self._write_cache(_wave2_cache(include_wave1_repo=False))
        summary = self.tool.convert(
            self.out_dir,
            cache_file=cache,
            sample_all=True,
            per_contest_cap=75,
        )
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        schema = self.validator.load_schema()
        for sub in self.out_dir.iterdir():
            if not sub.is_dir():
                continue
            yaml_path = sub / "record.yaml"
            self.assertTrue(yaml_path.exists())
            status, errs = self.validator.validate_file(yaml_path, schema)
            self.assertEqual(
                (status, errs), ("valid", []),
                msg=f"{yaml_path}: {errs}",
            )

    def test_per_contest_cap_default_in_wave2_runner_is_75(self) -> None:
        wave2 = _wave2()
        self.assertEqual(wave2.DEFAULT_PER_CONTEST_CAP_WAVE2, 75)


class Wave2RunnerCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.wave2 = _wave2()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.out_dir = self.tmp_path / "out"
        self.cache_path = self.tmp_path / "cache.json"
        self.cache_path.write_text(
            json.dumps(_wave2_cache(include_wave1_repo=False)),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_runner_help_does_not_crash(self) -> None:
        parser = self.wave2.build_parser()
        # Parser should expose the wave-2 flags.
        opts = {a.dest for a in parser._actions}
        self.assertIn("no_skip_already_mined", opts)
        self.assertIn("per_contest_cap", opts)
        self.assertIn("filter_platform", opts)
        self.assertIn("cache_file", opts)

    def test_runner_main_replays_cache_and_returns_zero(self) -> None:
        rc = self.wave2.main(
            [
                "--out-dir",
                str(self.out_dir),
                "--cache-file",
                str(self.cache_path),
                "--json-summary",
                # Use no-skip so the synthetic cache repos aren't filtered.
                "--no-skip-already-mined",
            ]
        )
        self.assertEqual(rc, 0)
        # At least one record subdir should exist.
        subdirs = [p for p in self.out_dir.iterdir() if p.is_dir()]
        self.assertTrue(subdirs)

    def test_runner_main_negative_per_contest_cap_returns_2(self) -> None:
        rc = self.wave2.main(
            [
                "--out-dir",
                str(self.out_dir),
                "--per-contest-cap",
                "-5",
                "--cache-file",
                str(self.cache_path),
            ]
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
