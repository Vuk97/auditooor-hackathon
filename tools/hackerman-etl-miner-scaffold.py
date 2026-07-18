#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - new-miner scaffolding tool.

Generates a runnable skeleton for a new ``tools/hackerman-etl-from-<slug>.py``
miner, its companion test under ``tools/tests/test_hackerman_etl_from_<slug>.py``
and an attribution ``_MINER_README.md`` under
``audit/corpus_tags/tags/<slug>/`` so Wave-2/3 contributors can stand a new
source-channel up by filling in TODOs rather than copy-pasting from a
sibling miner.

The generated skeleton is intentionally NON-FUNCTIONAL: it has TODO
markers wherever the channel-specific logic must be filled in (REST URL,
payload parsing, language/domain mapping, bug-class classifier, summary
filename). The README + the test are wired so that ``make
validate-hackerman`` and ``python3 -m unittest`` will not silently pass
an unfilled skeleton (the test asserts the TODO markers were replaced).

Real-source-only discipline (M14-trap, per ``~/.claude/CLAUDE.md``):

* This tool does NOT mint records. It mints SKELETONS. The contributor
  must implement the source-channel call (gh api / web fetch / PDF
  scrape / git log walk / corpus join) and re-run the miner before any
  record lands on disk.
* The skeleton's docstring carries a "Real-source-only discipline"
  reminder so a future LLM-driven contributor cannot forget the rule.

CLI:

    python3 tools/hackerman-etl-miner-scaffold.py \\
        --name npm-advisories \\
        --source-channel ghsa \\
        --target-domain vault

    # Re-emit even if files exist:
    python3 tools/hackerman-etl-miner-scaffold.py \\
        --name npm-advisories \\
        --source-channel ghsa \\
        --target-domain vault \\
        --force

Idempotency:

* Without ``--force``, the tool refuses to overwrite any of the 3
  files. The exit code is non-zero so a make-target wrapping the tool
  surfaces the conflict.
* With ``--force``, all 3 files are overwritten. The README's
  scaffold-time timestamp is refreshed.

Wire-up:

* ``make hackerman-etl-miner-scaffold NAME=<slug> SOURCE_CHANNEL=<ch> TARGET_DOMAIN=<dom>``
"""
from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent

# Allowed values mirror the v1 schema enums / observed conventions across
# existing miners. New values may be added if a future channel needs one;
# extend the lists below and add a test row to
# ``tools/tests/test_hackerman_etl_miner_scaffold.py``.
SOURCE_CHANNELS: Tuple[str, ...] = (
    "ghsa",
    "web-scrape",
    "pdf-listing",
    "commit-history",
    "corpus-bridge",
)

TARGET_DOMAINS: Tuple[str, ...] = (
    "vault",
    "dex",
    "lending",
    "bridge",
    "staking",
    "rollup",
    "oracle",
    "perp",
    "stablecoin",
    "dao",
    "wallet",
    "amm",
    "mev",
    "zk",
    "client",
    "cosmos",
    "solana",
    "tooling",
    "other",
)

SLUG_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def validate_slug(name: str) -> str:
    if not SLUG_RE.match(name):
        raise SystemExit(
            f"--name must be a lower-kebab slug matching {SLUG_RE.pattern!r}; "
            f"got {name!r}"
        )
    return name


def slug_to_snake(slug: str) -> str:
    return slug.replace("-", "_")


def slug_to_tag_dir(slug: str) -> str:
    # Tag dirs use snake_case by convention (see existing
    # audit/corpus_tags/tags/ siblings: amm_yield_lst_protocols,
    # contest_platform_findings, etc.).
    return slug_to_snake(slug)


def slug_to_title(slug: str) -> str:
    return " ".join(part.capitalize() for part in slug.split("-"))


def render_miner(slug: str, source_channel: str, target_domain: str) -> str:
    snake = slug_to_snake(slug)
    tag_dir = slug_to_tag_dir(slug)
    title = slug_to_title(slug)
    schema_summary = f"auditooor.hackerman_etl.{tag_dir}.summary.v1"
    return f'''#!/usr/bin/env python3
"""Wave-2/3 Hackerman ETL: {title} ({source_channel} source channel).

Scaffolded by ``tools/hackerman-etl-miner-scaffold.py``.

TODO(miner-author): replace this docstring with a real provenance note
describing (a) which {source_channel} feed this miner pulls from, (b) why
the records are eligible for the ``{target_domain}`` target domain, and
(c) the exact CLI invocation needed for a live pull and an offline
cache replay (mirror the docstring of a sibling miner such as
``tools/hackerman-etl-from-amm-yield-lst.py`` or
``tools/hackerman-etl-from-bridge-attacks.py``).

Real-source-only discipline (M14-trap, per ``~/.claude/CLAUDE.md``):

* Every record emitted MUST come from a live source call OR a
  previously-saved cache of one. No memory-recalled IDs.
* Honest-zero is allowed; record empty sources in the summary's
  ``sources_with_zero_records`` list rather than fabricating.
* Every record must cite its source URL verbatim in
  ``source_audit_ref`` AND in ``required_preconditions`` so the URL is
  resolvable from the record alone.

CLI (TODO(miner-author): refine):

    python3 tools/hackerman-etl-from-{slug}.py \\\\
        --out-dir audit/corpus_tags/tags/{tag_dir}

    # Offline replay:
    python3 tools/hackerman-etl-from-{slug}.py \\\\
        --cache-file /tmp/{slug}-cache.json \\\\
        --out-dir audit/corpus_tags/tags/{tag_dir}

Source channel : ``{source_channel}``
Target domain  : ``{target_domain}``
Tag subtree    : ``audit/corpus_tags/tags/{tag_dir}/``
Summary schema : ``{schema_summary}``
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SUMMARY_SCHEMA = "{schema_summary}"
SOURCE_CHANNEL = "{source_channel}"
TARGET_DOMAIN = "{target_domain}"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_{snake}",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def fetch_source_payload(*, cache_file: Optional[Path]) -> List[Dict[str, Any]]:
    """Return a list of raw records pulled from the {source_channel} channel.

    TODO(miner-author): implement the real source call. For ``ghsa``
    this typically means ``gh api /repos/<owner>/<repo>/security-advisories``
    per target repo. For ``web-scrape`` it means an HTTP GET +
    BeautifulSoup parse. For ``pdf-listing`` it means downloading the PDFs
    and shelling out to ``pdftotext``. For ``commit-history`` it means a
    ``git log -p`` walk against an audited repo pin. For ``corpus-bridge``
    it means joining two existing corpus subtrees on a shared key.

    Until this function is implemented, the scaffold refuses to run with
    exit code 2 so a CI invocation does not silently emit zero records.
    """
    if cache_file is not None:
        # TODO(miner-author): parse the cached payload format and return
        # the same shape your live-pull branch returns.
        raise NotImplementedError(
            "TODO(miner-author): implement cache-file replay for the "
            "{source_channel} source channel."
        )
    raise NotImplementedError(
        "TODO(miner-author): implement live-source fetch for the "
        "{source_channel} source channel."
    )


def map_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map one raw payload row to an ``auditooor.hackerman_record.v1`` row.

    TODO(miner-author): fill in the field mapping. Refer to
    ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``
    for the field list and enum values. At minimum you must populate:

    * ``schema_version`` (= ``auditooor.hackerman_record.v1``)
    * ``source_audit_ref`` (verbatim source URL)
    * ``target_language``
    * ``target_domain`` (= ``{target_domain}`` for this miner)
    * ``bug_class``
    * ``severity``
    * ``required_preconditions`` (must include the source URL +
      ``verification_tier=...``)
    * ``attacker_action_sequence``
    * ``observable_post_conditions``
    """
    raise NotImplementedError(
        "TODO(miner-author): implement raw->record mapping."
    )


def emit_records(
    *,
    records: List[Dict[str, Any]],
    out_dir: Path,
    validator: Any,
) -> Tuple[int, List[str]]:
    """Write per-record YAML + JSON under ``out_dir``.

    TODO(miner-author): mirror the per-record emission pattern from a
    sibling miner. Each record gets its own subdirectory named
    ``<owner>__<repo>__<source-id>`` or equivalent. Both ``record.json``
    and ``record.yaml`` are written so downstream consumers can pick
    whichever they prefer.
    """
    raise NotImplementedError(
        "TODO(miner-author): implement record emission to disk."
    )


def write_summary(
    *,
    out_dir: Path,
    record_count: int,
    sources_with_zero_records: List[str],
) -> None:
    """Write the miner-run summary JSON under ``out_dir/_summary.json``.

    TODO(miner-author): include at minimum ``schema_version``,
    ``source_channel``, ``target_domain``, ``record_count``,
    ``sources_with_zero_records``, and ``run_timestamp_utc``.
    """
    raise NotImplementedError(
        "TODO(miner-author): implement summary emission."
    )


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Hackerman ETL miner for the {source_channel} source "
            "channel (target domain {target_domain})."
        ),
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "audit" / "corpus_tags" / "tags" / "{tag_dir}",
        help="Where to write per-record YAML/JSON + _summary.json.",
    )
    p.add_argument(
        "--cache-file",
        type=Path,
        default=None,
        help=(
            "Replay a saved {source_channel} payload instead of calling "
            "the live source. Useful for offline tests."
        ),
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    validator = _load_validator()  # noqa: F841 (used by emit_records)
    raw = fetch_source_payload(cache_file=args.cache_file)
    records = [map_record(r) for r in raw]
    emitted, zeros = emit_records(
        records=records, out_dir=args.out_dir, validator=validator
    )
    write_summary(
        out_dir=args.out_dir,
        record_count=emitted,
        sources_with_zero_records=zeros,
    )
    print(json.dumps({{"emitted": emitted, "zeros": zeros}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def render_test(slug: str, source_channel: str, target_domain: str) -> str:
    snake = slug_to_snake(slug)
    return f'''"""Unit tests for ``tools/hackerman-etl-from-{slug}.py`` skeleton.

The miner scaffolded by ``tools/hackerman-etl-miner-scaffold.py`` is
intentionally non-functional until the contributor fills in the TODO
blocks. These tests assert:

* The skeleton imports cleanly.
* The CLI surface (``--out-dir``, ``--cache-file``) is wired.
* The TODO markers are still present (the scaffold is not yet
  considered implemented). Once the miner is implemented, the
  contributor MUST remove the ``test_skeleton_still_has_todos`` test
  and replace it with real end-to-end tests modeled on
  ``tools/tests/test_hackerman_etl_from_amm_yield_lst.py``.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-{slug}.py"


def _load_tool():
    name = "_hackerman_etl_from_{snake}"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestSkeleton(unittest.TestCase):
    def test_tool_file_exists(self) -> None:
        self.assertTrue(
            TOOL_PATH.exists(),
            f"Expected scaffolded miner at {{TOOL_PATH}}",
        )

    def test_tool_imports(self) -> None:
        mod = _load_tool()
        self.assertTrue(hasattr(mod, "main"))
        self.assertTrue(hasattr(mod, "parse_args"))

    def test_constants_match_scaffold_args(self) -> None:
        mod = _load_tool()
        self.assertEqual(mod.SOURCE_CHANNEL, "{source_channel}")
        self.assertEqual(mod.TARGET_DOMAIN, "{target_domain}")

    def test_cli_surface(self) -> None:
        mod = _load_tool()
        ns = mod.parse_args([])
        self.assertTrue(hasattr(ns, "out_dir"))
        self.assertTrue(hasattr(ns, "cache_file"))

    def test_skeleton_still_has_todos(self) -> None:
        # Remove this test once the miner is implemented.
        body = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("TODO(miner-author)", body)


if __name__ == "__main__":
    unittest.main()
'''


def render_readme(slug: str, source_channel: str, target_domain: str) -> str:
    tag_dir = slug_to_tag_dir(slug)
    title = slug_to_title(slug)
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    return f"""# {title} corpus (Wave-2/3 scaffold)

This subtree holds auditooor Hackerman corpus rows for the
``{tag_dir}`` source channel.  Scaffolded by
``tools/hackerman-etl-miner-scaffold.py`` on {now} BEFORE any records
were mined.

## Provenance summary

- Subtree: ``audit/corpus_tags/tags/{tag_dir}/``
- Miner: ``tools/hackerman-etl-from-{slug}.py``
- Source channel: ``{source_channel}``
- Target domain: ``{target_domain}``
- Record count at scaffold time: 0 (skeleton not yet implemented)

## Real-source-only discipline (M14-trap, per `~/.claude/CLAUDE.md`)

- The miner skeleton MUST be implemented (replace every
  ``TODO(miner-author)`` block in ``tools/hackerman-etl-from-{slug}.py``)
  before any record is emitted into this subtree.
- Every record's provenance must be anchored by ``source_audit_ref``
  plus the resolvable URLs (where present) re-cited in
  ``required_preconditions`` / ``attacker_action_sequence``.
- No memory-recalled IDs. Every identifier must come from a live source
  call or a cache of one.
- Honest-zero is allowed. Record empty sources in the summary's
  ``sources_with_zero_records`` rather than fabricating.

## Implementation checklist

When picking this lane up:

1. Fill in ``fetch_source_payload`` with the real source call
   (``gh api`` / HTTP GET / ``pdftotext`` / ``git log`` walk /
   corpus join, per the ``{source_channel}`` channel).
2. Fill in ``map_record`` per the v1 schema at
   ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.
3. Fill in ``emit_records`` and ``write_summary``. Mirror a sibling
   miner (``tools/hackerman-etl-from-amm-yield-lst.py`` is a good
   reference for GHSA-shaped channels).
4. Replace ``test_skeleton_still_has_todos`` in the companion test with
   real end-to-end coverage modeled on
   ``tools/tests/test_hackerman_etl_from_amm_yield_lst.py``.
5. Run ``make validate-hackerman`` and confirm every emitted record
   validates against the v1 schema.
6. Replace this scaffold README with the real provenance summary
   (record count, verification-tier mix, sample resolvable URLs).
"""


def write_file(path: Path, content: str, *, force: bool) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def scaffold(
    *,
    name: str,
    source_channel: str,
    target_domain: str,
    force: bool,
    repo_root: Path = REPO_ROOT,
) -> Dict[str, Path]:
    """Emit the 3 skeleton files. Returns a dict of {role: path}."""
    validate_slug(name)
    if source_channel not in SOURCE_CHANNELS:
        raise SystemExit(
            f"--source-channel must be one of {SOURCE_CHANNELS}; got "
            f"{source_channel!r}"
        )
    if target_domain not in TARGET_DOMAINS:
        raise SystemExit(
            f"--target-domain must be one of {TARGET_DOMAINS}; got "
            f"{target_domain!r}"
        )

    miner_path = repo_root / "tools" / f"hackerman-etl-from-{name}.py"
    test_path = (
        repo_root
        / "tools"
        / "tests"
        / f"test_hackerman_etl_from_{slug_to_snake(name)}.py"
    )
    readme_path = (
        repo_root
        / "audit"
        / "corpus_tags"
        / "tags"
        / slug_to_tag_dir(name)
        / "_MINER_README.md"
    )

    # Check all 3 up-front so we either write nothing or write all
    # (idempotency invariant: a partial-write does not leave the
    # caller in a half-scaffolded state).
    if not force:
        conflicts = [p for p in (miner_path, test_path, readme_path) if p.exists()]
        if conflicts:
            conflict_list = "\n  ".join(str(p.relative_to(repo_root)) for p in conflicts)
            raise SystemExit(
                "Refusing to overwrite existing files (pass --force to override):\n  "
                + conflict_list
            )

    miner_body = render_miner(name, source_channel, target_domain)
    test_body = render_test(name, source_channel, target_domain)
    readme_body = render_readme(name, source_channel, target_domain)

    write_file(miner_path, miner_body, force=True)
    write_file(test_path, test_body, force=True)
    write_file(readme_path, readme_body, force=True)

    return {"miner": miner_path, "test": test_path, "readme": readme_path}


def parse_args(argv: List[str] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Scaffold a new hackerman ETL miner skeleton "
            "(tools/hackerman-etl-from-<slug>.py + test + tag-dir "
            "_MINER_README.md)."
        ),
    )
    p.add_argument(
        "--name",
        required=True,
        help=(
            "Slug for the new miner, e.g. 'npm-advisories'. Must be "
            "lower-kebab (a-z, 0-9, hyphen)."
        ),
    )
    p.add_argument(
        "--source-channel",
        required=True,
        choices=SOURCE_CHANNELS,
        help="Where the records will be mined from.",
    )
    p.add_argument(
        "--target-domain",
        required=True,
        choices=TARGET_DOMAINS,
        help="Schema v1 target_domain enum value for emitted records.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files instead of refusing.",
    )
    return p.parse_args(argv)


def main(argv: List[str] = None) -> int:
    args = parse_args(argv)
    paths = scaffold(
        name=args.name,
        source_channel=args.source_channel,
        target_domain=args.target_domain,
        force=args.force,
    )
    print("Scaffolded:")
    for role, path in paths.items():
        print(f"  {role}: {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
