#!/usr/bin/env python3
"""Convert Sherlock + Code4rena + Cantina Critical-class findings (lifted from
the Solodit MCP) into hackerman_record v1 YAML.

EXEC-WAVE8-SOLODIT-CRITICAL. Sister tool to
`hackerman-etl-from-sherlock-c4-historic.py` (Wave 6b-v2). The reference tool
covered HIGH-severity Sherlock + Code4rena. This tool extends the same
discipline to Cantina and to the "Critical-class" top-severity slice of all
three platforms.

Severity-bucket reality (documented honestly, M14-trap avoided):
- Solodit's MCP `severity` enum is restricted to `HIGH|MEDIUM|LOW|GAS`.
  Sending `CRITICAL` triggers a 400 from the Solodit API.
- Sherlock and Code4rena use H-1/H-2/H-3 as their top-severity class
  (functionally "Critical"). Cantina natively labels findings "Critical"
  AND "High"; Solodit normalizes both into the HIGH bucket.
- This tool therefore queries `severity=["HIGH"]` per platform and treats
  the high-quality slice (Quality >= 4/5, sorted by Quality desc) as the
  Critical-class proxy that Solodit's normalized index makes available.
- The commit body MUST disclose this normalization explicitly; the records
  themselves carry `severity_at_finding` verbatim from the Solodit row.

The on-disk input shape matches the existing Wave 6b-v2 tool. Reuses the
parsing/inference primitives from
`tools/hackerman-etl-from-sherlock-c4-historic.py` (loaded by spec; the
reference tool is not modified).

Provenance carried into every record (identical to Wave 6b-v2 + Cantina):
- `source_audit_ref` = the raw GitHub source URL OR the Solodit per-finding
  URL when no GitHub source URL was provided. Cantina PDF findings often
  ship only the Solodit URL (and a Cantina-hosted PDF reference embedded in
  body text); for those rows the Solodit URL is the verbatim ref we cite.
- `target_repo` = GitHub owner/repo extracted from the Source: line when
  present; for Cantina PDF-only findings we fall back to
  `cantina-audit/<protocol-slug>` so the record-id stays distinct and
  parseable, with the verbatim solodit_url still in `source_audit_ref`.
- `severity_at_finding` = lower-cased severity tag verbatim from Solodit
  (today: always `high` since Solodit's index normalizes Cantina Critical
  into HIGH).
- `fix_pattern` = same Wave 6b-v2 disclaimer; never asserts mitigation
  has shipped.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"

# Reuse Wave 6b-v2 helpers by importing the reference tool. The reference
# tool is committed at tools/hackerman-etl-from-sherlock-c4-historic.py
# (PR #726 commit 08cbbc835) and MUST NOT be modified by this script.
#
# NOTE (wave-1-hackerman-capability-lift branch, 2026-05-16): the reference
# tool ships on sister exec branches (`exec-wave7-make-audit-deep-wiring`,
# commits 08cbbc8358 / 0a541412fb / 1da4848627) but is NOT present on this
# capability-lift branch. To keep `import hackerman-etl-from-solodit-critical-platforms`
# from hard-failing at module-load time (which previously broke 8 unit
# tests at setUp), we lazy-load the reference + validator on first use.
# Tests that do not need the sibling helpers (e.g. the `--out-dir` only
# CLI guard) can still run; tests that DO need them skip gracefully via
# the public `SISTER_MODULE_AVAILABLE` flag below.
REF_TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-sherlock-c4-historic.py"
SISTER_MODULE_AVAILABLE = REF_TOOL_PATH.is_file()
SISTER_MODULE_MISSING_REASON = (
    f"depends-on-sister-branch: {REF_TOOL_PATH.name} ships on "
    "`exec-wave7-make-audit-deep-wiring` (commit 08cbbc8358); not present "
    "on `wave-1-hackerman-capability-lift`"
)


def _load_ref_tool() -> Any:
    if not REF_TOOL_PATH.is_file():
        raise ModuleNotFoundError(SISTER_MODULE_MISSING_REASON)
    spec = importlib.util.spec_from_file_location(
        "_hackerman_etl_sherlock_c4_historic_for_critical",
        str(REF_TOOL_PATH),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_critical_platforms",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_REF: Any | None = None
_VALIDATOR: Any | None = None


def _ref() -> Any:
    """Lazy accessor for the Wave 6b-v2 reference module.

    Raises ModuleNotFoundError with `SISTER_MODULE_MISSING_REASON` if the
    sibling module is not on disk (cross-branch case). Callers that want
    to degrade gracefully should check `SISTER_MODULE_AVAILABLE` first.
    """
    global _REF
    if _REF is None:
        _REF = _load_ref_tool()
    return _REF


def _validator() -> Any:
    global _VALIDATOR
    if _VALIDATOR is None:
        _VALIDATOR = _load_validator()
    return _VALIDATOR


def __getattr__(name: str) -> Any:
    """Module-level lazy re-export of Wave 6b-v2 helpers.

    Accessing any of HEADER_RE / URL_LINE_RE / FIRM_LINE_RE / SOURCE_LINE_RE
    / GITHUB_REPO_RE / YEAR_IN_URL_RE / slugify / repo_slug_part /
    infer_domain / infer_bug_attack / infer_impact / infer_target_language
    / extract_year / yaml_dump / parse_mcp_file resolves to the matching
    attribute on the lazy-loaded reference module. Raises AttributeError
    for anything else (so `from module import X` for unrelated names still
    fails fast).
    """
    _REF_NAMES = {
        "HEADER_RE",
        "URL_LINE_RE",
        "FIRM_LINE_RE",
        "SOURCE_LINE_RE",
        "GITHUB_REPO_RE",
        "YEAR_IN_URL_RE",
        "slugify",
        "repo_slug_part",
        "infer_domain",
        "infer_bug_attack",
        "infer_impact",
        "infer_target_language",
        "extract_year",
        "yaml_dump",
        "parse_mcp_file",
    }
    if name in _REF_NAMES:
        return getattr(_ref(), name)
    raise AttributeError(f"module has no attribute {name!r}")


# Cantina-specific protocol-slug extraction from the Solodit URL itself.
# Cantina-PDF rows look like:
#   https://solodit.cyfrin.io/issues/<slug>-cantina-none-<protocol>-pdf
# We extract <protocol> for use as the synthetic repo-slug fallback.
_CANTINA_PROTOCOL_RE = re.compile(
    r"^https?://solodit\.cyfrin\.io/issues/.+?-cantina-(?:none-)?(?P<protocol>[a-z0-9._-]+?)(?:-pdf|-git)?/?$",
    re.IGNORECASE,
)


def extract_target_repo_with_cantina_fallback(
    source_url: str,
    solodit_url: str,
    firm: str,
) -> str:
    """Like Wave 6b-v2 ``extract_target_repo`` but adds a Cantina fallback.

    Wave 6b-v2 returned ``unknown/solodit`` when no GitHub source URL was
    present. For Cantina PDF-only findings, that loses too much information.
    We synthesize ``cantina-audit/<protocol-slug>`` from the Solodit URL slug.
    The verbatim solodit_url is still cited in source_audit_ref, so this
    only shapes the record_id/filename, not the provenance claim.
    """
    ref = _ref()
    if source_url:
        match = ref.GITHUB_REPO_RE.search(source_url)
        if match:
            owner = ref.repo_slug_part(match.group("owner"))
            repo = ref.repo_slug_part(match.group("repo"))
            return f"{owner}/{repo}"
    if "cantina" in (firm or "").lower():
        cantina_match = _CANTINA_PROTOCOL_RE.match(solodit_url or "")
        if cantina_match:
            protocol = ref.repo_slug_part(cantina_match.group("protocol"), max_len=64)
            if protocol and protocol != "none":
                return f"cantina-audit/{protocol}"
    return "unknown/solodit"


def build_record(item: dict[str, Any]) -> dict[str, Any]:
    """Critical-platforms variant of Wave 6b-v2 build_record.

    Differences from the reference build_record:
    - Uses ``extract_target_repo_with_cantina_fallback`` so Cantina PDF rows
      keep a meaningful target_repo slug.
    - record_id slug uses a ``critical:`` namespace prefix (Wave 6b-v2 used
      ``historic:``) so the two lifts can be distinguished on disk.
    - fix_pattern disclaimer is identical to Wave 6b-v2 (no fabrication of
      mitigation state).
    """
    ref = _ref()
    title = item["title"]
    body = item.get("body_snippet", "")
    severity = item["severity"]
    source_url = item.get("source_url") or ""
    solodit_url = item.get("solodit_url") or ""
    firm = item.get("firm", "") or "Sherlock"
    target_repo = extract_target_repo_with_cantina_fallback(source_url, solodit_url, firm)
    full_text = "\n".join([title, body, item.get("protocol", "")])
    domain = ref.infer_domain(full_text)
    bug_class, attack_class = ref.infer_bug_attack(full_text)
    impact = ref.infer_impact(full_text)
    target_language = ref.infer_target_language(target_repo, body)
    year = ref.extract_year(source_url, solodit_url)
    source_audit_ref = source_url or solodit_url or f"solodit:{item['solodit_id']}"
    source_audit_ref = source_audit_ref[:240]
    identity_seed = f"critical-class\n{firm.lower()}\nsolodit-{item['solodit_id']}\n{source_audit_ref}"
    digest = hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:12]
    firm_slug = ref.slugify(firm, max_len=24) or "sherlock"
    record_id = f"critical:{firm_slug}:{item['solodit_id']}:{digest}"
    component = (item.get("protocol") or title).strip()[:240] or "unknown-component"
    function_hint = ref.slugify(title, max_len=48).replace("-", "_") or "unknown_function"
    if target_language == "solidity":
        signature = f"function-name-hint: {function_hint}"
    elif target_language == "rust":
        signature = f"fn-name-hint: {function_hint}"
    elif target_language == "go":
        signature = f"func-name-hint: {function_hint}"
    else:
        signature = f"name-hint: {function_hint}"
    shape_tags = [
        ref.slugify(attack_class),
        ref.slugify(f"{target_language}-{bug_class}"),
        ref.slugify(f"firm-{firm}", max_len=48),
        "critical-class",
        "inferred-function-name",
    ]
    seen = set()
    shape_tags = [t for t in shape_tags if t and not (t in seen or seen.add(t))]
    attacker_action = re.sub(r"\s+", " ", body).strip()[:800] or (
        f"Exercise the {component} path described by {title}."
    )
    precondition = (
        f"{firm}/{item.get('protocol', 'unknown')} {domain} component reachable; reproduce per {source_audit_ref}"
    )[:1000]
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "target_domain": domain,
        "target_language": target_language,
        "target_repo": target_repo,
        "target_component": component,
        "function_shape": {
            "raw_signature": signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": attacker_action,
        "required_preconditions": [precondition],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": ref.dollar_class(severity, impact),
        "fix_pattern": (
            f"Refer to {firm} judging discussion at {source_audit_ref} for the recommended mitigation. "
            "Do not assume mitigation has shipped without confirming the protocol's post-audit fix commit."
        )[:1000],
        "fix_anti_pattern_avoided": (
            "shipping detector-shaped symptoms without confirming the upstream protocol fix commit"
        ),
        "severity_at_finding": severity,
        "year": year,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


def output_filename(record: dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{_ref().slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def convert(
    inputs: list[Path],
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_files = 0
    parse_errors: list[str] = []
    ref = _ref()
    for path in inputs:
        if not path.is_file():
            parse_errors.append(f"missing input: {path}")
            continue
        scanned_files += 1
        try:
            findings.extend(ref.parse_mcp_file(path))
        except Exception as exc:  # noqa: BLE001
            parse_errors.append(f"{path}: parse error: {exc}")
            continue
    seen_ids: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in findings:
        sid = item["solodit_id"]
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        unique.append(item)
        if limit is not None and len(unique) >= limit:
            break
    records: list[dict[str, Any]] = []
    build_errors: list[str] = []
    for item in unique:
        try:
            records.append(build_record(item))
        except Exception as exc:  # noqa: BLE001
            build_errors.append(f"solodit-{item['solodit_id']}: build error: {exc}")
    files: list[str] = []
    validator = _validator()
    schema = validator.load_schema()
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    validation_errors: list[str] = []
    for record in records:
        out_path = out_dir / output_filename(record)
        files.append(str(out_path))
        rendered = ref.yaml_dump(record)
        try:
            import yaml as _yaml

            rendered_doc = _yaml.safe_load(rendered)
        except Exception as exc:  # noqa: BLE001
            validation_errors.append(f"{out_path}: yaml parse failure: {exc}")
            continue
        errs = validator.validate_doc(rendered_doc, schema)
        if errs:
            validation_errors.extend(f"{out_path}: {err}" for err in errs)
            continue
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "inputs": [str(p) for p in inputs],
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "scanned_files": scanned_files,
        "scanned_findings": len(findings),
        "unique_findings": len(unique),
        "records_emitted": len(records) - len(validation_errors),
        "parse_errors": parse_errors,
        "build_errors": build_errors,
        "validation_errors": validation_errors,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        required=False,
        help="Path to a JSON file containing raw MCP search results; repeatable.",
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    inputs = [Path(p).expanduser().resolve() for p in args.input]
    if not inputs:
        print(
            "no --input files provided; this tool consumes Solodit MCP results "
            "(real source only). Exiting BLOCKED-NO-REAL-SOURCE.",
            file=sys.stderr,
        )
        return 2
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        inputs,
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Sherlock+Code4rena+Cantina critical-class ETL: "
            f"files={summary['scanned_files']} findings={summary['scanned_findings']} "
            f"unique={summary['unique_findings']} records={summary['records_emitted']} "
            f"validation_errors={len(summary['validation_errors'])}"
        )
    rc = 0
    if summary["parse_errors"] or summary["build_errors"] or summary["validation_errors"]:
        rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
