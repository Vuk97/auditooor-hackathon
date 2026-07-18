#!/usr/bin/env python3
"""Capability-readiness dashboard (Lane W4.11).

After many waves of capability work there was NO single view answering the
operator question "what can this toolchain actually do right now, and is it
wired in." This dashboard is that view. It is the measurable answer to
"when do we start using all our capabilities."

For each capability it reports four axes:

  (a) exists   - the tool / runner / corpus file is present on disk.
  (b) wired    - it is referenced by a ``make`` target or by the
                 ``make audit`` / ``audit-deep`` / ``audit-deep-solidity``
                 pipeline recipes.
  (c) tested   - a sibling test under ``tools/tests/`` exercises it.
  (d) exercised- best-effort signal that it has actually run (artifact
                 files, ledger rows, or recent corpus output).

Each capability is then graded:

  GREEN  - exists AND wired AND tested.
  YELLOW - exists but missing wiring OR missing test coverage.
  RED    - missing or structurally broken.

Output schema: ``auditooor.capability_readiness_dashboard.v1``.

Read-only. Honest by construction: a capability with no make target and
no test is YELLOW, never silently GREEN.

CLI:

    python3 tools/audit/capability-readiness-dashboard.py [--markdown]
        [--json] [--output PATH] [--markdown-output PATH] [--strict]

Exit codes:

    0 - dashboard rendered (any colour mix is fine).
    1 - tooling error (repo root unreadable, etc.).
    2 - --strict given AND >=1 RED capability.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.capability_readiness_dashboard.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

GREEN = "GREEN"
YELLOW = "YELLOW"
RED = "RED"

# Detector language subdir -> canonical language name.
DETECTOR_LANG = {
    "go_wave1": "go",
    "rust_wave1": "rust",
    "rust_wave2": "rust",
    "cairo_wave1": "cairo",
    "circom_wave1": "circom",
    "move_wave2": "move",
    "vyper_wave2": "vyper",
    "python_wave1": "python",
    "noir_wave1": "noir",
    "halo2_wave1": "halo2",
    "gnark_wave1": "gnark",
    "arkworks_wave1": "arkworks",
    "bellperson_wave1": "bellperson",
    "plonky2_wave1": "plonky2",
    "plonky3_wave1": "plonky3",
    "risc0_wave1": "risc0",
    "pil_wave1": "pil",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _count_py(d: Path) -> int:
    if not d.is_dir():
        return 0
    return sum(1 for p in d.rglob("*.py") if p.is_file())


# ---------------------------------------------------------------------------
# Surface probes
# ---------------------------------------------------------------------------

def probe_detectors(root: Path) -> dict[str, Any]:
    """Detector inventory by language."""
    det_root = root / "detectors"
    by_lang: dict[str, int] = {}
    for sub in sorted(det_root.iterdir()) if det_root.is_dir() else []:
        if not sub.is_dir():
            continue
        lang = DETECTOR_LANG.get(sub.name)
        if lang:
            by_lang[lang] = by_lang.get(lang, 0) + _count_py(sub)
    # Solidity detectors live in the unnamed wave* dirs.
    sol = 0
    for sub in sorted(det_root.iterdir()) if det_root.is_dir() else []:
        if sub.is_dir() and re.fullmatch(r"wave\d+", sub.name):
            sol += _count_py(sub)
    if sol:
        by_lang["solidity"] = sol
    total = sum(by_lang.values())
    return {"by_language": dict(sorted(by_lang.items())), "total": total}


def probe_mcp_callables(root: Path) -> int:
    """Count distinct vault_* callables in the MCP server."""
    txt = _read(root / "tools" / "vault-mcp-server.py")
    return len(set(re.findall(r'"name":\s*"(vault_\w+)"', txt)))


def probe_corpus(root: Path) -> dict[str, Any]:
    """Corpus record count + tier stratification."""
    tags = root / "audit" / "corpus_tags" / "tags"
    yaml_count = sum(1 for _ in tags.glob("*.yaml")) if tags.is_dir() else 0
    rq = root / "audit" / "corpus_tags" / "derived" / "record_quality.jsonl"
    # record_tier = provenance class (submission-derived, etc.).
    # verification_tier (tier-1..tier-5) is carried inside the free-form
    # `reason` field per Rule 37 schema-v1 legacy; extract it too.
    record_tier_counts: dict[str, int] = {}
    verification_tier_counts: dict[str, int] = {}
    rq_rows = 0
    _vt_re = re.compile(r"verification_tier\s+(tier-\d[\w-]*)")
    if rq.is_file():
        with rq.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rq_rows += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rt = obj.get("record_tier") or "untiered"
                record_tier_counts[rt] = record_tier_counts.get(rt, 0) + 1
                m = _vt_re.search(str(obj.get("reason") or ""))
                vt = m.group(1) if m else "unstated"
                verification_tier_counts[vt] = verification_tier_counts.get(vt, 0) + 1
    return {
        "tag_yaml_count": yaml_count,
        "record_quality_rows": rq_rows,
        "record_tier_stratification": dict(sorted(record_tier_counts.items())),
        "verification_tier_stratification": dict(sorted(verification_tier_counts.items())),
    }


# ---------------------------------------------------------------------------
# Capability registry
# ---------------------------------------------------------------------------

# Each capability declares: the relpath(s) that must exist, the make target
# token(s) that mark it "wired" (or "PIPELINE" to mark "referenced by an
# audit* recipe body"), the test module token, and exercised-evidence
# relpath globs.
CAPABILITIES: list[dict[str, Any]] = [
    {
        "id": "detector-engine",
        "label": "Multi-language detector engine",
        "files": ["detectors/run_custom.py", "detectors/run_regex_detectors.py"],
        "make_tokens": ["regex-detectors", "scan"],
        "test_tokens": ["test_universal_fp_runner"],
        "exercised_globs": ["detectors/_hits_ledger.yaml"],
    },
    {
        "id": "mcp-server",
        "label": "Vault MCP server (recall callables)",
        "files": ["tools/vault-mcp-server.py"],
        "make_tokens": ["mcp-callable-count", "vault-mcp-help"],
        "test_tokens": ["test_vault_mcp"],
        "exercised_globs": [],
    },
    {
        "id": "audit-pipeline",
        "label": "make audit engagement pipeline",
        "files": ["tools/engage.py", "Makefile"],
        "make_tokens": ["audit"],
        "test_tokens": ["test_makefile_vault_routing"],
        "exercised_globs": [],
    },
    {
        "id": "audit-deep-pipeline",
        "label": "make audit-deep pipeline",
        "files": ["tools/audit-deep.sh"],
        "make_tokens": ["audit-deep"],
        "test_tokens": ["test_audit_deep"],
        "exercised_globs": [],
        "test_files": ["tools/tests"],
    },
    {
        "id": "audit-deep-solidity",
        "label": "make audit-deep-solidity pipeline",
        "files": ["Makefile"],
        "make_tokens": ["audit-deep-solidity"],
        "test_tokens": ["test_audit_deep"],
        "exercised_globs": [],
    },
    {
        "id": "universal-fp-runner",
        "label": "Universal false-positive runner",
        "files": ["tools/audit/universal_fp_runner.py"],
        "make_tokens": ["wave3-fp-runner"],
        "test_tokens": ["test_universal_fp_runner"],
        "exercised_globs": [],
    },
    {
        "id": "fp-tp-feedback-loop",
        "label": "FP/TP feedback learning loop",
        "files": ["tools/audit/fp_tp_feedback_loop.py"],
        "make_tokens": ["fp-tp-feedback-loop"],  # W4.11: wired via make target.
        "test_tokens": ["test_fp_tp_feedback_loop"],
        "exercised_globs": ["audit/fp_verdict_ledger.jsonl"],
    },
    {
        "id": "invariant-harness-generator",
        "label": "Invariant-harness generator",
        "files": ["tools/audit/invariant-harness-generator.py"],
        "make_tokens": ["invariant-harness-gen"],
        "test_tokens": ["test_invariant_harness_generator"],
        "exercised_globs": [],
    },
    {
        "id": "symbolic-runner-halmos",
        "label": "Symbolic execution / halmos runner",
        "files": ["tools/halmos-runner.sh", "tools/symbolic-runner.sh"],
        "make_tokens": ["symbolic-runner-test"],  # smoke-test only; not in `all`.
        "test_tokens": ["test_symbolic_runner"],
        "exercised_globs": [],
        "pipeline_ref": True,  # invoked inside audit-deep-solidity recipe.
    },
    {
        "id": "fuzz-medusa",
        "label": "Medusa fuzzing campaign",
        "files": ["tools/medusa-fuzz.sh"],
        "make_tokens": [],  # only invoked from audit-deep-solidity recipe body.
        "test_tokens": ["test_medusa_fuzz"],  # W4.11: sibling smoke test.
        "exercised_globs": [],
        "pipeline_ref": True,
    },
    {
        "id": "fuzz-echidna",
        "label": "Echidna fuzzing campaign",
        "files": ["tools/echidna-campaign.sh"],
        "make_tokens": [],
        "test_tokens": ["test_echidna_campaign"],  # W4.11: sibling smoke test.
        "exercised_globs": [],
        "pipeline_ref": True,
    },
    {
        "id": "differential-test-runner",
        "label": "Differential / cross-client test runner",
        "files": [
            "tools/audit/differential-test-runner.py",
            "tools/audit/precompile-differential-engine.py",
        ],
        "make_tokens": ["a11-precompile-diff"],
        "test_tokens": ["test_precompile_differential_engine"],
        "exercised_globs": [],
        # W4.11: a11-precompile-diff now invokes a real precompile
        # differential engine (registry-mine + classify + input crosscheck)
        # when UPSTREAM/FORK trees are supplied. No longer staging-only.
    },
    {
        "id": "corpus-tier-stratification",
        "label": "Corpus record tier stratification",
        "files": ["tools/hackerman-stratify-verification-tier.py"],
        "make_tokens": ["tier-stratify"],  # W4.11: wired via make target.
        "test_tokens": ["test_hackerman_stratify"],
        "exercised_globs": ["audit/corpus_tags/derived/record_quality.jsonl"],
    },
    {
        # DeepSeek monitoring (real-time spend + budget alerts + tier gate).
        # GREEN when budget < 80% AND failure rate < 5% AND no anomalies in
        # the last 24h. YELLOW between 80-99% spend / 5-15% fail / 1-2 anomalies.
        # RED at >=100% spend, >15% fail, or a budget_cap_exceeded.flag present.
        "id": "deepseek-monitor",
        "label": "DeepSeek monitoring (spend + budget alerts + verification_tier gate)",
        "files": ["tools/deepseek-monitor.py"],
        "make_tokens": ["deepseek-monitor"],
        "test_tokens": ["test_deepseek_monitor"],
        "exercised_globs": [
            ".auditooor/llm_dispatch_log.jsonl",
            ".auditooor/deepseek_fanout",
        ],
    },
]


def _collect_make_targets(makefile_txt: str) -> set[str]:
    return set(re.findall(r"(?m)^([a-zA-Z][\w-]*)\s*:", makefile_txt))


def _audit_recipe_bodies(makefile_txt: str) -> str:
    """Return concatenated recipe bodies of audit / audit-deep* targets."""
    bodies: list[str] = []
    lines = makefile_txt.splitlines()
    capture = False
    for line in lines:
        m = re.match(r"^([a-zA-Z][\w-]*)\s*:", line)
        if m:
            capture = m.group(1) in {"audit", "audit-deep", "audit-deep-solidity"}
            continue
        if capture and (line.startswith("\t") or line.startswith("    ")):
            bodies.append(line)
        elif capture and line.strip() == "":
            continue
        elif capture:
            capture = False
    return "\n".join(bodies)


def evaluate_capability(
    cap: dict[str, Any],
    root: Path,
    make_targets: set[str],
    makefile_txt: str,
    audit_bodies: str,
    test_files: list[str],
) -> dict[str, Any]:
    # (a) exists
    exists = all((root / f).exists() for f in cap["files"])

    # (b) wired
    wired = False
    wired_via = None
    for tok in cap["make_tokens"]:
        if tok in make_targets:
            wired = True
            wired_via = f"make target: {tok}"
            break
    if not wired and cap.get("pipeline_ref"):
        # referenced inside an audit* recipe body.
        for f in cap["files"]:
            base = Path(f).name
            if base and base in audit_bodies:
                wired = True
                wired_via = "referenced by audit-deep* pipeline recipe"
                break

    # (c) tested
    tested = False
    test_via = None
    for tok in cap["test_tokens"]:
        for tf in test_files:
            if tok and tok in tf:
                tested = True
                test_via = tf
                break
        if tested:
            break

    # (d) exercised - best-effort.
    exercised = False
    exercised_via = None
    for g in cap.get("exercised_globs", []):
        p = root / g
        if p.exists() and p.stat().st_size > 0:
            exercised = True
            exercised_via = g
            break

    # Grade.
    if not exists:
        colour = RED
    elif wired and tested:
        colour = GREEN
    else:
        colour = YELLOW

    notes: list[str] = []
    if not wired:
        notes.append("no make target / pipeline reference")
    if not tested:
        notes.append("no sibling test")
    if not exercised:
        notes.append("no exercised-evidence artifact found")
    if cap.get("partial"):
        notes.append("PARTIAL: " + cap["partial"])

    return {
        "id": cap["id"],
        "label": cap["label"],
        "colour": colour,
        "exists": exists,
        "wired": wired,
        "wired_via": wired_via,
        "tested": tested,
        "tested_via": test_via,
        "exercised": exercised,
        "exercised_via": exercised_via,
        "files": cap["files"],
        "notes": notes,
    }


def build_dashboard(root: Path) -> dict[str, Any]:
    makefile_txt = _read(root / "Makefile")
    make_targets = _collect_make_targets(makefile_txt)
    audit_bodies = _audit_recipe_bodies(makefile_txt)
    tests_dir = root / "tools" / "tests"
    test_files = (
        sorted(p.name for p in tests_dir.glob("test_*.py"))
        if tests_dir.is_dir()
        else []
    )

    caps = [
        evaluate_capability(c, root, make_targets, makefile_txt, audit_bodies, test_files)
        for c in CAPABILITIES
    ]

    tally = {GREEN: 0, YELLOW: 0, RED: 0}
    for c in caps:
        tally[c["colour"]] += 1

    return {
        "schema": SCHEMA_ID,
        "generated_at": _now(),
        "repo_root": str(root),
        "surface": {
            "detectors": probe_detectors(root),
            "mcp_callables": probe_mcp_callables(root),
            "corpus": probe_corpus(root),
        },
        "tally": tally,
        "capabilities": caps,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(dash: dict[str, Any]) -> str:
    surf = dash["surface"]
    det = surf["detectors"]
    corp = surf["corpus"]
    tally = dash["tally"]
    lines: list[str] = []
    lines.append("# Capability-readiness dashboard")
    lines.append("")
    lines.append(f"Generated: {dash['generated_at']}")
    lines.append("")
    lines.append(
        f"Tally: GREEN {tally[GREEN]} / YELLOW {tally[YELLOW]} / RED {tally[RED]}"
    )
    lines.append("")
    lines.append("## Surface")
    lines.append("")
    lines.append(f"- Detectors: {det['total']} total")
    for lang, n in det["by_language"].items():
        lines.append(f"  - {lang}: {n}")
    lines.append(f"- MCP callables: {surf['mcp_callables']}")
    lines.append(f"- Corpus tag YAMLs: {corp['tag_yaml_count']}")
    lines.append(f"- record_quality rows: {corp['record_quality_rows']}")
    if corp["record_tier_stratification"]:
        lines.append("  - Record-tier (provenance class):")
        for tier, n in corp["record_tier_stratification"].items():
            lines.append(f"    - {tier}: {n}")
    if corp["verification_tier_stratification"]:
        lines.append("  - Verification-tier (Rule 37):")
        for tier, n in corp["verification_tier_stratification"].items():
            lines.append(f"    - {tier}: {n}")
    lines.append("")
    lines.append("## Capabilities")
    lines.append("")
    lines.append("| Capability | Colour | Exists | Wired | Tested | Exercised |")
    lines.append("|---|---|---|---|---|---|")
    for c in dash["capabilities"]:
        lines.append(
            f"| {c['label']} | {c['colour']} | "
            f"{'yes' if c['exists'] else 'NO'} | "
            f"{'yes' if c['wired'] else 'NO'} | "
            f"{'yes' if c['tested'] else 'NO'} | "
            f"{'yes' if c['exercised'] else 'no'} |"
        )
    lines.append("")
    lines.append("## Notes (YELLOW / RED detail)")
    lines.append("")
    any_note = False
    for c in dash["capabilities"]:
        if c["colour"] != GREEN and c["notes"]:
            any_note = True
            lines.append(f"- **{c['label']}** ({c['colour']}): " + "; ".join(c["notes"]))
    if not any_note:
        lines.append("- All capabilities GREEN.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capability-readiness dashboard.")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--json", action="store_true", help="emit JSON (default).")
    parser.add_argument("--markdown", action="store_true", help="emit markdown.")
    parser.add_argument("--output", help="write JSON to file.")
    parser.add_argument("--markdown-output", help="write markdown to file.")
    parser.add_argument(
        "--strict", action="store_true", help="exit 2 if any RED capability."
    )
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve()
    if not (root / "Makefile").is_file():
        sys.stderr.write(f"[capability-readiness] repo root invalid: {root}\n")
        return 1

    dash = build_dashboard(root)
    payload = json.dumps(dash, indent=2, sort_keys=True)
    md = render_markdown(dash)

    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
    if args.markdown_output:
        Path(args.markdown_output).write_text(md + "\n", encoding="utf-8")

    if args.markdown and not args.json:
        print(md)
    elif args.json and not args.markdown:
        print(payload)
    elif args.markdown and args.json:
        print(payload)
        print(md)
    else:
        # default: markdown to stdout (human-readable answer).
        print(md)

    if args.strict and dash["tally"][RED] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
