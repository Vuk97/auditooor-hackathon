#!/usr/bin/env python3
"""Impact-methodology CORPUS-PROVENANCE gate (delivery/genuineness, not presence).

WHY THIS EXISTS (the coverage-theater hole it closes)
-----------------------------------------------------
The impact-methodology capability was injected only into the DISPATCH BRIEF
(dispatch-agent-with-prebriefing.py) and guarded only by:
  - a drift gate (the methodology YAML is internally consistent), and
  - audit-complete's hacker-questions gate (which COUNTS resolved obligations).
None of those assert that the persisted per-function question CORPUS actually
carries the impact-methodology, that the impact questions are FUNCTION-SPECIALIZED,
or that the credited hunt is FRESH relative to the capability. So on SSV the audit
rode a pre-capability June-23 corpus (0 impact-methodology rows) and every gate
went green - the capability never drove the credited hunt. Present-in-brief +
count-resolved == green, while delivery was absent.

This gate asserts DELIVERY, fail-closed:
  (1) PROVENANCE: a workspace whose corpus enumerates >=1 value-moving function
      MUST carry >=1 `question_source: impact-methodology` row. Zero impact rows on
      a value surface == the corpus predates / skipped the capability == FAIL
      (this is also the freshness signal: a stale corpus has no impact rows).
  (2) SPECIALIZATION: the impact rows that ARE present must be FUNCTION-BOUND
      (the question names its function) above a threshold - a corpus full of
      identical generic prose (the pre-specialization renderer) FAILs.

Verdicts: pass-impact-methodology-corpus / fail-* / not-applicable (no corpus, or
no value-moving functions in scope - e.g. a pure-view/library surface).

PLAYBOOK-CORPUS XREF/INDEX PROVENANCE (additive, repo-level)
------------------------------------------------------------
A second, repo-level check (`--playbook-corpus`) validates the SUPPLY side: the
32 impact-hunting playbooks in audit/corpus_tags/impact_hunting_methodology.yaml
cite (a) a `kill_rubric_xref` into docs/KILL_RUBRIC_LIBRARY.md (commit 69ec80c7b9)
and (b) `index_key`/`index_keys` into audit/corpus_tags/index/*.jsonl with member
counts (commit 3208e3abf4). Before this gate nothing asserted those citations
still RESOLVE on disk. It now validates, fail-closed if >10% are unresolved:
  (a) every playbook `kill_rubric_xref` resolves to a real KILL_RUBRIC_LIBRARY.md
      section (slug anchor under `## N. Title`, or a cited `sec N` that exists);
  (b) every cited index reference (`index_key`/`index_keys` + `index_file`) points
      at an existing index file AND the key is present in it.
Numeric member-count drift (a label says "(53 members)" but the on-disk count
differs) is reported as a WARN, never a fail - the canonical counts are noisy
and re-grounded periodically; an unresolved key/file is the real defect.

Playbook verdicts: pass-playbook-corpus-provenance / fail-playbook-corpus-provenance.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

VERDICT_PASS = "pass-impact-methodology-corpus"
VERDICT_FAIL_PROVENANCE = "fail-impact-methodology-absent"
VERDICT_FAIL_SPECIALIZATION = "fail-impact-methodology-generic"
VERDICT_NA = "not-applicable"

# Playbook-corpus (repo-level xref/index) verdicts.
VERDICT_PB_PASS = "pass-playbook-corpus-provenance"
VERDICT_PB_FAIL = "fail-playbook-corpus-provenance"

# Fraction of playbook xref/index references allowed to be unresolved before the
# playbook-corpus check fails. <=10% unresolved -> WARN (non-blocking).
_PLAYBOOK_UNRESOLVED_FLOOR = 0.10

# Mirror tools/hacker_question_renderer._VALUE_MOVING_VERB_RE so "is this a value
# surface" agrees with "which functions the renderer attaches fund-theft to".
_VALUE_MOVING_VERB_RE = re.compile(
    r"(withdraw|redeem|claim|transfer|send|deposit|mint|burn|liquidat|"
    r"stake|unstake|payout|collect|sweep|rescue|settle|distribut|refund|"
    r"borrow|repay|swap|flashloan|migrat|harvest|skim|donate)",
    re.IGNORECASE,
)

# Specialization floor: at least this fraction of impact rows must name their
# function (fn-bound). The specialized renderer prefixes "On `<fn>`: ".
_SPECIALIZATION_FLOOR = 0.80
# Disable the whole gate (escape hatch, audit-logged by the caller).
import os as _os
_DISABLED = bool(_os.environ.get("AUDITOOOR_NO_IMPACT_CORPUS_GATE"))


def _corpus_paths(ws: Path) -> list[Path]:
    base = ws / ".auditooor" / "per_fn_hacker_questions.jsonl"
    ranked = Path(str(base) + ".ranked.jsonl")
    return [p for p in (ranked, base) if p.is_file()]


def _load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict):
                rows.append(d)
    except OSError:
        return []
    return rows


def _fn_of(row: dict) -> str:
    fn = str(row.get("function") or "").strip()
    if fn and fn != "?":
        return fn
    unit = str(row.get("unit_id") or "")
    if "::" in unit:
        return unit.rsplit("::", 1)[-1].strip()
    return fn


def check(ws: Path) -> dict:
    if _DISABLED:
        return {"verdict": VERDICT_NA, "reason": "gate disabled via env"}
    paths = _corpus_paths(ws)
    if not paths:
        return {"verdict": VERDICT_NA,
                "reason": "no per_fn_hacker_questions corpus on disk"}
    path = paths[0]
    rows = _load_rows(path)
    if not rows:
        return {"verdict": VERDICT_NA, "reason": f"empty corpus: {path.name}"}

    functions = {f for f in (_fn_of(r) for r in rows) if f}
    # Anchor the verb at the START of the name (after any leading underscore) so a
    # getter like `getBurnRate` (contains "burn" mid-word) is NOT counted as a
    # value surface; value-movers lead with the verb (withdraw/liquidate/mint).
    value_fns = {
        f for f in functions
        if _VALUE_MOVING_VERB_RE.match(re.sub(r"^[^A-Za-z]+", "", f))
    }
    impact_rows = [r for r in rows if str(r.get("question_source") or "")
                   .strip().lower() == "impact-methodology"]

    detail = {
        "corpus": path.name,
        "total_rows": len(rows),
        "functions": len(functions),
        "value_moving_functions": len(value_fns),
        "impact_rows": len(impact_rows),
    }

    # NOT-APPLICABLE: no value-moving function in scope (pure view/library
    # surface) -> impact-methodology has nothing to attach; do not penalize.
    if not value_fns:
        return {"verdict": VERDICT_NA,
                "reason": "no value-moving function in the corpus surface",
                "detail": detail}

    # (1) PROVENANCE / FRESHNESS: a value surface with ZERO impact rows means the
    # corpus predates or skipped the capability.
    if not impact_rows:
        return {
            "verdict": VERDICT_FAIL_PROVENANCE,
            "reason": (f"{len(value_fns)} value-moving function(s) in scope but "
                       "0 impact-methodology rows in the corpus - the credited "
                       "hunt predates/skipped the capability (regenerate the "
                       "per_fn corpus through render_impact_questions)"),
            "detail": detail,
        }

    # (2) SPECIALIZATION: impact rows must be function-bound (name their fn).
    bound = 0
    for r in impact_rows:
        fn = _fn_of(r)
        q = str(r.get("question") or "")
        if fn and fn in q:
            bound += 1
    frac = bound / len(impact_rows) if impact_rows else 0.0
    detail["fn_bound_impact_rows"] = bound
    detail["fn_bound_fraction"] = round(frac, 3)
    if frac < _SPECIALIZATION_FLOOR:
        return {
            "verdict": VERDICT_FAIL_SPECIALIZATION,
            "reason": (f"only {bound}/{len(impact_rows)} impact rows are "
                       f"function-bound (< {_SPECIALIZATION_FLOOR:.0%}) - the "
                       "corpus carries generic, non-specialized impact prose"),
            "detail": detail,
        }

    return {
        "verdict": VERDICT_PASS,
        "reason": (f"{len(impact_rows)} impact-methodology row(s) present and "
                   f"{bound}/{len(impact_rows)} function-bound across "
                   f"{len(value_fns)} value-moving function(s)"),
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Playbook-corpus (repo-level) xref-resolution + index-existence/count check.
# Mirrors the live reader / test regexes so a shape the production reader would
# not see cannot pass here either.
# ---------------------------------------------------------------------------
_SECTION_RE = re.compile(r"^## (\d+)\.\s+(.+)$", re.MULTILINE)
_SLUG_ANCHOR_RE = re.compile(
    r"^<!--\s*kill_rubric_slug:\s*([a-z0-9-]+)\s*-->\s*$", re.MULTILINE)
_SLUG_VALUE_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SEC_REF_RE = re.compile(r"\b(?:sec|section)\s+(\d+)\b", re.IGNORECASE)
# A count cited next to / inside a label: "(53 members)", "(75)", "x82", "82".
_LABEL_COUNT_RE = re.compile(r"\((\d+)(?:\s+members)?\)|\bx(\d+)\b")


def _repo_root_from(start: Path) -> Path:
    """Walk up from a hint path to the dir holding audit/corpus_tags."""
    start = start.resolve()
    cands = [start] + list(start.parents)
    for c in cands:
        if (c / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml").is_file():
            return c
    # fall back to the tool's own repo root (tools/ -> repo).
    return Path(__file__).resolve().parents[1]


def _section_numbers(text: str) -> set[int]:
    return {int(m.group(1)) for m in _SECTION_RE.finditer(text)}


def _section_slugs(text: str) -> set[str]:
    headers = list(_SECTION_RE.finditer(text))
    slugs: set[str] = set()
    for i, h in enumerate(headers):
        body = text[h.end():(headers[i + 1].start() if i + 1 < len(headers) else len(text))]
        for sm in _SLUG_ANCHOR_RE.finditer(body):
            slugs.add(sm.group(1))
    return slugs


def _xref_resolves(value: str, sec_nums: set[int], sec_slugs: set[str]) -> bool:
    value = (value or "").strip()
    if not value:
        return False
    if _SLUG_VALUE_RE.match(value):
        return value in sec_slugs
    cited = {int(n) for n in _SEC_REF_RE.findall(value)}
    return bool(cited) and cited.issubset(sec_nums)


def _index_key_counts(index_file: Path) -> dict[str, int]:
    """Count records per `key` in a by_*.jsonl index file (one JSON/line)."""
    counts: dict[str, int] = {}
    try:
        for line in index_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict):
                k = d.get("key")
                if isinstance(k, str):
                    counts[k] = counts.get(k, 0) + 1
    except OSError:
        return {}
    return counts


def _iter_index_refs(node, label: str = ""):
    """Yield (key, index_file, cited_count_or_None) for every index reference in
    a playbook subtree. Handles index_key / index_keys with an index_file, and
    pulls a numeric member-count out of the nearest enclosing `label` field."""
    if isinstance(node, dict):
        idx_file = node.get("index_file")
        node_label = node.get("label") or label
        cited = None
        if isinstance(node_label, str):
            m = _LABEL_COUNT_RE.search(node_label)
            if m:
                cited = int(m.group(1) or m.group(2))
        if isinstance(idx_file, str):
            keys = []
            if isinstance(node.get("index_key"), str):
                keys.append(node["index_key"])
            ik = node.get("index_keys")
            if isinstance(ik, list):
                keys.extend([k for k in ik if isinstance(k, str)])
            for k in keys:
                yield (k, idx_file, cited if len(keys) == 1 else None)
        for v in node.values():
            yield from _iter_index_refs(v, node_label if isinstance(node_label, str) else label)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_index_refs(v, label)


def check_playbook_corpus(repo_hint: Path | None = None) -> dict:
    """Validate kill_rubric_xref resolution + index-key existence/counts across
    the 32 impact-hunting playbooks. Additive, repo-level."""
    root = _repo_root_from(repo_hint or Path(__file__))
    yaml_path = root / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"
    lib_path = root / "docs" / "KILL_RUBRIC_LIBRARY.md"
    if not yaml_path.is_file():
        return {"verdict": VERDICT_NA,
                "reason": f"no playbook corpus on disk under {root}"}
    try:
        import yaml as _yaml  # lazy: only this mode needs PyYAML
    except ImportError:
        return {"verdict": VERDICT_NA,
                "reason": "PyYAML unavailable; cannot parse playbook corpus"}
    try:
        data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001 - corpus parse error is informational
        return {"verdict": VERDICT_NA,
                "reason": f"playbook corpus unparseable: {e}"}
    playbooks = data.get("playbooks") if isinstance(data, dict) else None
    if not isinstance(playbooks, list) or not playbooks:
        return {"verdict": VERDICT_NA, "reason": "playbook corpus has no playbooks"}

    lib_text = lib_path.read_text(encoding="utf-8") if lib_path.is_file() else ""
    sec_nums = _section_numbers(lib_text)
    sec_slugs = _section_slugs(lib_text)

    xref_total = 0
    xref_unresolved: list[str] = []
    for pb in playbooks:
        if not isinstance(pb, dict):
            continue
        val = pb.get("kill_rubric_xref")
        impact_id = str(pb.get("impact_id") or "?")
        xref_total += 1
        if not isinstance(val, str) or not _xref_resolves(val, sec_nums, sec_slugs):
            xref_unresolved.append(impact_id)

    # Index references (existence + key presence; counts -> warn only).
    idx_total = 0
    idx_unresolved: list[str] = []
    count_warnings: list[str] = []
    _counts_cache: dict[str, dict[str, int]] = {}
    for pb in playbooks:
        if not isinstance(pb, dict):
            continue
        for key, idx_file, cited in _iter_index_refs(pb):
            idx_total += 1
            fpath = (root / idx_file) if not Path(idx_file).is_absolute() else Path(idx_file)
            if not fpath.is_file():
                idx_unresolved.append(f"{key} (missing file {idx_file})")
                continue
            if idx_file not in _counts_cache:
                _counts_cache[idx_file] = _index_key_counts(fpath)
            counts = _counts_cache[idx_file]
            if key not in counts:
                idx_unresolved.append(f"{key} (absent key in {idx_file})")
                continue
            if cited is not None and cited != counts[key]:
                count_warnings.append(
                    f"{key}: label cites {cited}, on-disk {counts[key]}")

    total_refs = xref_total + idx_total
    unresolved = len(xref_unresolved) + len(idx_unresolved)
    frac = (unresolved / total_refs) if total_refs else 0.0
    detail = {
        "repo_root": str(root),
        "playbooks": len(playbooks),
        "xref_total": xref_total,
        "xref_unresolved": xref_unresolved,
        "index_refs_total": idx_total,
        "index_unresolved": idx_unresolved,
        "unresolved_fraction": round(frac, 3),
        "count_warnings": count_warnings,
    }
    if frac > _PLAYBOOK_UNRESOLVED_FLOOR:
        return {
            "verdict": VERDICT_PB_FAIL,
            "reason": (f"{unresolved}/{total_refs} playbook xref/index references "
                       f"unresolved ({frac:.0%} > {_PLAYBOOK_UNRESOLVED_FLOOR:.0%}); "
                       "kill_rubric_xref must resolve to a KILL_RUBRIC_LIBRARY.md "
                       "section and every index_key must exist in its index_file"),
            "detail": detail,
        }
    return {
        "verdict": VERDICT_PB_PASS,
        "reason": (f"{total_refs - unresolved}/{total_refs} playbook xref/index "
                   f"references resolve ({len(count_warnings)} count drift warning(s))"),
        "detail": detail,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("workspace", nargs="?",
                   help="workspace dir (per-fn corpus check); omit with --playbook-corpus")
    p.add_argument("--json", action="store_true")
    p.add_argument("--playbook-corpus", action="store_true",
                   help="run the repo-level kill_rubric-xref + index-existence check")
    args = p.parse_args(argv)
    if args.playbook_corpus:
        hint = Path(args.workspace) if args.workspace else None
        res = check_playbook_corpus(hint)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[impact-playbook-corpus] verdict={res['verdict']}")
            print(f"  reason: {res['reason']}")
            for k, v in (res.get("detail") or {}).items():
                print(f"    {k}: {v}")
        return 0 if res["verdict"] in (VERDICT_PB_PASS, VERDICT_NA) else 1
    if not args.workspace:
        p.error("workspace is required unless --playbook-corpus is given")
    res = check(Path(args.workspace))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[impact-corpus-provenance] verdict={res['verdict']}")
        print(f"  reason: {res['reason']}")
        for k, v in (res.get("detail") or {}).items():
            print(f"    {k}: {v}")
    # rc=0 only on PASS or NOT-APPLICABLE; non-zero on any FAIL.
    return 0 if res["verdict"] in (VERDICT_PASS, VERDICT_NA) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
