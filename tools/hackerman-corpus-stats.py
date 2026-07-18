#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - reproducible corpus stats dump.

Emits a deterministic stats report to stdout summarising the live state of
``audit/corpus_tags/tags/`` so the operator (and CI) can diff between runs
without re-deriving anything by hand.

Sections (stable order, stable sort within):

1. Header (schema, generated_at_iso, tags_dir)
2. Record-shape histogram (record.yaml / record.json-only / flat .yaml at tags root)
3. Per-corpus-subtree breakdown (records, target_domain top-5, verification_tier
   histogram, attack_class top-5) - subtrees sorted by name asc.
4. Quarantine status (count of records under ``_QUARANTINE_*`` plus the quarantine
   reason directories).
5. Verification-tier verdict (delegates to ``tools/hackerman-record-verification-tier-check.py``).
6. Acceptance-test verdict (delegates to ``tools/hackerman-corpus-subdir-acceptance-check.py --all``).

The output is read-only against the corpus tree. The two delegated gates are
invoked in ``--json`` mode and only the summary verdict line is surfaced (keeps
the report well under the 1MB cap demanded by the spec).

Determinism guarantees:

- Subtrees, attack classes, target domains, tier keys are sorted asc.
- Top-N truncations are stable (sort by count desc, tie-break by name asc).
- A fixed ``--generated-at`` override (env ``AUDITOOOR_CORPUS_STATS_GENERATED_AT``)
  is honored so tests can pin the timestamp.

Wired into Makefile as ``make hackerman-corpus-stats`` (no args required).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional pyyaml.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA = "auditooor.hackerman_corpus_stats.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

VERIFICATION_TIER_TAG_RE = re.compile(r"^verification_tier:tier-([1-5])-[a-z0-9-]+$")
QUARANTINE_PREFIX = "_QUARANTINE_"
TOP_N_DOMAIN = 5
TOP_N_ATTACK_CLASS = 5


# ---------------------------------------------------------------------------
# Loader helpers (kept small + fallback-friendly).
# ---------------------------------------------------------------------------


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load. Falls back to a minimal key:value parser when
    PyYAML is unavailable - we only need a handful of top-level scalar keys
    plus ``function_shape.shape_tags`` list entries."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    in_function_shape = False
    current_list_key: str | None = None
    shape_tags: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("function_shape:"):
            in_function_shape = True
            current_list_key = None
            continue
        if in_function_shape and line.startswith("  ") and not line.startswith("    "):
            current_subkey = line.strip().rstrip(":")
            current_list_key = "shape_tags" if current_subkey == "shape_tags" else None
            continue
        if in_function_shape and current_list_key == "shape_tags" and line.startswith("    - "):
            shape_tags.append(line[6:].strip().strip("\"'"))
            continue
        if not line.startswith(" "):
            in_function_shape = False
            current_list_key = None
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip().strip("\"'")
    if shape_tags:
        out["function_shape"] = {"shape_tags": shape_tags}
    return out


def _load_record(path: Path) -> dict[str, Any]:
    """Load a single record file. Returns {} on any I/O or parse error."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


def _extract_verification_tier(record: dict[str, Any] | None) -> int | None:
    """Return tier int from ``function_shape.shape_tags`` or None."""
    if not isinstance(record, dict):
        return None
    shape = record.get("function_shape")
    if not isinstance(shape, dict):
        return None
    tags = shape.get("shape_tags")
    if not isinstance(tags, list):
        return None
    for tag in tags:
        text = str(tag or "").strip()
        m = VERIFICATION_TIER_TAG_RE.match(text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def _is_hackerman_v1(record: dict[str, Any]) -> bool:
    # Accept both v1 and v1.1 (Wave-2 Phase-3 schema migration). Use
    # prefix-match so future v1.x minor bumps remain in-gate without a
    # tool-side rev. Sibling verdict_tag.v2 YAMLs still fail this check.
    return str(record.get("schema_version") or "").strip().startswith(
        HACKERMAN_V1_SCHEMA
    )


def _subtree_of(path: Path, tags_dir: Path) -> str:
    """Return the top-level corpus subtree under ``tags_dir``. Flat files at
    the tags-dir root return ``<flat-root>``."""
    try:
        rel = path.relative_to(tags_dir)
    except ValueError:
        return "<unknown>"
    parts = rel.parts
    if not parts:
        return "<unknown>"
    if len(parts) == 1:
        return "<flat-root>"
    return parts[0]


# ---------------------------------------------------------------------------
# Walker - splits records into 3 shapes: record.yaml, record.json (json-only),
# and flat <name>.yaml at the tags-dir root.
# ---------------------------------------------------------------------------


def _walk_records(tags_dir: Path) -> Iterable[tuple[Path, dict[str, Any], str]]:
    """Yield ``(path, record, shape_label)`` tuples in a stable order.

    Shape labels:
    - ``record.yaml`` - structured dir with a YAML record (preferred).
    - ``record.json`` - structured dir with only record.json (no record.yaml).
    - ``flat.yaml``   - loose ``<name>.yaml`` at the ``tags/`` root.
    """
    seen_dirs: set[Path] = set()
    for path in sorted(tags_dir.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec, "record.yaml"
    for path in sorted(tags_dir.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, "record.json"
    # Flat <name>.yaml records: every *.yaml that is NOT a record.yaml. These
    # show up at the tags-dir root (~28k bulk corpus) AND inside subtree dirs
    # like ``_QUARANTINE_FABRICATED_CVE/vyper_cve_fabricated/<name>.yaml``.
    # Excluding ``record.yaml`` avoids double-counting structured records.
    for path in sorted(tags_dir.rglob("*.yaml")):
        if path.name == "record.yaml":
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, "flat.yaml"


# ---------------------------------------------------------------------------
# Aggregation.
# ---------------------------------------------------------------------------


def _top_n(counter: Counter[str], n: int) -> list[tuple[str, int]]:
    """Top-N entries by count desc; tie-break by name asc."""
    items = [(k, int(v)) for k, v in counter.items() if k]
    items.sort(key=lambda kv: (-kv[1], kv[0]))
    return items[:n]


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Aggregate the corpus tree into a deterministic stats payload."""
    shape_counts: Counter[str] = Counter()
    hackerman_v1_by_shape: Counter[str] = Counter()
    per_subtree: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "records": 0,
            "hackerman_v1_records": 0,
            "target_domain": Counter(),
            "verification_tier": Counter(),
            "attack_class": Counter(),
        }
    )
    quarantine_per_reason: Counter[str] = Counter()
    quarantine_total = 0

    for path, rec, shape in _walk_records(tags_dir):
        shape_counts[shape] += 1
        if _is_hackerman_v1(rec):
            hackerman_v1_by_shape[shape] += 1
        subtree = _subtree_of(path, tags_dir)
        entry = per_subtree[subtree]
        entry["records"] += 1
        if _is_hackerman_v1(rec):
            entry["hackerman_v1_records"] += 1
        td = str(rec.get("target_domain") or "").strip() or "<missing-target-domain>"
        ac = str(rec.get("attack_class") or "").strip() or "<missing-attack-class>"
        tier = _extract_verification_tier(rec)
        tier_key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        entry["target_domain"][td] += 1
        entry["attack_class"][ac] += 1
        entry["verification_tier"][tier_key] += 1

        if subtree.startswith(QUARANTINE_PREFIX):
            quarantine_total += 1
            # Reason = the next path component (e.g. ``vyper_cve_fabricated``)
            # under the ``_QUARANTINE_*`` umbrella, or ``<root>`` if directly
            # under quarantine.
            try:
                rel = path.relative_to(tags_dir)
            except ValueError:
                rel = Path(path.name)
            parts = rel.parts
            reason = parts[1] if len(parts) >= 3 else "<root>"
            quarantine_per_reason[reason] += 1

    # Materialize per-subtree dict deterministically.
    subtree_rows: list[dict[str, Any]] = []
    for name in sorted(per_subtree.keys()):
        entry = per_subtree[name]
        td_counter: Counter[str] = entry["target_domain"]
        ac_counter: Counter[str] = entry["attack_class"]
        vt_counter: Counter[str] = entry["verification_tier"]
        subtree_rows.append(
            {
                "subtree": name,
                "records": int(entry["records"]),
                "hackerman_v1_records": int(entry["hackerman_v1_records"]),
                "target_domain_top5": _top_n(td_counter, TOP_N_DOMAIN),
                "verification_tier_histogram": {
                    k: int(vt_counter[k]) for k in sorted(vt_counter.keys())
                },
                "attack_class_top5": _top_n(ac_counter, TOP_N_ATTACK_CLASS),
            }
        )

    total_records = sum(shape_counts.values())
    total_hackerman_v1 = sum(hackerman_v1_by_shape.values())

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "hackerman_v1_total": total_hackerman_v1,
        "shape_counts": {k: int(shape_counts[k]) for k in sorted(shape_counts.keys())},
        "hackerman_v1_by_shape": {
            k: int(hackerman_v1_by_shape[k]) for k in sorted(hackerman_v1_by_shape.keys())
        },
        "subtrees": subtree_rows,
        "quarantine": {
            "total": quarantine_total,
            "per_reason": {k: int(quarantine_per_reason[k]) for k in sorted(quarantine_per_reason.keys())},
        },
    }


# ---------------------------------------------------------------------------
# Gate delegation.
# ---------------------------------------------------------------------------


def _run_gate(cmd: list[str], cwd: Path) -> dict[str, Any]:
    """Invoke a sibling tool and return ``{verdict, summary, rc, stderr_tail}``.

    On any subprocess / JSON failure, returns a structured ``error`` row so
    the stats run still completes (the gates are advisory inside this report).
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "verdict": "error",
            "summary": f"subprocess failed: {exc}",
            "rc": -1,
            "stderr_tail": "",
        }
    rc = int(proc.returncode)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "verdict": "error",
            "summary": "gate did not emit JSON",
            "rc": rc,
            "stderr_tail": stderr[-200:],
        }
    return {
        "verdict": str(data.get("verdict") or "<no-verdict>"),
        "summary": _gate_summary(data),
        "rc": rc,
        "stderr_tail": stderr[-200:] if stderr else "",
    }


def _gate_summary(data: dict[str, Any]) -> str:
    """One-line summary pulled from gate JSON payload (best-effort)."""
    if "reason" in data:
        return str(data["reason"])
    if "directory_count" in data:
        return (
            f"dirs={data.get('directory_count')} "
            f"pass={data.get('pass_count')} "
            f"fail={data.get('fail_count')}"
        )
    return "<no-summary>"


def _verification_tier_gate(tags_dir: Path) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "hackerman-record-verification-tier-check.py"),
        "--tags-dir",
        str(tags_dir),
        "--json",
        "--allow-missing-tags-dir",
    ]
    return _run_gate(cmd, REPO_ROOT)


def _acceptance_gate(tags_dir: Path) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "hackerman-corpus-subdir-acceptance-check.py"),
        "--all",
        "--tags-dir",
        str(tags_dir),
        "--json",
    ]
    return _run_gate(cmd, REPO_ROOT)


# ---------------------------------------------------------------------------
# Renderer.
# ---------------------------------------------------------------------------


def _generated_at(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_CORPUS_STATS_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def render_report(
    stats: dict[str, Any],
    tier_gate: dict[str, Any],
    accept_gate: dict[str, Any],
    *,
    generated_at: str,
) -> str:
    lines: list[str] = []
    lines.append(f"# hackerman corpus stats ({stats['schema']})")
    lines.append(f"generated_at: {generated_at}")
    lines.append(f"tags_dir: {stats['tags_dir']}")
    lines.append(f"total_records: {stats['total_records']}")
    lines.append(f"hackerman_v1_total: {stats['hackerman_v1_total']}")
    lines.append("")

    lines.append("## Record-shape histogram")
    for shape in sorted(stats["shape_counts"].keys()):
        total = stats["shape_counts"][shape]
        v1 = stats["hackerman_v1_by_shape"].get(shape, 0)
        lines.append(f"- {shape}: total={total} hackerman_v1={v1}")
    lines.append("")

    lines.append("## Per-corpus-subtree breakdown")
    for row in stats["subtrees"]:
        lines.append(f"### {row['subtree']}")
        lines.append(
            f"  records={row['records']} hackerman_v1_records={row['hackerman_v1_records']}"
        )
        # target_domain
        td = row["target_domain_top5"]
        td_str = ", ".join(f"{name}={count}" for name, count in td) if td else "(none)"
        lines.append(f"  target_domain_top5: {td_str}")
        # verification_tier
        vt = row["verification_tier_histogram"]
        vt_str = ", ".join(f"{k}={vt[k]}" for k in sorted(vt.keys())) if vt else "(none)"
        lines.append(f"  verification_tier: {vt_str}")
        # attack_class
        ac = row["attack_class_top5"]
        ac_str = ", ".join(f"{name}={count}" for name, count in ac) if ac else "(none)"
        lines.append(f"  attack_class_top5: {ac_str}")
    lines.append("")

    lines.append("## Quarantine status")
    q = stats["quarantine"]
    lines.append(f"total_quarantine_records: {q['total']}")
    if q["per_reason"]:
        for reason in sorted(q["per_reason"].keys()):
            lines.append(f"- {reason}: {q['per_reason'][reason]}")
    else:
        lines.append("- (no quarantine entries)")
    lines.append("")

    lines.append("## Verification-tier gate (tools/hackerman-record-verification-tier-check.py)")
    lines.append(f"verdict: {tier_gate.get('verdict')}")
    lines.append(f"summary: {tier_gate.get('summary')}")
    lines.append(f"rc: {tier_gate.get('rc')}")
    if tier_gate.get("stderr_tail"):
        lines.append(f"stderr_tail: {tier_gate['stderr_tail']}")
    lines.append("")

    lines.append("## Acceptance gate (tools/hackerman-corpus-subdir-acceptance-check.py --all)")
    lines.append(f"verdict: {accept_gate.get('verdict')}")
    lines.append(f"summary: {accept_gate.get('summary')}")
    lines.append(f"rc: {accept_gate.get('rc')}")
    if accept_gate.get("stderr_tail"):
        lines.append(f"stderr_tail: {accept_gate['stderr_tail']}")
    lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hackerman-corpus-stats")
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of hackerman corpus tag records.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON payload instead of the human-readable report.",
    )
    parser.add_argument(
        "--skip-gates",
        action="store_true",
        help="Skip the verification-tier + acceptance gate subprocess calls.",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="Override the generated_at timestamp (also via env AUDITOOOR_CORPUS_STATS_GENERATED_AT).",
    )
    args = parser.parse_args(argv)

    tags_dir = args.tags_dir.resolve()
    if not tags_dir.is_dir():
        sys.stderr.write(f"[hackerman-corpus-stats] tags_dir not found: {tags_dir}\n")
        return 2

    stats = build_stats(tags_dir)
    if args.skip_gates:
        tier_gate = {"verdict": "skipped", "summary": "skipped via --skip-gates", "rc": 0, "stderr_tail": ""}
        accept_gate = {"verdict": "skipped", "summary": "skipped via --skip-gates", "rc": 0, "stderr_tail": ""}
    else:
        tier_gate = _verification_tier_gate(tags_dir)
        accept_gate = _acceptance_gate(tags_dir)

    generated_at = _generated_at(args.generated_at)
    if args.json:
        payload = {
            "schema": stats["schema"],
            "generated_at": generated_at,
            "stats": stats,
            "verification_tier_gate": tier_gate,
            "acceptance_gate": accept_gate,
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        report = render_report(stats, tier_gate, accept_gate, generated_at=generated_at)
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
