#!/usr/bin/env python3
"""Mechanical R76-verify + distinctness + ingest of negative-space probe records.

Replaces the LLM verify-agent that truncated its input (slice(0,60000)) and
burned tokens. Reads ALL probe records from a jsonl file and runs, purely
mechanically (no agent, no truncation, no token cost):

  (1) R76 source-exists  - the cited code_excerpt must grep-match real source
                           at/near its file_line (else it is a hallucination -> drop).
  (2) distinctness       - reject bulk-template reasoning (largest near-identical
                           cluster > AUDITOOOR_DEPTH_TEMPLATE_FRACTION -> not genuine).
  (3) ingest             - write the genuine rows into the workspace's
                           negative_space_gaps.jsonl (replace stub rows by guard_id).
  (4) positives          - gap_found=true rows are split out for LLM escalation.

Probe record shape (one JSON object per line), produced by the cheap probe step:
  {"guard_id","file_line","code_excerpt","gap_found",
   "why_no_gap_or_exploit", ["what_it_checks"]}

Usage:
  depth-probe-ingest.py --workspace <ws> --probes <probes.jsonl>
                        [--source-root <dir>] [--positives-out <path>]
                        [--json] [--no-ingest]

Exit 0 always (a diagnostic tool); --json prints the full report.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

SCHEMA = "auditooor.depth_probe_ingest.v1"
_SOURCE_EXT = (".rs", ".sol", ".go", ".move", ".cairo", ".vy")
_SKIP_DIRS = {"target", "node_modules", ".git", "lib", "out", "cache", "vendor", ".auditooor"}


# --- anti-stub: share the cert builder's logic verbatim (cert = gate authority) ---
# RECONCILE (zebra divergence, 2026-06): this ingest previously had its OWN
# weaker anti-stub implementation (length-only `_substantive` + a single global
# `bulk` boolean). That counted genuine=1203 on zebra where the cert builder
# counted genuine_adjudicated=698 over the SAME gaps, because the ingest accepted
# any 80+ char reason as "substantive" while the cert requires a guard-specific
# anchor (file:line / per-guard id / backtick code / a concrete check keyword)
# AND does per-row (not global) bulk-cluster marking. The cert
# (depth-certificate-build.py) is the R81 gate authority, so we import and reuse
# its `adjudication_genuineness` classifier here rather than re-implement it -
# this makes the two tools' cluster-detection logic + threshold + min-cluster
# size identical BY CONSTRUCTION (one implementation, no drift). The only
# remaining scope difference is legitimate: the ingest sees one probe BATCH,
# the cert sees the merged negative_space_gaps.jsonl - same logic, different
# input set.
def _load_cert_builder():
    path = Path(__file__).resolve().parent / "depth-certificate-build.py"
    spec = importlib.util.spec_from_file_location("_depth_cert_build_for_ingest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CERT = _load_cert_builder()


def _reason_tokens(text: str) -> set[str]:
    """Return distinctive tokens for tying source excerpts to probe prose."""
    tokens = {
        t.lower()
        for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text or "")
    }
    return {
        t
        for t in tokens
        if t not in {
            "the", "and", "for", "with", "that", "this", "from", "into",
            "because", "every", "input", "passing", "preserves", "invariant",
            "caller", "path", "state", "value", "guard", "check", "checks",
        }
    }


def _excerpt_tied_to_reason(excerpt: str, reason: str) -> bool:
    """True iff the prose cites or names something specific from the excerpt."""
    if not excerpt or not reason:
        return False
    if "`" in reason and _normalize(excerpt) in _normalize(reason):
        return True
    if re.search(r"\bline\s+\d+\b", reason, re.I):
        return True
    if _reason_tokens(excerpt) & _reason_tokens(reason):
        return True
    return False


def _normalize(text: str) -> str:
    """Collapse whitespace + strip markdown noise for robust substring match."""
    text = text.replace("`", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(_SOURCE_EXT):
                yield Path(dirpath) / fn


def _file_hint(file_line: str) -> str | None:
    """Extract the file path portion of a 'path/to/file.rs:123' citation."""
    if not file_line:
        return None
    return file_line.split(":", 1)[0].strip()


# R76 token-overlap fallback. The strict contiguous-substring match below rejects
# a LEGITIMATE excerpt whenever the agent paraphrases whitespace / modifier order
# (e.g. cites `function f(...) onlyEOA {` while the source spans `function f(...)\n
# public\n virtual\n onlyEOA\n {`, or quotes a multi-line function signature). On
# optimism that silently dropped real asymmetry + guard verdicts -> undisposed
# candidates -> a FALSE depth-pending the operator had to hand-patch. The fallback
# keeps R76's anti-hallucination strength (it only fires inside the CITED file, in
# a window around the cited line, and demands a high distinctive-token overlap +
# the single longest identifier present) while tolerating cosmetic excerpt drift.
_R76_NOISE_TOKENS = frozenset({
    "the", "and", "for", "function", "func", "public", "external", "internal",
    "private", "view", "pure", "returns", "return", "memory", "calldata", "storage",
    "virtual", "override", "address", "uint256", "uint", "int", "bytes", "bytes32",
    "bool", "string", "struct", "mapping", "require", "assert", "revert", "else",
    "let", "var", "const", "self", "this", "payable", "external",
})


def _r76_distinctive_tokens(text: str) -> set:
    """Identifier/number tokens (len>=3) minus language-noise keywords - the
    distinctive anchors a real excerpt shares with its source location."""
    toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}|\d{2,}", text or "")
    return {t.lower() for t in toks if t.lower() not in _R76_NOISE_TOKENS}


def _r76_window(raw: str, file_line: str, radius: int = 30) -> str | None:
    """Raw text of +/- radius lines around the cited line. None if there is no
    line number OR the cited line is out of the file's range (a bogus citation
    must NOT silently widen the fallback to a whole-file scan)."""
    try:
        n = int(str(file_line).rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None
    lines = raw.splitlines()
    if n < 1 or n > len(lines):
        return None
    a = max(0, n - 1 - radius)
    b = min(len(lines), n + radius)
    if a >= b:
        return None
    return "\n".join(lines[a:b])


def _r76_grep(excerpt: str, file_line: str, source_root: Path, file_cache: dict) -> bool:
    """True iff the excerpt is grounded in real source. Strict contiguous match
    first (anti-hallucination), then a conservative cited-file token-overlap
    fallback for cosmetically-drifted-but-genuine excerpts."""
    needle = _normalize(excerpt)
    if len(needle) < 8:  # too short to be a meaningful anchor
        return False
    # 1. try the cited file (and a couple of common path normalizations)
    hint = _file_hint(file_line)
    candidates = []
    if hint:
        h = hint.lstrip("/")
        candidates += [source_root / h, source_root / "src" / h]
        # short-prefix forms like 'zebra-...': match by basename
        candidates += list(source_root.rglob(Path(h).name)) if "/" not in h else []
    cited_files = []
    for c in candidates:
        try:
            if c.is_file():
                cited_files.append(c)
                body = file_cache.get(str(c))
                if body is None:
                    body = _normalize(c.read_text(encoding="utf-8", errors="replace"))
                    file_cache[str(c)] = body
                if needle in body:
                    return True
        except OSError:
            continue
    # 2. fall back to a bounded tree scan (cache normalized bodies)
    for f in _iter_source_files(source_root):
        body = file_cache.get(str(f))
        if body is None:
            try:
                body = _normalize(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                body = ""
            file_cache[str(f)] = body
        if needle in body:
            return True
    # 3. token-overlap fallback - CITED FILE ONLY, windowed around the cited line.
    #    Genuine but cosmetically-reworded excerpts pass; a fabricated excerpt whose
    #    distinctive tokens are not co-located at the cited line still fails.
    ex_tokens = _r76_distinctive_tokens(excerpt)
    if len(ex_tokens) < 4:
        return False  # too few anchors to trust an overlap match
    longest = max(ex_tokens, key=len)
    for c in cited_files:
        try:
            raw = c.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scope = _r76_window(raw, file_line, radius=30)
        if scope is None:
            continue  # no valid window at the cited line -> no whole-file widening
        win_tokens = _r76_distinctive_tokens(scope)
        if not win_tokens:
            continue
        overlap = len(ex_tokens & win_tokens) / len(ex_tokens)
        if overlap >= 0.85 and longest in win_tokens:
            return True
    return False


def _cert_row(r: dict) -> dict:
    """Project a probe record into the row shape the cert builder's
    `adjudication_genuineness` classifier judges. The classifier reads
    `ruled_out_reason` (prose it judges for substantive-ness + templating) and
    `exploitation_attempt_artifact` (rows disposed via an artifact are genuine by
    nature and skip the prose gates). The probe's adjudication prose lives in
    `why_no_gap_or_exploit`/`ruled_out_reason`, so we map it onto
    `ruled_out_reason` and carry any artifact through unchanged."""
    reason = str(r.get("why_no_gap_or_exploit") or r.get("ruled_out_reason") or "")
    excerpt = str(r.get("code_excerpt") or "").strip()
    if excerpt and _excerpt_tied_to_reason(excerpt, reason):
        # The excerpt has already survived R76 before ingest. We only include it
        # in the cert-projected prose when the explanation names the same code,
        # which keeps a real excerpt from laundering generic stub prose.
        reason = f"{excerpt} | {reason}".strip(" |")
    row = {"ruled_out_reason": reason}
    art = r.get("exploitation_attempt_artifact")
    if isinstance(art, str) and art.strip():
        row["exploitation_attempt_artifact"] = art
    return row


def ingest(workspace: Path, probes_path: Path, source_root: Path,
           positives_out: Path | None, do_ingest: bool,
           output_path: Path | None = None) -> dict:
    rows = []
    for ln in probes_path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            o = json.loads(ln)
        except json.JSONDecodeError:
            continue
        # Defensive: only dict rows are valid probe records. A stray list/scalar
        # (e.g. a single-line JSON array slipping through) must not reach _cert_row.
        if isinstance(o, dict):
            rows.append(o)
        elif isinstance(o, list):
            rows.extend(x for x in o if isinstance(x, dict))

    # Anti-stub genuineness: identical logic to the cert builder (its
    # `adjudication_genuineness`), run over THIS probe batch. We reuse the cert's
    # exact helpers (`_has_artifact`, `_is_substantive_reason`, `_template_shingle`,
    # `_template_min_cluster`) and its exact bulk-shingle rule + threshold, so the
    # per-row genuine/templated verdict here is identical BY CONSTRUCTION to the
    # cert builder's. (The cert later runs the SAME classifier over the merged
    # negative_space_gaps.jsonl; only the input scope differs - this batch vs the
    # merged file - which is a legitimate scope difference, not a logic divergence.)
    cert_rows = [_cert_row(r) for r in rows]
    genu = _CERT.adjudication_genuineness(cert_rows)
    cluster_size = genu["largest_template_cluster"]
    cluster_frac = genu["largest_template_fraction"]
    threshold = genu["template_threshold"]

    # Recompute the bulk-shingle SET exactly as adjudication_genuineness does (it
    # does not return the set), so the per-row predicate below matches the cert's.
    prose_reasons = [cr["ruled_out_reason"] for cr in cert_rows if not _CERT._has_artifact(cr)]
    prose_total = len(prose_reasons)
    if prose_total:
        shingles = Counter(_CERT._template_shingle(x) for x in prose_reasons)
        min_cluster = _CERT._template_min_cluster()
        bulk_shingles = {
            k for k, v in shingles.items()
            if (v / prose_total) > threshold and v >= min_cluster
        }
    else:
        bulk_shingles = set()
    # "bulk template detected" iff at least one shingle crossed BOTH the fraction
    # threshold AND the absolute min-cluster floor (the zebra-class identical
    # cluster). A non-empty stub set with NO bulk shingle (e.g. distinct-but-
    # generic reasons) is a substantive-gate reject, not a bulk-template reject.
    bulk = bool(bulk_shingles)

    def _row_is_genuine(cr: dict) -> bool:
        # genuine iff (artifact row) OR (substantive AND not in a bulk shingle).
        if _CERT._has_artifact(cr):
            return True
        reason = cr["ruled_out_reason"]
        return _CERT._is_substantive_reason(reason) and \
            _CERT._template_shingle(reason) not in bulk_shingles

    file_cache: dict = {}
    r76_pass, r76_fail, positives, genuine = [], [], [], []
    for r, cr in zip(rows, cert_rows):
        # Key fallback: ASYMMETRY probe verdicts are keyed by candidate_gap_id /
        # asym_id (not guard_id). Accepting those keeps asym records from silently
        # dropping (gid=None) before they reach asymmetry_probes.jsonl.
        gid = r.get("guard_id") or r.get("id") or r.get("candidate_gap_id") or r.get("asym_id")
        excerpt = str(r.get("code_excerpt") or "")
        fl = str(r.get("file_line") or "")
        reason = str(r.get("why_no_gap_or_exploit") or r.get("ruled_out_reason") or "")
        ok76 = _r76_grep(excerpt, fl, source_root, file_cache) if excerpt else False
        if not ok76:
            r76_fail.append({"guard_id": gid, "file_line": fl, "reason": "code_excerpt not found in source (R76 drop)"})
            continue
        r76_pass.append(gid)
        if not _row_is_genuine(cr):
            continue  # not genuine - reject (anti-stub, cert-identical logic)
        grow = {
            "guard_id": gid, "file_line": fl,
            "gap_found": bool(r.get("gap_found")),
            "disposition": "candidate" if r.get("gap_found") else "drop",
            "ruled_out_reason": f"{excerpt.strip()} | {reason}".strip(" |"),
            "probed": True,
            "probe_source": r.get("probe_source") or "mechanical-ingest",
            "schema": "auditooor.negative_space_gap.v1",
        }
        # Carry the ASYMMETRY identity through so the cert builder can match the
        # disposition to its sibling-pair row. The cert keys asymmetry dispositions
        # by candidate_gap_id / asym_id (preferred) or the file_lines PAIR - none of
        # which survive if we only emit the single under-guarded-side file_line.
        cgid = r.get("candidate_gap_id") or r.get("asym_id")
        if cgid:
            grow["candidate_gap_id"] = cgid
        fls = r.get("file_lines")
        if isinstance(fls, list) and fls:
            grow["file_lines"] = fls
        genuine.append(grow)
        if r.get("gap_found"):
            positives.append(genuine[-1])

    # ingest: merge genuine rows by guard_id into the target jsonl. Default is
    # negative_space_gaps.jsonl (guard probes); --output redirects asymmetry
    # probes to asymmetry_probes.jsonl, which is what the cert builder reads at
    # depth-certificate-build.py for _apply_asymmetry_dispositions (keyed by
    # asym_id == the genuine row's guard_id).
    ingested = 0
    gaps_path = output_path if output_path is not None else (
        workspace / ".auditooor" / "negative_space_gaps.jsonl"
    )
    if do_ingest and genuine:
        existing = {}
        if gaps_path.is_file():
            for ln in gaps_path.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    o = json.loads(ln)
                    existing[o.get("guard_id") or o.get("id")] = o
                except json.JSONDecodeError:
                    continue
        for g in genuine:
            existing[g["guard_id"]] = g
            ingested += 1
        gaps_path.parent.mkdir(parents=True, exist_ok=True)
        with gaps_path.open("w", encoding="utf-8") as fh:
            for o in existing.values():
                fh.write(json.dumps(o) + "\n")

    if positives_out and positives:
        positives_out.write_text("\n".join(json.dumps(p) for p in positives) + "\n", encoding="utf-8")

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "output_path": str(gaps_path),
        "probes_read": len(rows),
        "r76_pass": len(r76_pass),
        "r76_fail": len(r76_fail),
        "r76_fail_detail": r76_fail[:50],
        "bulk_template_detected": bulk,
        "largest_template_cluster": cluster_size,
        "largest_template_fraction": round(cluster_frac, 4),
        "genuine": len(genuine),
        "ingested": ingested,
        "positives": len(positives),
        "positives_detail": [p["guard_id"] for p in positives],
        "verdict": (
            "ingested-genuine" if ingested else
            ("all-bulk-rejected" if bulk else ("no-genuine-probes" if not genuine else "verified-no-ingest"))
        ),
    }


def _combine_probes_dir(probes_dir: Path, combined: Path) -> int:
    """Concatenate every *.jsonl row under probes_dir into one file. This is the
    truncation-proof path: parallel probe batch agents each WRITE their verdicts to
    <probes_dir>/batch_<i>.jsonl on disk, and ingest reads the whole directory -
    no probe is ever passed inline through a (truncating) agent prompt."""
    n = 0
    with combined.open("w", encoding="utf-8") as out:
        for f in sorted(probes_dir.glob("*.jsonl")):
            text = f.read_text(encoding="utf-8", errors="replace")
            recs: list = []
            # Probe batch agents write EITHER JSONL (one dict/line) OR a JSON ARRAY
            # (the canonical agent-batch prompt instructs "Write a JSON array").
            # Parse both: try whole-file JSON first (array or single dict), else fall
            # back to line-by-line JSONL. Flatten any array to its dict elements so a
            # single-line array is never emitted as a bare list row (which crashed
            # _cert_row with 'list' object has no attribute 'get').
            stripped = text.strip()
            parsed_whole = None
            if stripped:
                try:
                    parsed_whole = json.loads(stripped)
                except json.JSONDecodeError:
                    parsed_whole = None
            if isinstance(parsed_whole, list):
                recs = [x for x in parsed_whole if isinstance(x, dict)]
            elif isinstance(parsed_whole, dict):
                recs = [parsed_whole]
            else:
                for ln in text.splitlines():
                    ln = ln.strip().rstrip(",")
                    if not ln:
                        continue
                    try:
                        o = json.loads(ln)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(o, dict):
                        recs.append(o)
                    elif isinstance(o, list):
                        recs.extend(x for x in o if isinstance(x, dict))
            for o in recs:
                out.write(json.dumps(o) + "\n")
                n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--probes", type=Path, help="single jsonl of probe records")
    src.add_argument("--probes-dir", type=Path,
                     help="directory of per-batch *.jsonl files (truncation-proof; batch agents write to disk)")
    ap.add_argument("--source-root", type=Path, default=None)
    ap.add_argument("--positives-out", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=None,
                    help="target jsonl to merge genuine rows into "
                         "(default <ws>/.auditooor/negative_space_gaps.jsonl). "
                         "Pass <ws>/.auditooor/asymmetry_probes.jsonl for the "
                         "sibling-asymmetry probe pass so the cert builder reads it.")
    ap.add_argument("--combined-name", default="negative_space_probes.jsonl",
                    help="filename for the combined probes file written under "
                         ".auditooor when --probes-dir is used (default "
                         "negative_space_probes.jsonl; use a distinct name for "
                         "the asymmetry pass so it does not clobber the guard pass).")
    ap.add_argument("--no-ingest", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if args.probes_dir is not None:
        pdir = args.probes_dir.expanduser().resolve()
        if not pdir.is_dir():
            print(f"[depth-probe-ingest] probes dir not found: {pdir}", file=sys.stderr)
            return 2
        args.probes = ws / ".auditooor" / args.combined_name
        args.probes.parent.mkdir(parents=True, exist_ok=True)
        combined = _combine_probes_dir(pdir, args.probes)
        if not args.json:
            print(f"[depth-probe-ingest] combined {combined} probe rows from {pdir}")
    if not args.probes.is_file():
        print(f"[depth-probe-ingest] probes file not found: {args.probes}", file=sys.stderr)
        return 2
    source_root = (args.source_root or ws).expanduser().resolve()
    out = ingest(ws, args.probes, source_root, args.positives_out, not args.no_ingest,
                 output_path=(args.output.expanduser().resolve() if args.output else None))
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[depth-probe-ingest] {out['verdict']}: read {out['probes_read']} probes | "
              f"R76 {out['r76_pass']} pass / {out['r76_fail']} fail | "
              f"genuine {out['genuine']} | ingested {out['ingested']} | positives {out['positives']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
