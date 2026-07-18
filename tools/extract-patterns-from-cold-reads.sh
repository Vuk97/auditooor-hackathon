#!/usr/bin/env bash
# extract-patterns-from-cold-reads.sh — R73 C4: retrospective miner that
# pulls recurring themes out of our own cold-read probe logs.
#
# Why: every engagement produces dozens of "probe hypothesis → verdict"
# lines in reference/cold_reads or workspace cold_reads. Over time, the
# same NOT-A-BUG refutations keep appearing ("balance check is relative",
# "sha256 salt collision-resistant", "OOS-trusted admin"). Those recurring
# refutations are exactly the signals the rejection classifier wants as
# anti-patterns, and the rare BUG verdicts are seed candidates for new DSL
# YAMLs.
#
# What it does:
#   1. Finds every `*.analysis.md` across:
#        reference/cold_reads/
#        ~/audits/*/cold_reads/
#   2. Parses each file for probe lines of the form:
#        N. **hypothesis …** — VERDICT — evidence
#      Extracts (hypothesis_key, verdict_class, engagement, file).
#   3. Aggregates:
#        - Verdict distribution per engagement
#        - Top recurring hypothesis themes (keyword-bucketed)
#        - BUG / NEEDS-MORE verdicts → candidate seeds (written as draft
#          DSL YAML stubs under reference/patterns.dsl.r73_c4_seeds/)
#        - NOT-A-BUG clusters (≥3 across engagements) → anti-pattern
#          suggestions for the classifier, logged to
#          reference/cold_read_retrospective.md
#   4. Emits a concise console summary + the markdown report.
#
# Usage:
#   bash tools/extract-patterns-from-cold-reads.sh            # full retrospective
#   bash tools/extract-patterns-from-cold-reads.sh --summary  # console only (no writes)
#   bash tools/extract-patterns-from-cold-reads.sh --min 2    # lower anti-pattern threshold
#
# Runs on every round close (hook into flow-gate.sh --strict --dashboard).

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDITS_ROOT="${AUDITS_ROOT:-$HOME/audits}"
OUT_MD="$AUDITOOOR_DIR/reference/cold_read_retrospective.md"
SEED_DIR="$AUDITOOOR_DIR/reference/patterns.dsl.r73_c4_seeds"

MIN_CLUSTER=3
SUMMARY_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --summary) SUMMARY_ONLY=1; shift ;;
        --min) MIN_CLUSTER="$2"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# //; s/^#//'; exit 0 ;;
        *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$SEED_DIR"

python3 - "$AUDITOOOR_DIR" "$AUDITS_ROOT" "$OUT_MD" "$SEED_DIR" "$MIN_CLUSTER" "$SUMMARY_ONLY" <<'PY'
import sys, re, pathlib, collections, datetime, json

aud_dir, audits_root, out_md, seed_dir, min_cluster, summary_only = sys.argv[1:]
min_cluster = int(min_cluster); summary_only = int(summary_only)

aud_dir = pathlib.Path(aud_dir); audits_root = pathlib.Path(audits_root)
seed_dir = pathlib.Path(seed_dir); out_md = pathlib.Path(out_md)

# ─── Gather cold-read files ───
cold_reads = []
for candidate in [aud_dir / "reference/cold_reads"] + list(audits_root.glob("*/cold_reads")):
    if candidate.exists():
        for f in candidate.glob("*.analysis.md"):
            cold_reads.append(f)

if not cold_reads:
    print("[info] no *.analysis.md cold-read files found — nothing to retrospect")
    sys.exit(0)

print(f"[info] scanning {len(cold_reads)} cold-read files across "
      f"{len(set(f.parent for f in cold_reads))} engagements")

# ─── Parse probes ───
# Lines look like:
#   1. **Can deposit route to wrong pubkey?** — NOT-A-BUG. Evidence...
#   N. **Hypothesis** — VERDICT_CLASS(. description)
VERDICT_CLASSES = [
    "BUG", "LIKELY-BUG", "CONFIRMED-BUG",
    "NEEDS-MORE", "NEEDS-PAIR-FUZZ", "NEEDS-FUZZ", "DEFER",
    "PRIOR-AUDIT-DUPE", "KNOWN", "KNOWN/INTENDED",
    "NOT-A-BUG", "NOT-PROTOCOL-BUG", "NOT-APPLICABLE",
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
]

probe_re = re.compile(
    r'^\s*\d+\.\s+\*\*(?P<hyp>[^*]+?)\*\*\s*[—-]\s*'
    r'(?P<verdict>[A-Z][A-Z/\-]+(?:\s[A-Z]+)?)\b',
    flags=re.M,
)

# Normalise hypothesis text → keyword bucket for aggregation
def bucket(h):
    h = h.lower()
    buckets = []
    themes = [
        ('reentrancy', ['reentr', 'callback', 'delegatecall', 'self-call']),
        ('slippage/minOut', ['slippage', 'minout', 'min out', 'min amount', 'mindout']),
        ('overflow/underflow', ['overflow', 'underflow', 'wrap', 'truncat']),
        ('access control', ['only', 'permission', 'role', 'auth', 'onlyowner', 'admin', 'restricted']),
        ('frontrun/mev', ['front-run', 'frontrun', 'sandwich', 'mev', 'back-run']),
        ('griefing/dos', ['grief', 'dos', 'denial', 'spam', 'gas-lim', 'oog']),
        ('oracle/price', ['oracle', 'pricefeed', 'chainlink', 'twap', 'sequencer']),
        ('init/upgrade', ['init', 'upgrade', 'proxy', 'cloneinit', 'initializer']),
        ('accounting', ['balance', 'account', 'share', 'asset', 'expectedliquid']),
        ('salt/create2', ['create2', 'sha256', 'collis', 'keccak', 'salt', 'predict']),
        ('fees/commission', ['fee', 'commis', 'basis_point', 'bps', 'rebate']),
        ('signature/sig', ['signat', 'permit', 'ecrecover', 'eip712', 'malleab']),
        ('loop/batch', ['loop', 'batch', 'array', 'iterat']),
        ('external-call', ['external call', 'call.', 'low-level', '.call{']),
        ('token decimal', ['decimal', 'unit', 'scale', 'wad', 'ray', 'precision']),
        ('withdrawal-queue', ['queue', 'pending', 'unstake', 'withdrawal', 'cooldown']),
        ('flash-loan', ['flash', 'flashloan', 'flash-loan']),
        ('replay/nonce', ['replay', 'nonce', 'idempot']),
    ]
    for tag, needles in themes:
        for n in needles:
            if n in h:
                buckets.append(tag)
                break
    return tuple(buckets) or ('misc',)

# Verdict class simplification
def verdict_class(v):
    v = v.upper().strip('. ')
    if v.startswith('NOT-A-BUG') or v.startswith('NOT-PROTOCOL') or v == 'NOT-APPLICABLE':
        return 'NOT-A-BUG'
    if v.startswith('PRIOR-AUDIT') or v.startswith('KNOWN'):
        return 'KNOWN'
    if v.startswith('NEEDS') or v == 'DEFER':
        return 'NEEDS-MORE'
    if v in ('BUG', 'LIKELY-BUG', 'CONFIRMED-BUG', 'HIGH', 'CRITICAL', 'MEDIUM'):
        return 'BUG'
    if v in ('INFO', 'LOW'):
        return 'INFO'
    return v

per_engagement = collections.Counter()
per_verdict = collections.Counter()
theme_refutations = collections.defaultdict(list)   # bucket -> [(hyp, engagement, file)]
bug_seeds = []  # (hyp, verdict, engagement, file)

for f in cold_reads:
    engagement = f.parent.parent.name   # e.g. kiln-v1
    txt = f.read_text(errors='ignore')
    matches = list(probe_re.finditer(txt))
    per_engagement[engagement] += len(matches)
    for m in matches:
        hyp = m.group('hyp').strip()[:140]
        v = verdict_class(m.group('verdict'))
        per_verdict[v] += 1
        if v == 'NOT-A-BUG':
            for b in bucket(hyp):
                theme_refutations[b].append((hyp, engagement, f.name))
        elif v == 'BUG' or v == 'NEEDS-MORE':
            bug_seeds.append((hyp, v, engagement, f.name))

# ─── Anti-pattern clusters (themes with ≥ MIN_CLUSTER refutations) ───
anti_patterns = {
    b: rs for b, rs in theme_refutations.items()
    if len({(r[1], r[0]) for r in rs}) >= min_cluster
}

# ─── Console summary ───
print("\n═══ Cold-read retrospective ═══")
print(f"Engagements scanned : {len(per_engagement)}")
print(f"Total probes parsed : {sum(per_engagement.values())}")
print("\nVerdict distribution:")
for v, n in per_verdict.most_common():
    pct = 100 * n / max(sum(per_verdict.values()), 1)
    print(f"  {v:<16} {n:5}  ({pct:5.1f}%)")
print("\nPer-engagement probe count:")
for e, n in per_engagement.most_common():
    print(f"  {e:<20} {n}")
print(f"\nAnti-pattern theme clusters (≥{min_cluster} NOT-A-BUG refutations):")
for b, rs in sorted(anti_patterns.items(), key=lambda x: -len(x[1])):
    engs = sorted(set(r[1] for r in rs))
    print(f"  {b:<22} {len(rs):3}  engs={','.join(engs)}")
print(f"\nBUG / NEEDS-MORE seeds harvested: {len(bug_seeds)}")

if summary_only:
    sys.exit(0)

# ─── Write retrospective markdown ───
out_md.parent.mkdir(parents=True, exist_ok=True)
with open(out_md, 'w') as f:
    f.write("# Cold-read retrospective — what we probe, what we reject\n\n")
    f.write(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n\n")
    f.write(f"Scanned **{len(cold_reads)} files** across "
            f"**{len(per_engagement)} engagements** — **{sum(per_engagement.values())} probes**.\n\n")

    f.write("## Verdict distribution\n\n")
    f.write("| Verdict | Count | % |\n|---|---:|---:|\n")
    total = sum(per_verdict.values())
    for v, n in per_verdict.most_common():
        f.write(f"| {v} | {n} | {100*n/max(total,1):.1f} |\n")

    f.write("\n## Per-engagement\n\n")
    f.write("| Engagement | Probes |\n|---|---:|\n")
    for e, n in per_engagement.most_common():
        f.write(f"| {e} | {n} |\n")

    f.write(f"\n## Recurring NOT-A-BUG themes (≥{min_cluster} across engagements)\n\n")
    f.write("These are *recurring refutation shapes* — each cluster is a place ")
    f.write("we keep probing but keep finding the design intentional. They are ")
    f.write("candidate **anti-patterns** for the rejection classifier: if a ")
    f.write("future candidate finding looks like one of these and is not ")
    f.write("accompanied by new evidence, we should down-weight it.\n\n")
    for b, rs in sorted(anti_patterns.items(), key=lambda x: -len(x[1])):
        engs = sorted(set(r[1] for r in rs))
        f.write(f"### `{b}` — {len(rs)} refutations across {len(engs)} engagements\n\n")
        f.write(f"Engagements: {', '.join(engs)}\n\n")
        f.write("Sample hypotheses (first 5):\n")
        for hyp, eng, fn in rs[:5]:
            f.write(f"- *{eng}* / `{fn}` — {hyp}\n")
        f.write("\n")

    f.write("\n## BUG / NEEDS-MORE seeds\n\n")
    if bug_seeds:
        f.write("Candidate new DSL patterns (for manual review before compilation).\n")
        f.write("Draft stubs written to `reference/patterns.dsl.r73_c4_seeds/`.\n\n")
        f.write("| Verdict | Engagement | File | Hypothesis |\n|---|---|---|---|\n")
        for hyp, v, eng, fn in bug_seeds:
            h = hyp.replace('|', '\\|')
            f.write(f"| {v} | {eng} | `{fn}` | {h} |\n")
    else:
        f.write("(no BUG or NEEDS-MORE verdicts found in the scanned cold reads)\n")

    f.write("\n## How to consume this\n\n")
    f.write("1. **Classifier**: each anti-pattern theme → add to ")
    f.write("`reference/anti_patterns.md` as a weight-negative feature when a finding's title/body matches.\n")
    f.write("2. **DSL pattern seeds**: review each `patterns.dsl.r73_c4_seeds/*.yaml` stub and promote to `patterns.dsl/` when confidence is HIGH.\n")
    f.write("3. **Meta-lesson**: if an engagement has very few NOT-A-BUG probes, we probably under-probed; if very few BUG verdicts, we over-probed the wrong scope.\n")

# ─── Write draft YAML stubs for BUG seeds ───
def slugify(s, max_len=60):
    s = re.sub(r'[^a-zA-Z0-9]+', '-', s.lower()).strip('-')
    return s[:max_len].rstrip('-')

written = 0
for hyp, v, eng, fn in bug_seeds:
    slug = slugify(hyp)
    if not slug:
        continue
    yml_path = seed_dir / f"{slug}.yaml"
    if yml_path.exists():
        continue
    stub = f"""# DRAFT — auto-generated by extract-patterns-from-cold-reads.sh
# Source: cold read {fn} (engagement: {eng})
# Verdict class: {v}
# REVIEW BEFORE COMPILING
pattern: {slug[:80]}
source: auditooor-R73-coldread-{eng}
severity: UNKNOWN
confidence: LOW

# Hypothesis text:
# {hyp}

preconditions: []

match:
  - function.kind: external_or_public
  - function.not_in_skip_list: true
  - function.not_leaf_helper: true

help: "TODO — write one-line explanation."
wiki_title: "TODO — write title from hypothesis."
wiki_description: "TODO — generalize the cold-read hypothesis into a bug class."
wiki_exploit_scenario: "TODO — draft a concrete exploit scenario."
wiki_recommendation: "TODO — draft the recommendation."
"""
    yml_path.write_text(stub)
    written += 1

print(f"\n[ok] retrospective: {out_md}")
print(f"[ok] seed YAMLs   : {written} under {seed_dir}")
print(f"[ok] anti-patterns: {len(anti_patterns)} theme clusters flagged")
PY
