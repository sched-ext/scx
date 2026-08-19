#!/usr/bin/env python3
"""Keep source comments true, unique, and within the kernel's density band.

Three checks, each one paid for by a defect found by hand:

STALE — a comment naming code that no longer exists. It hands the next reader
(human or model) a false mental model and shoehorns the next change around a
thing that is not there. Three were found on 2026-07-30: two dangling function
names and a 32-line duplicate that had drifted until it contradicted the
implementation it described.

DUPLICATE — the same explanation written twice. Both copies are maintained by
nobody, so they drift apart and then one of them is wrong. The stale check
cannot see this: a duplicate names only identifiers that DO exist. Two shipped
in cake.bpf.c — cake_pinned_wake_preempt's rationale appeared at both its
definition and its single call site, and a continuation-arm block still
described a 1.5x slice grant that had been deleted.

DENSITY — comment:code ratio against the kernel peer band. cake.bpf.c measured
2.00 on 2026-07-30 against EEVDF's 0.63 and a 0.15-0.73 scx peer range. History
belongs in HYPOTHESES.md / STATE.md / the commit message, with a section pointer
from the code; the source keeps WHAT and WHY (coding-style.rst §8).

Only project identifiers are checked for staleness (cake_*, CAKE_*, and the
SCREAMING_CASE policy constants). Prose emphasis like "MEASURED" and kernel
names cake does not define (SCX_ENQ_*, WF_SYNC, READ_ONCE) are deliberately NOT
flagged -- a first cut without that filter reported 53 hits of which 2 were real.

A reference is allowed when the same sentence marks it as history: "since
deleted", "was ", "used to", "no longer", "removed", "former".

    python3 bench/comment_lint.py src/bpf/cake.bpf.c src/bpf/intf.h
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter

HISTORY_MARKERS = (
    "no longer",
    "used to",
    "removed",
    "former",
    "deleted",
    "renamed",
    "replaced",
    "merged",
    "superseded",
    "since",
)

# Identifiers cake owns. Anything else in a comment is prose or kernel API.
OWNED = re.compile(r"\b(cake_[a-z0-9_]+|CAKE_[A-Z0-9_]+)\b")
# Policy constants: SCREAMING_CASE ending in a unit/verb we use.
POLICY = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:NS|MS|SHIFT|DEPTH|MAX|SIZE))\b")

# Peer band from coding-style.rst §8 and the 2026-07-30 measurement: EEVDF 0.63,
# scx peers 0.15-0.73. Above this, relocate the narrative rather than trim it.
DEFAULT_MAX_RATIO = 0.70
# Below this a block is a label, not an explanation, and repeating it is fine.
DUPLICATE_MIN_LINES = 3
# Jaccard over word multisets. 0.6 catches reworded copies without firing on
# two blocks that merely share this file's vocabulary.
DUPLICATE_MIN_SIMILARITY = 0.6


def split_comments(text: str) -> list[tuple[int, str]]:
    """Return (line_no, comment_text) for every comment line."""
    out: list[tuple[int, str]] = []
    in_block = False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        started = s.startswith("/*")
        if started:
            in_block = True
        if in_block or s.startswith("*") or s.startswith("//"):
            out.append((n, line))
        if "*/" in s:
            in_block = False
    return out


def comment_blocks(text: str) -> list[tuple[int, int, str]]:
    """Return (first_line, n_lines, prose) for every run of comment lines."""
    lines = dict(split_comments(text))
    out: list[tuple[int, int, str]] = []
    start = None
    body: list[str] = []
    for n in range(1, len(text.splitlines()) + 1):
        if n in lines:
            if start is None:
                start = n
            body.append(lines[n])
        elif start is not None:
            out.append((start, len(body), " ".join(body)))
            start, body = None, []
    if start is not None:
        out.append((start, len(body), " ".join(body)))
    return out


def prose_words(block: str) -> Counter:
    """Comment text reduced to its words, free of delimiters and case."""
    stripped = re.sub(r"/\*+|\*+/|^\s*\*|//", " ", block, flags=re.M)
    return Counter(re.findall(r"[a-z_][a-z0-9_]{2,}", stripped.lower()))


def similarity(a: Counter, b: Counter) -> float:
    """Jaccard over word multisets: shared words / total distinct words."""
    if not a or not b:
        return 0.0
    return sum((a & b).values()) / sum((a | b).values())


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def count_lines(text: str) -> tuple[int, int]:
    """Return (comment_lines, code_lines); blank lines count as neither."""
    comment = len(split_comments(text))
    code = sum(
        1
        for n, line in enumerate(text.splitlines(), 1)
        if line.strip() and n not in dict(split_comments(text))
    )
    return comment, code


def check_stale(sources: dict[str, str]) -> list[str]:
    # Everything defined anywhere in the checked set counts as existing.
    code = " ".join(strip_comments(t) for t in sources.values())
    defined = set(OWNED.findall(code)) | set(POLICY.findall(code))

    findings: list[str] = []
    for path, text in sources.items():
        for line_no, line in split_comments(text):
            low = line.lower()
            if any(m in low for m in HISTORY_MARKERS):
                continue
            named = set(OWNED.findall(line)) | set(POLICY.findall(line))
            for ident in sorted(named - defined):
                findings.append(
                    f"{path}:{line_no}: names '{ident}', which no longer exists in code"
                )
    return findings


def check_duplicates(sources: dict[str, str]) -> list[str]:
    blocks: list[tuple[str, int, int, Counter]] = []
    for path, text in sources.items():
        for start, size, body in comment_blocks(text):
            if size >= DUPLICATE_MIN_LINES:
                blocks.append((path, start, size, prose_words(body)))

    findings: list[str] = []
    for i, (pa, la, sa, wa) in enumerate(blocks):
        for pb, lb, sb, wb in blocks[i + 1:]:
            sim = similarity(wa, wb)
            if sim >= DUPLICATE_MIN_SIMILARITY:
                findings.append(
                    f"{pa}:{la}: {sa}-line comment is {sim:.0%} the same as "
                    f"{pb}:{lb} ({sb} lines) -- one description, at the code"
                )
    return findings


def check_density(sources: dict[str, str], max_ratio: float) -> list[str]:
    findings: list[str] = []
    for path, text in sources.items():
        comment, code = count_lines(text)
        if not code:
            continue
        ratio = comment / code
        if ratio > max_ratio:
            findings.append(
                f"{path}: comment:code {ratio:.2f} exceeds {max_ratio:.2f} "
                f"({comment} comment / {code} code) -- relocate the narrative "
                f"to HYPOTHESES.md and leave a section pointer"
            )
    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO)
    ap.add_argument("--skip-density", action="store_true")
    args = ap.parse_args(argv)

    sources = {p: open(p, encoding="utf-8").read() for p in args.paths}

    failures = 0
    for label, findings, hint in (
        (
            "stale",
            check_stale(sources),
            "Fix the comment, or mark it as history "
            f"({', '.join(HISTORY_MARKERS[:3])}, ...).",
        ),
        (
            "duplicate",
            check_duplicates(sources),
            "Delete one copy. Two copies of a decision drift until one is wrong.",
        ),
        (
            "density",
            [] if args.skip_density else check_density(sources, args.max_ratio),
            "Nothing is deleted -- it is RELOCATED. See CLAUDE.md §Design laws.",
        ),
    ):
        if findings:
            failures += len(findings)
            for f in findings:
                print(f"{label}: {f}")
            print(f"  {hint}\n")

    if failures:
        print(f"{failures} finding(s).")
        return 1

    for path, text in sources.items():
        comment, code = count_lines(text)
        ratio = comment / code if code else 0.0
        print(f"comment_lint: {path} clean ({ratio:.2f} comment:code)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
