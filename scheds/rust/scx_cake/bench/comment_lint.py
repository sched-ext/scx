#!/usr/bin/env python3
"""Check source comments against the project's comment rules.

STALE: a comment names a project identifier that no code in the checked set defines.
DUPLICATE: two comments say the same thing; both copies drift until one is wrong.
DENSITY: comment-only lines per code line exceed the project ceiling.
BLOCK FORMAT: a C comment over one line does not use the kernel's block format.

Only project identifiers are checked for staleness (cake_*, CAKE_* and the
SCREAMING_CASE policy constants); prose and kernel names cake does not define are
not. A comment is one line; the summary counts the blocks that are longer.

    python3 bench/comment_lint.py src/bpf/cake.bpf.c src/bpf/intf.h
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter

# Identifiers cake owns. Anything else in a comment is prose or kernel API.
OWNED = re.compile(r"\b(cake_[a-z0-9_]+|CAKE_[A-Z0-9_]+)\b")
# Policy constants: SCREAMING_CASE ending in a unit/verb we use.
POLICY = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:NS|MS|SHIFT|DEPTH|MAX|SIZE))\b")
# A block comment with text on its opening line; the kernel format opens on a bare /*.
TEXT_ON_OPENING = re.compile(r"/\*+\s*\S")

# The project ceiling: comment-only lines per code line.
DEFAULT_MAX_RATIO = 0.20
# Below this a comment is a label, not an explanation, and repeating it is fine.
DUPLICATE_MIN_WORDS = 10
# Jaccard over word multisets. 0.6 catches reworded copies without firing on
# two comments that merely share this file's vocabulary.
DUPLICATE_MIN_SIMILARITY = 0.6


def scan_lines(text: str) -> list[tuple[str, str | None]]:
    """Split each line into (code, comment); comment is None on a line with none."""
    rows: list[tuple[str, str | None]] = []
    in_block = False
    for line in text.splitlines():
        code: list[str] = []
        comment: list[str] | None = [] if in_block else None
        quoted = False
        i = 0
        while i < len(line):
            if in_block or (not quoted and line.startswith("/*", i)):
                end = line.find("*/", i if in_block else i + 2)
                stop = len(line) if end < 0 else end + 2
                comment = (comment or []) + [line[i:stop]]
                in_block = end < 0
                i = stop
            elif not quoted and line.startswith("//", i):
                comment = (comment or []) + [line[i:]]
                break
            elif quoted and line[i] == "\\":
                code.append(line[i:i + 2])
                i += 2
            elif not quoted and line.startswith("'\"'", i):
                code.append(line[i:i + 3])
                i += 3
            else:
                quoted ^= line[i] == '"'
                code.append(line[i])
                i += 1
        rows.append(("".join(code), None if comment is None else "".join(comment)))
    return rows


def comment_blocks(rows: list[tuple[str, str | None]]) -> list[tuple[int, int, str]]:
    """Return (first_line, n_lines, prose) for every run of comment-only lines."""
    out: list[tuple[int, int, str]] = []
    start = 0
    body: list[str] = []
    for n, (code, comment) in enumerate(rows, 1):
        if comment is not None and not code.strip():
            if not body:
                start = n
            body.append(comment)
        elif body:
            out.append((start, len(body), " ".join(body)))
            body = []
    if body:
        out.append((start, len(body), " ".join(body)))
    return out


def prose_words(block: str) -> Counter:
    """Comment text reduced to its words, free of delimiters and case."""
    stripped = re.sub(r"/\*+|\*+/|^\s*\*|//", " ", block, flags=re.M)
    return Counter(re.findall(r"[a-z_][a-z0-9_]{2,}", stripped.lower()))


def similarity(a: Counter, b: Counter) -> float:
    """Jaccard over word multisets: shared words / total distinct words."""
    return sum((a & b).values()) / sum((a | b).values())


def count_lines(rows: list[tuple[str, str | None]]) -> tuple[int, int]:
    """Return (comment_only_lines, code_lines); blank lines count as neither."""
    code = sum(1 for c, _ in rows if c.strip())
    comment = sum(1 for c, m in rows if m is not None and not c.strip())
    return comment, code


def check_stale(sources: dict[str, list]) -> list[str]:
    # Everything defined anywhere in the checked set counts as existing.
    code = " ".join(c for rows in sources.values() for c, _ in rows)
    defined = set(OWNED.findall(code)) | set(POLICY.findall(code))

    findings: list[str] = []
    for path, rows in sources.items():
        for n, (_, comment) in enumerate(rows, 1):
            if not comment:
                continue
            named = set(OWNED.findall(comment)) | set(POLICY.findall(comment))
            for ident in sorted(named - defined):
                findings.append(f"{path}:{n}: names '{ident}', which no code here defines")
    return findings


def check_duplicates(sources: dict[str, list]) -> list[str]:
    blocks: list[tuple[str, int, Counter]] = []
    for path, rows in sources.items():
        for start, _, body in comment_blocks(rows):
            words = prose_words(body)
            if sum(words.values()) >= DUPLICATE_MIN_WORDS and "SPDX" not in body:
                blocks.append((path, start, words))

    findings: list[str] = []
    for i, (pa, la, wa) in enumerate(blocks):
        for pb, lb, wb in blocks[i + 1:]:
            sim = similarity(wa, wb)
            if sim >= DUPLICATE_MIN_SIMILARITY:
                findings.append(
                    f"{pa}:{la}: comment is {sim:.0%} the same as {pb}:{lb}; keep one, at the code"
                )
    return findings


def check_density(sources: dict[str, list], max_ratio: float) -> list[str]:
    findings: list[str] = []
    for path, rows in sources.items():
        comment, code = count_lines(rows)
        if code and comment / code > max_ratio:
            findings.append(
                f"{path}: comment:code {comment / code:.2f} exceeds {max_ratio:.2f} "
                f"({comment} comment / {code} code)"
            )
    return findings


def check_block_format(sources: dict[str, list]) -> list[str]:
    findings: list[str] = []
    for path, rows in sources.items():
        for n, (_, comment) in enumerate(rows, 1):
            if comment and "*/" not in comment and TEXT_ON_OPENING.match(comment.lstrip()):
                findings.append(f"{path}:{n}: multi-line comment has text on its opening line")
    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO)
    args = ap.parse_args(argv)

    sources = {p: scan_lines(open(p, encoding="utf-8").read()) for p in args.paths}

    failures = 0
    for label, findings, hint in (
        ("stale", check_stale(sources), "Fix the comment; history lives in STATE.md and git."),
        ("duplicate", check_duplicates(sources), "Delete one copy."),
        (
            "density",
            check_density(sources, args.max_ratio),
            "Cut to one line each; design narrative goes in DESIGN.md or STATE.md.",
        ),
        (
            "block format",
            check_block_format(sources),
            "Cut to one line, or open with a bare /* and close with a bare */.",
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

    for path, rows in sources.items():
        comment, code = count_lines(rows)
        ratio = comment / code if code else 0.0
        multi = sum(1 for _, size, _ in comment_blocks(rows) if size > 1)
        print(f"comment_lint: {path} clean ({ratio:.2f} comment:code, {multi} multi-line)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
