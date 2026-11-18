#!/usr/bin/env python3
"""The sched_ext Discord emoji set: the mark knocked out of a filled rounded
square, in teal, in the K&R cover's blues and in Rust red, and the mark alone
in its own teal with no fill. Writes the four emoji, a preview at Discord's
sizes on its dark and light themes, and a zip of the four into OUT_DIR.

usage: make_emoji.py OUT_DIR
needs: rsvg-convert (librsvg), magick (ImageMagick 7)"""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

LOGO = Path(__file__).resolve().parent / "sched_ext-logo.svg"
LOGO_FILL = "#18ad9e"
# name: (ground, mark). The C badge is the first edition's cover, its title
# blue on the large C's pale blue.
BADGES = {
    "scx": ("#18ad9e", "#ffffff"),
    "scx_c": ("#A8B9CC", "#1B75B3"),
    "scx_rust": ("#CE422B", "#ffffff"),
}
PLAIN = ("sched_ext", LOGO_FILL)
SIZE = 128
RADIUS = 28
BADGE_INNER = 100
PLAIN_INNER = SIZE - 2
DISCORD_DARK = "#313338"
DISCORD_LIGHT = "#ffffff"
SHEET_SIZES = (16, 22, 32, 48, 128)
LIMIT = 256 * 1024


def run(*cmd: str) -> None:
    subprocess.run(cmd, check=True)


def mark(colour: str, inner: int, dest: Path, work: Path) -> None:
    """The mark in one colour, trimmed to its edges, inner px across, centred
    on a transparent SIZE x SIZE square."""
    svg = work / f"{dest.stem}.svg"
    svg.write_text(LOGO.read_text().replace(f"fill:{LOGO_FILL}", f"fill:{colour}"))
    big = work / f"{dest.stem}-1024.png"
    run("rsvg-convert", "-w", "1024", str(svg), "-o", str(big))
    run("magick", str(big), "-trim", "+repage", "-resize", f"{inner}x{inner}",
        "-background", "none", "-gravity", "center",
        "-extent", f"{SIZE}x{SIZE}", "-strip", str(dest))


def badge(name: str, out: Path, work: Path) -> Path:
    g, m = BADGES[name]
    fg, bg = work / f"{name}-mark.png", work / f"{name}-ground.png"
    mark(m, BADGE_INNER, fg, work)
    run("magick", "-size", f"{SIZE}x{SIZE}", "xc:none", "-fill", g,
        "-draw", f"roundrectangle 0,0 {SIZE - 1},{SIZE - 1} {RADIUS},{RADIUS}",
        str(bg))
    dest = out / f"{name}.png"
    run("magick", str(bg), str(fg), "-composite", "-strip", str(dest))
    return dest


def plain(name: str, colour: str, out: Path, work: Path) -> Path:
    dest = out / f"{name}.png"
    mark(colour, PLAIN_INNER, dest, work)
    return dest


def preview(files: list[Path], dest: Path, work: Path) -> None:
    halves = []
    for theme in (DISCORD_DARK, DISCORD_LIGHT):
        rows = []
        for src in files:
            cells = []
            for s in SHEET_SIZES:
                cell = work / f"cell-{src.stem}-{s}-{theme[1:]}.png"
                run("magick", str(src), "-resize", f"{s}x{s}",
                    "-background", theme, "-gravity", "center",
                    "-extent", f"{max(s, 48) + 16}x{SIZE + 16}", str(cell))
                cells.append(str(cell))
            row = work / f"row-{src.stem}-{theme[1:]}.png"
            run("magick", *cells, "+append", str(row))
            rows.append(str(row))
        half = work / f"half-{theme[1:]}.png"
        run("magick", *rows, "-append", str(half))
        halves.append(str(half))
    run("magick", *halves, "+append", "-strip", str(dest))


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        emoji = [badge(name, out, work) for name in BADGES]
        emoji.append(plain(*PLAIN, out, work))
        preview(emoji, out / "preview.png", work)
    with zipfile.ZipFile(out / "sched_ext-emoji.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for f in emoji:
            z.write(f, f.name)
    over = [f.name for f in emoji if f.stat().st_size > LIMIT]
    for f in emoji + [out / "preview.png", out / "sched_ext-emoji.zip"]:
        print(f"{f.name}\t{f.stat().st_size}")
    if over:
        print(f"over Discord's 256 KB: {', '.join(over)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
