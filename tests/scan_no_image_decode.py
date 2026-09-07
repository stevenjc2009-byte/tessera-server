#!/usr/bin/env python3
"""Fail if the daemon's source imports anything that could decode an image.

The spec's single hardest security requirement is that the server never
interprets uploaded bytes (spec section 5.6). This is a source-level proof of
that: an AST walk over every module, refusing any import whose top-level name
is on the banned list.

Usage:  python3 tests/scan_no_image_decode.py src/tessera
Exit 0 = clean. Exit 1 = a banned import was found, and it prints where.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

BANNED_MODULES: frozenset[str] = frozenset(
    {
        "PIL",
        "Pillow",
        "cv2",
        "imageio",
        "skimage",
        "png",
        "pypng",
        "imghdr",
        "wand",
        "pyvips",
        "cairosvg",
        "numpy",
        "matplotlib",
        "tkinter",
        "turtle",
        "colorsys",
    }
)


def banned_imports(source: str, where: Path) -> list[str]:
    findings: list[str] = []
    for node in ast.walk(ast.parse(source, filename=str(where))):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            continue
        for name in names:
            top = name.split(".", 1)[0]
            if top in BANNED_MODULES:
                findings.append(f"{where}:{node.lineno}: imports {name!r}")
    return findings


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.py")):
        findings.extend(banned_imports(path.read_text(encoding="utf-8"), path))
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "src/tessera")
    findings = scan(root)
    if findings:
        print("IMAGE DECODING IMPORT FOUND — the server must never decode uploads:")
        for line in findings:
            print("  " + line)
        return 1
    count = len(list(root.rglob("*.py")))
    print(f"  no image-decoding imports in {count} modules under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
