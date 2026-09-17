"""Render a small PNG "evidence card" without third-party imaging libraries.

The conformance suite only accepts PNG/JPEG uploads for REVIEW placeholders. The
card states what the harness observed in Inji's own verification result, so a human
reviewer (or a certification package) sees the same facts the gate used.
"""

from __future__ import annotations

import base64
import struct
import zlib

# 5x7 bitmap font, one string of 7 rows per glyph ('#' = ink). Lowercase is rendered
# as uppercase to keep the table small.
_FONT_ROWS = {
    "A": ".###.#...##...#######...##...##...#", "B": "####.#...#####.#...##...##...#####.",
    "C": ".###.#...##....#....#....#...#.###.", "D": "####.#...##...##...##...##...#####.",
    "E": "######....####.#....#....#....#####", "F": "######....####.#....#....#....#....",
    "G": ".###.#...##....#.####...##...#.####", "H": "#...##...#######...##...##...##...#",
    "I": ".###...#....#....#....#....#...###.", "J": "..###...#....#....#.#..#.#..#..##..",
    "K": "#...##..#.#.#..##...#.#..#..#.#...#", "L": "#....#....#....#....#....#....#####",
    "M": "#...###.###.#.##...##...##...##...#", "N": "#...###..##.#.##..###...##...##...#",
    "O": ".###.#...##...##...##...##...#.###.", "P": "####.#...##...#####.#....#....#....",
    "Q": ".###.#...##...##...##.#.##..#..##.#", "R": "####.#...##...#####.#.#..#..#.#...#",
    "S": ".####.....#.....###.....#....#####.", "T": "#####..#....#....#....#....#....#..",
    "U": "#...##...##...##...##...##...#.###.", "V": "#...##...##...##...##...#.#.#...#..",
    "W": "#...##...##...##.#.##.#.##.#.#.#.#.", "X": "#...##...#.#.#...#...#.#.#...##...#",
    "Y": "#...##...#.#.#...#....#....#....#..", "Z": "#####....#...#...#...#...#....#####",
    "0": ".###.#...##..###.#.###..##...#.###.", "1": "..#...##....#....#....#....#...###.",
    "2": ".###.#...#....#...#...#...#...#####", "3": "####.....#....#.###.....#....#####.",
    "4": "...#...##..#.#.#..#.#####...#....#.", "5": "######....####.....#....#....#####.",
    "6": ".###.#....#....####.#...##...#.###.", "7": "#####....#...#...#...#....#....#...",
    "8": ".###.#...##...#.###.#...##...#.###.", "9": ".###.#...##...#.####....#....#.###.",
    " ": "...................................", ".": "..............................##...",
    ":": "......##...##.........##...##......", "-": "...............#####...............",
    "_": "..............................#####", "/": "....#...#...#...#...#....#.........",
    "=": "..........#####.....#####..........", "(": "...#...#...#....#....#.....#.....#.",
    ")": ".#.....#.....#....#....#...#...#...", ",": "........................##...#..#..",
    "'": "..#....#...........................", "?": ".###.#...#....#...#....#.........#.",
    "#": ".#.#.#####.#.#..#.#.#####.#.#......", "+": ".......#....#..#####..#....#.......",
}
_GLYPH_W, _GLYPH_H, _SCALE = 5, 7, 2


def _glyph(ch: str) -> str:
    return _FONT_ROWS.get(ch.upper(), _FONT_ROWS["?"])


def render_card(lines: list[str], *, accent: tuple[int, int, int], width_chars: int = 72) -> bytes:
    """Return PNG bytes for a text card. Lines longer than ``width_chars`` are wrapped."""
    wrapped: list[str] = []
    for line in lines:
        while len(line) > width_chars:
            wrapped.append(line[:width_chars])
            line = "  " + line[width_chars:]
        wrapped.append(line)

    cell_w = (_GLYPH_W + 1) * _SCALE
    cell_h = (_GLYPH_H + 3) * _SCALE
    pad = 16
    bar = 8
    width = pad * 2 + width_chars * cell_w
    height = pad * 2 + bar + len(wrapped) * cell_h
    background = (255, 255, 255)
    ink = (20, 24, 31)

    pixels = [[background] * width for _ in range(height)]
    for y in range(bar):
        pixels[y] = [accent] * width

    for row_index, text in enumerate(wrapped):
        top = pad + bar + row_index * cell_h
        for col_index, ch in enumerate(text):
            glyph = _glyph(ch)
            left = pad + col_index * cell_w
            for gy in range(_GLYPH_H):
                for gx in range(_GLYPH_W):
                    if glyph[gy * _GLYPH_W + gx] != "#":
                        continue
                    for sy in range(_SCALE):
                        row = pixels[top + gy * _SCALE + sy]
                        for sx in range(_SCALE):
                            row[left + gx * _SCALE + sx] = ink
    return _encode_png(width, height, pixels)


def _encode_png(width: int, height: int, pixels: list[list[tuple[int, int, int]]]) -> bytes:
    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type: none
        for r, g, b in row:
            raw.extend((r, g, b))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")


def to_data_url(png: bytes) -> str:
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")
