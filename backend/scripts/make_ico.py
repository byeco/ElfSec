"""Çok çözünürlüklü PNG tabanlı Windows .ico üretici (saf Python stdlib).

Kullanım:
    python backend/scripts/make_ico.py
"""

from __future__ import annotations

import struct
from pathlib import Path


def _read_png_dimensions(raw: bytes) -> tuple[int, int]:
    if len(raw) < 24 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Geçerli bir PNG dosyası değil.")
    width, height = struct.unpack(">II", raw[16:24])
    return int(width), int(height)


def build_ico(png_paths: list[Path], out_path: Path) -> Path:
    """Verilen PNG dosyalarını Vista+ PNG-sıkıştırmalı çoklu .ico dosyasında birleştirir."""
    images: list[tuple[int, int, bytes]] = []
    for p in png_paths:
        raw = Path(p).read_bytes()
        w, h = _read_png_dimensions(raw)
        images.append((w, h, raw))
    if not images:
        raise ValueError("En az bir PNG dosyası gerekli.")

    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = bytearray()
    payload = bytearray()

    for w, h, raw in images:
        bw = 0 if w >= 256 else w
        bh = 0 if h >= 256 else h
        entries.extend(struct.pack("<BBBBHHII", bw, bh, 0, 0, 1, 32, len(raw), offset))
        payload.extend(raw)
        offset += len(raw)

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(header) + bytes(entries) + bytes(payload))
    return out


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    icons_dir = repo_root / "extension" / "icons"
    pngs = [
        icons_dir / f"icon{sz}.png"
        for sz in (16, 32, 48, 128)
        if (icons_dir / f"icon{sz}.png").exists()
    ]
    if not pngs:
        raise FileNotFoundError(f"İkon PNG dosyaları bulunamadı: {icons_dir}")

    targets = [
        repo_root / "installer" / "elfsec.ico",
        repo_root / "backend" / "assets" / "elfsec.ico",
    ]
    for tgt in targets:
        p = build_ico(pngs, tgt)
        print(f"OK: {p} ({p.stat().st_size} bayt)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
