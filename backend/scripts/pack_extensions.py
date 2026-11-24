"""Chrome Web Store, Edge Add-ons, Firefox AMO ve GitHub için uzantı ZIP paketleyici.

Kullanım:
    python scripts/pack_extensions.py --out ../dist_ext

GÜVENLİK: Mağazaya giden pakete gizli anahtar, .env, harita (source map),
geliştirici notu veya önbellek dosyası sızmamalı. Bu yüzden yalnızca
bilinen güvenli dosyalar paketlenir; `.pem`/`.key` gibi bir sır dosyası
görülürse paketleme sessizce devam etmez, hata verir (fail-closed).
ZIP'ler önce geçici dosyaya yazılır, ancak başarıyla tamamlanınca yerine
taşınır; böylece yarım/bozuk bir mağaza paketi yayınlanmaz.
"""

from __future__ import annotations

import argparse
import json
import os
import zipfile
from pathlib import Path

EXCLUDE_DIRS = {"__pycache__", "node_modules", ".git", ".github", ".idea", ".vscode"}
EXCLUDE_NAMES = {"STORE_LISTING.md", ".DS_Store", "Thumbs.db"}
EXCLUDE_SUFFIXES = {".zip", ".crx", ".map", ".log", ".bak", ".swp", ".tmp", ".orig"}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SECRET_NAMES = {".env", ".env.local", ".npmrc", ".netrc", "id_rsa", "id_ed25519"}

REQUIRED_MANIFEST_FIELDS = ("name", "version", "description")


def _is_secret(p: Path) -> bool:
    name = p.name.lower()
    return (
        p.suffix.lower() in SECRET_SUFFIXES
        or name in SECRET_NAMES
        or name.startswith(".env")
    )


def _iter_extension_files(ext_dir: Path) -> list[Path]:
    files: list[Path] = []
    for p in sorted(ext_dir.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(ext_dir).parts
        if any(part in EXCLUDE_DIRS or part.startswith(".") for part in rel_parts[:-1]):
            continue
        if p.name.startswith(".") or p.name in EXCLUDE_NAMES:
            continue
        if p.suffix.lower() in EXCLUDE_SUFFIXES:
            continue
        if _is_secret(p):
            raise ValueError(f"Mağaza paketine sır dosyası giremez: {p}")
        files.append(p)
    return files


def _validate_manifest(mf: dict) -> None:
    if mf.get("manifest_version") != 3:
        raise ValueError("manifest.json 'manifest_version' değeri 3 olmalı.")
    for key in REQUIRED_MANIFEST_FIELDS:
        if not str(mf.get(key, "") or "").strip():
            raise ValueError(f"manifest.json içinde '{key}' alanı zorunlu.")
    if not isinstance(mf.get("permissions", []), list):
        raise ValueError("manifest.json 'permissions' alanı liste olmalı.")


def _build_manifest_for_target(base_manifest: dict, target: str) -> dict:
    mf = json.loads(json.dumps(base_manifest))
    if target == "chrome_edge":
        mf.pop("key", None)
        mf.pop("browser_specific_settings", None)
        mf["background"] = {"service_worker": "background.js"}
    elif target == "firefox":
        mf.pop("key", None)
        mf["background"] = {"scripts": ["fallback_analyzer.js", "background.js"]}
    elif target == "unpacked":
        pass
    else:
        raise ValueError(f"Bilinmeyen hedef: {target}")
    return mf


def pack_all(ext_dir: Path, out_dir: Path) -> dict[str, Path]:
    ext_dir = Path(ext_dir).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json bulunamadı: {manifest_path}")
    base_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _validate_manifest(base_manifest)
    files = _iter_extension_files(ext_dir)

    targets = {
        "chrome_edge": out_dir / "elfsec-extension-chrome-edge-store.zip",
        "firefox": out_dir / "elfsec-extension-firefox-amo.zip",
        "unpacked": out_dir / "elfsec-browser-extension.zip",
    }

    for target, zip_path in targets.items():
        manifest_obj = _build_manifest_for_target(base_manifest, target)
        tmp_path = zip_path.with_name(zip_path.name + ".tmp")
        try:
            with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for fp in files:
                    rel = fp.relative_to(ext_dir).as_posix()
                    if rel == "manifest.json":
                        zf.writestr("manifest.json", json.dumps(manifest_obj, indent=2, ensure_ascii=False) + "\n")
                    else:
                        zf.write(fp, rel)
            os.replace(tmp_path, zip_path)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return targets


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="ElfSec tarayıcı uzantısını mağazalar için paketler.")
    parser.add_argument("--ext-dir", default=str(repo_root / "extension"))
    parser.add_argument("--out", default=str(repo_root))
    args = parser.parse_args()

    out = pack_all(Path(args.ext_dir), Path(args.out))
    for name, p in out.items():
        print(f"OK [{name}]: {p} ({p.stat().st_size} bayt)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
