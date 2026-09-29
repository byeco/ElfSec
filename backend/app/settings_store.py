"""Ayarları tuttuğum yer — başta tek bir .env vardı, sonra işler karıştı.

Kullanıcılar "benim evde ayrı işte ayrı hesabım var" deyince katmanlı
sisteme geçtim. Öncelik sırası (yüksekten düşüğe):
  1. Ortam değişkenleri  (IMAP_PASSWORD=... → otomasyon için pratik)
  2. --config YOLU / ELFSEC_CONFIG ortam değişkeni
  3. Kullanıcı dosyası: %APPDATA%/ElfSec/elfsec.env (Win) / ~/.config/elfsec/elfsec.env
  4. ./backend/.env ve ./.env (ilk sürümden kalanlarla uyumluluk için)

Şifreler dosyada açık durmuyor, Windows'un kendi kasasıyla (DPAPI)
şifrelenip ENC(...) olarak yazılıyor. Hatalı ayarda Türkçe mesaj
veriyorum, yoksa insan neyi yanlış yaptığını anlamıyor (kendimden biliyorum).

Not: bu projede hiç API anahtarı yok — analiz %100 yerelde oluyor.
"""

import os
from pathlib import Path

from dotenv import dotenv_values
from pydantic import ValidationError

from app import secret_vault
from app.config import Settings

APP_NAME = "ElfSec"
SECRET_KEYS = {"IMAP_PASSWORD", "OAUTH_REFRESH_OUTLOOK", "OAUTH_REFRESH_GMAIL"}
FIELD_BY_KEY = {name.upper(): name for name in Settings.model_fields}

# Alan bazlı Türkçe doğrulama ipuçları
FIELD_HINTS = {
    "IMAP_HOST": "IMAP_HOST boş olamaz. Örn: imap.gmail.com / outlook.office365.com",
    "IMAP_PORT": "IMAP_PORT 1-65535 arası sayı olmalı (genelde 993).",
    "IMAP_USER": "IMAP_USER e-posta adresiniz. Örn: ad@gmail.com",
    "IMAP_PASSWORD": "IMAP_PASSWORD yok. Seçenek: uygulama şifresi YA DA `elfsec config login --provider outlook|gmail` (OAuth, önerilir).",
    "OAUTH_PROVIDER": "OAUTH_PROVIDER outlook|gmail olmalı (boşsa şifreli giriş).",
    "MS_CLIENT_ID": "MS_CLIENT_ID boş. Azure Portal → App registrations → kendi uygulamanızın ID'si.",
    "GOOGLE_CLIENT_ID": "GOOGLE_CLIENT_ID boş. Google Cloud → OAuth client (Desktop) ID'si.",
    "OAUTH_REFRESH_OUTLOOK": "Önce `elfsec config login --provider outlook` ile giriş yapın.",
    "OAUTH_REFRESH_GMAIL": "Önce `elfsec config login --provider gmail` ile giriş yapın.",
}


class ConfigError(Exception):
    def __init__(self, hints: list[str], source: str = ""):
        self.hints = hints
        self.source = source
        super().__init__("; ".join(hints))


def default_user_config_path() -> Path:
    # Test/CI izolasyonu: her platformda geçerli açık geçersiz kılma.
    override = os.environ.get("ELFSEC_CONFIG_DIR", "").strip()
    if override:
        return Path(override) / "elfsec.env"
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
        return base / APP_NAME / "elfsec.env"
    return Path.home() / ".config" / "elfsec" / "elfsec.env"


def candidate_files(explicit: str | None = None) -> list[Path]:
    cands: list[Path] = []
    if explicit:
        cands.append(Path(explicit))
    elif os.environ.get("ELFSEC_CONFIG"):
        cands.append(Path(os.environ["ELFSEC_CONFIG"]))
    cands.append(default_user_config_path())
    cands += [Path("backend") / ".env", Path(".env")]
    return cands


def find_config_file(explicit: str | None = None) -> Path | None:
    for p in candidate_files(explicit):
        if p.exists():
            return p
    return None


def load_file_values(path: Path) -> tuple[dict, list[str]]:
    """Dosyayı oku, ENC(...) değerleri çöz. Dönüş: ({ALAN: değer}, uyarılar)."""
    warnings: list[str] = []
    raw = dotenv_values(str(path))
    out: dict = {}
    for key, val in raw.items():
        if key not in FIELD_BY_KEY or val is None:
            continue
        try:
            out[FIELD_BY_KEY[key]] = secret_vault.unprotect(val)
        except OSError as e:
            warnings.append(f"{key} çözülemedi ({e}). Dosyayı oluşturan kullanıcı/PC ile açın.")
    return out, warnings


def build_settings(explicit: str | None = None) -> tuple[Settings, Path | None, list[str]]:
    """Katmanları birleştir + doğrula. Hata varsa Türkçe ConfigError yükseltir."""
    found = find_config_file(explicit)
    if explicit and not (found and str(found) == explicit):
        raise ConfigError([f"Config dosyası bulunamadı: {explicit}"], source=explicit)
    merged: dict = {}
    warnings: list[str] = []
    if found:
        file_vals, warnings = load_file_values(found)
        merged.update(file_vals)
    for key, field in FIELD_BY_KEY.items():  # ortam değişkenleri dosyayı ezer
        if key in os.environ and os.environ[key] != "":
            merged[field] = os.environ[key]
    try:
        settings = Settings(**merged)
    except ValidationError as e:
        hints = []
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"]).upper()
            hints.append(FIELD_HINTS.get(loc, f"{loc}: {err['msg']}"))
        raise ConfigError(hints, source=str(found) if found else "")
    warnings += semantic_warnings(settings)
    return settings, found, warnings


def semantic_warnings(s: Settings) -> list[str]:
    w: list[str] = []
    if s.imap_user and not s.imap_password and not s.oauth_configured:
        w.append("IMAP_USER var ama giriş yok — `elfsec config login --provider outlook|gmail` (önerilir) "
                 "veya `elfsec config set IMAP_PASSWORD ...` ile ekleyin.")
    if not s.imap_configured and not s.oauth_configured:
        w.append("IMAP yapılandırılmamış — fetch/triage/guard çalışmaz (analiz çalışır).")
    return w


def mask(value: str, secret: bool = False) -> str:
    if not value:
        return "(boş)"
    if secret:
        return value[:2] + "***" if len(value) > 4 else "***"
    return value if len(value) <= 60 else value[:57] + "..."


# --- CLI süreci için tekil erişim (config dosya yolu + önbellek) ---

_EXPLICIT: str | None = None
_CACHE: dict = {}


def set_explicit(path: str | None) -> None:
    global _EXPLICIT
    _EXPLICIT = path
    _CACHE.clear()


def get_explicit() -> str | None:
    return _EXPLICIT or os.environ.get("ELFSEC_CONFIG")


def current_settings() -> Settings:
    """Tüm CLI komutlarının kullanması gereken ayarlar (doğrulanmış)."""
    if "settings" not in _CACHE:
        s, _found, warnings = build_settings(_EXPLICIT)
        for w in warnings:
            print(f"UYARI: {w}")
        _CACHE["settings"] = s
    return _CACHE["settings"]


def upsert_kv(path: Path, key: str, value: str, secret: bool = False) -> str:
    """Dosyaya KEY=VALUE yaz/güncelle. Dönüş: saklanan ham değer."""
    key = key.upper()
    if key not in FIELD_BY_KEY:
        raise ConfigError([f"Bilinmeyen ayar: {key}. Geçerli: {', '.join(sorted(FIELD_BY_KEY))}"])
    stored = secret_vault.protect(value) if (secret or key in SECRET_KEYS) else value
    if secret or key in SECRET_KEYS:
        ok, why = secret_vault.available()
        if not ok:
            print(f"UYARI: {why}")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    lines = [ln for ln in lines if not ln.strip().startswith(f"{key}=")]
    stored_q = f'"{stored}"' if any(c in stored for c in " #\"") else stored
    lines.append(f"{key}={stored_q}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _lock_down(path)
    return stored


def config_mode(path: Path) -> int:
    """Dosya izin bitleri (yoksa -1)."""
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return -1


def _windows_acl_tight(path: Path) -> bool | None:
    """Windows ACL sıkı mı? True=sıkı, False=gevşek, None=bilinmiyor (best-effort)."""
    if os.name != "nt":
        return None
    try:
        import subprocess

        r = subprocess.run(["icacls", str(path)], capture_output=True, timeout=10, check=False)
        out = (r.stdout or b"").decode("utf-8", errors="replace") + (r.stderr or b"").decode("utf-8", errors="replace")
        if not out.strip():
            return None
        loose = ("Everyone", "BUILTIN\\Users", "Authenticated Users", "NT AUTHORITY\\Authenticated Users")
        return not any(k.lower() in out.lower() for k in loose)
    except Exception:
        return None


def _lock_down(path: Path) -> None:
    """Gizli dosya: sadece sahibi okusun (POSIX 0o600; Windows icacls)."""
    try:
        if os.name == "nt":
            # Gerçek koruma DPAPI şifrelemesidir; ACL ek kilit olarak denenir.
            try:
                import subprocess

                user = os.environ.get("USERNAME", "")
                if user:
                    subprocess.run(
                        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                        capture_output=True, timeout=10, check=False,
                    )
            except Exception:
                pass
            return
        os.chmod(path, 0o600)
    except Exception as e:
        print(f"UYARI: dosya izni sıkılaştırılamadı ({path}): {e}")
