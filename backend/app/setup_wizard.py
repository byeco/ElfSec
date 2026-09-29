"""Mail kurulum sihirbazı — arkadaşlarım "kuramadık" deyince yazmaya karar verdim.

Fikir: kullanıcıya teknik sorular sormak yerine e-posta adresinden
sağlayıcıyı otomatik tanıyor, tarayıcıyı DOĞRU uygulama-şifresi
sayfasında açıyor, şifreyi alıp bağlantıyı ANINDA test ediyor.
Olmadıysa hatayı sınıflandırıp ne yapması gerektiğini söylüyor
(en fazla 3 deneme, sonra bırakıyor).

Kullanım: `elfsec config setup [--email ...] [--no-browser]`
Şifre ASLA komut satırı argümanı olmuyor (process listesinde görünürmüş,
güvenlik dersinde öğrendim) — gizli gizli soruluyor ya da
ELFSEC_SETUP_PASSWORD ortam değişkeninden okunuyor.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Callable

MAX_ATTEMPTS = 3

PRESETS: dict[str, dict] = {
    "gmail": {
        "label": "Gmail",
        "domains": ("gmail.com", "googlemail.com"),
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "app_password_url": "https://myaccount.google.com/apppasswords",
        "oauth": True,
        "steps": (
            "Google Hesabınızda 2 Adımlı Doğrulama AÇIK olmalı "
            "(Hesabım > Güvenlik > 2 Adımlı Doğrulama). Kapalıysa önce açın.",
            "Tarayıcıda açılan sayfada bir ad yazın (örn. ElfSec) ve Oluştur'a basın.",
            "Ekrandaki 16 harfli kodu kopyalayın (boşluksuz da olur).",
        ),
        "notes": "Normal Gmail şifreniz burada ÇALIŞMAZ — mutlaka uygulama şifresi gerekir.",
    },
    "outlook": {
        "label": "Outlook / Hotmail / Live",
        "domains": ("outlook.com", "outlook.com.tr", "hotmail.com", "hotmail.com.tr",
                    "live.com", "msn.com", "outlook.fr", "outlook.de"),
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "app_password_url": "https://account.microsoft.com/account/manage-my-account/security-info",
        "oauth": True,
        "steps": (
            "Microsoft hesabınızda 2 Adımlı Doğrulama AÇIK olmalı.",
            "Açılan sayfada Güvenlik bilgileri > Yeni oturum açma yöntemi ekle > Uygulama şifresi.",
            "Ekrandaki kodu kopyalayın.",
        ),
        "notes": ("Bazı kurumsal (iş/okul) hesaplarda uygulama şifresi kapalıdır — "
                  "o durumda 2. yöntem olan OAuth'u seçin."),
    },
    "yahoo": {
        "label": "Yahoo",
        "domains": ("yahoo.com", "yahoo.com.tr", "ymail.com"),
        "imap_host": "imap.mail.yahoo.com",
        "imap_port": 993,
        "app_password_url": "https://login.yahoo.com/account/security",
        "oauth": False,
        "steps": (
            "Yahoo Hesap Güvenliği sayfasında 2 Adımlı Doğrulama AÇIK olmalı.",
            "Sayfanın altındaki 'Uygulama şifresi oluştur' bölümünden bir ad verip üretin.",
            "Ekrandaki kodu kopyalayın.",
        ),
        "notes": "Normal Yahoo şifreniz burada ÇALIŞMAZ.",
    },
    "yandex": {
        "label": "Yandex",
        "domains": ("yandex.com", "yandex.com.tr", "ya.ru", "yandex.ru"),
        "imap_host": "imap.yandex.com",
        "imap_port": 993,
        "app_password_url": "https://id.yandex.com/profile/app-passwords",
        "oauth": False,
        "steps": (
            "Yandex ID'de 2 Adımlı Doğrulama AÇIK olmalı.",
            "Açılan sayfada 'Posta' için uygulama şifresi oluşturun.",
            "Ekrandaki kodu kopyalayın.",
        ),
        "notes": "Normal Yandex şifreniz burada ÇALIŞMAZ.",
    },
    "icloud": {
        "label": "iCloud",
        "domains": ("icloud.com", "me.com", "mac.com"),
        "imap_host": "imap.mail.me.com",
        "imap_port": 993,
        "app_password_url": "https://appleid.apple.com/account/manage",
        "oauth": False,
        "steps": (
            "Apple Kimliğinizde 2 Adımlı Doğrulama AÇIK olmalı.",
            "Oturum açma ve Güvenlik > Uygulamaya özgü parola > yeni parola üretin.",
            "Ekrandaki kodu kopyalayın (örn. xxxx-xxxx-xxxx-xxxx).",
        ),
        "notes": "Normal Apple şifreniz burada ÇALIŞMAZ.",
    },
}


def detect_provider_by_email(email: str) -> str:
    """E-posta alan adından preset anahtarı. Bilinmiyorsa ''."""
    domain = (email or "").strip().lower().split("@")[-1] if "@" in (email or "") else ""
    for key, p in PRESETS.items():
        if domain in p["domains"]:
            return key
    return ""


# Numaralı sağlayıcı menüsü (sabit sıra — testler buna güvenir).
PROVIDER_MENU: tuple[str, ...] = ("gmail", "outlook", "yahoo", "yandex", "icloud", "custom")
CUSTOM_LABEL = "Diğer (sunucuyu elle gir)"


def menu_label(key: str) -> str:
    """Menüde görünen ad."""
    if key == "custom":
        return CUSTOM_LABEL
    return str(PRESETS[key]["label"])


def choose_provider(io: IO, suggested: str = "") -> str:
    """Numaralı sağlayıcı menüsü. Dönüş: preset anahtarı | 'custom' | '' (vazgeçme).

    Öneri varsa boş giriş onu onaylar. En fazla 3 geçersiz deneme.
    """
    suggested = (suggested or "").lower()
    if suggested not in PRESETS:
        suggested = ""
    for _ in range(MAX_ATTEMPTS):
        io.tell("Sağlayıcı seçin:")
        for i, k in enumerate(PROVIDER_MENU, 1):
            mark = "  <-- tahmin" if k == suggested else ""
            io.tell(f"  [{i}] {menu_label(k)}{mark}")
        raw = io.ask(f"Seçim [1-{len(PROVIDER_MENU)}" + (", Enter=tahmin" if suggested else "") + "]: ").strip().lower()
        if not raw and suggested:
            return suggested
        if raw.isdigit() and 1 <= int(raw) <= len(PROVIDER_MENU):
            return PROVIDER_MENU[int(raw) - 1]
        for k in PROVIDER_MENU:
            if raw == k or (k != "custom" and raw == menu_label(k).lower()):
                return k
        io.tell(f"HATA: 1-{len(PROVIDER_MENU)} arası bir numara girin.")
    io.tell("HATA: çok fazla geçersiz seçim.")
    return ""


def classify_error(exc: Exception) -> tuple[str, str]:
    """Bağlantı hatasını sınıflandır: (tür, Türkçe yol gösterici mesaj).

    tür: auth | network | tls | unknown
    """
    text = f"{type(exc).__name__}: {exc}"
    low = text.lower()
    auth_hints = ("authenticationfailed", "auth", "login", "credential",
                  "invalid credentials", "username and password not accepted")
    if any(h in low for h in auth_hints):
        return ("auth",
                "Kullanıcı adı/şifre reddedildi. Çoğu zaman sebep: normal şifre "
                "yerine UYGULAMA ŞİFRESİ kullanılmaması ya da kapalı 2 Adımlı Doğrulama. "
                "Kodu yeniden üretip boşluksuz yapıştırın; Outlook iş/okul hesabıysa "
                "OAuth yöntemini deneyin.")
    net_hints = ("timeout", "timed out", "connection", "unreachable", "network",
                 "name or service not known", "getaddrinfo", "refused", "reset by peer")
    if any(h in low for h in net_hints):
        return ("network",
                "Sunucuya ulaşılamadı. İnternet bağlantınızı ve IMAP sunucu/port "
                "bilgisini kontrol edin (güvenlik duvarı/VPN 993 portunu kesiyor olabilir).")
    if "ssl" in low or "certificate" in low or "tls" in low:
        return ("tls",
                "Güvenli bağlantı (TLS/sertifika) kurulamadı. Sistem saatinizin doğru "
                "olduğunu ve arada TLS bozan bir vekil (proxy) olmadığını kontrol edin.")
    return ("unknown", f"Beklenmeyen hata: {text}")


@dataclass
class IO:
    """Sihirbazın dış dünya bağımlılıkları (testte sahtesi verilir)."""
    ask: Callable[[str], str] = input
    tell: Callable[[str], None] = print
    ask_secret: Callable[[str], str] | None = None
    open_browser: Callable[[str], bool] | None = None

    def secret(self, prompt: str) -> str:
        if self.ask_secret is not None:
            return self.ask_secret(prompt)
        import getpass

        return getpass.getpass(prompt)

    def browse(self, url: str) -> bool:
        if self.open_browser is not None:
            return bool(self.open_browser(url))
        import webbrowser

        try:
            return bool(webbrowser.open(url))
        except Exception:
            return False


def test_connection(host: str, user: str, password: str, port: int = 993) -> list[str]:
    """Canlı IMAP testi. Dönüş: klasör listesi (başarısızsa exception fırlar)."""
    from app.services.imap_client import list_folders

    return asyncio.run(list_folders(host, user, password, port))


def run_setup(email: str | None = None,
              method: str | None = None,
              provider: str | None = None,
              no_browser: bool = False,
              io: IO | None = None,
              do_test: Callable[..., list[str]] = test_connection,
              do_save: Callable[[str, str, bool], None] | None = None,
              ) -> int:
    """Sihirbazın tamamı. Dönüş: 0 başarı, 2 başarısızlık.

    OAuth seçilirse ("OAUTH:<provider>") döndürür — çağıran (cli) login
    akışına devreder. do_save(key, value, secret) verilmezse kayıt yapılmaz
    (kuru test modu).
    """
    io = io or IO()
    t = io.tell

    addr = (email or io.ask("E-posta adresiniz: ")).strip()
    if "@" not in addr or "." not in addr.split("@")[-1]:
        t("HATA: geçerli bir e-posta adresi girin (örn. ad@gmail.com).")
        return 2

    m = (method or "").lower()
    if m and m not in ("app-password", "oauth"):
        t("HATA: yöntem 'app-password' ya da 'oauth' olmalı.")
        return 2
    if provider:
        key = provider.lower()
        if key not in PRESETS and key != "custom":
            t(f"HATA: bilinmeyen sağlayıcı '{provider}'. Geçerli: {', '.join([*PRESETS, 'custom'])}.")
            return 2
    else:
        suggested = detect_provider_by_email(addr)
        if m and suggested:
            key = suggested  # niyet belli + alan adı tanındı → sorusuz devam
        else:
            if suggested:
                t(f"Tahmin: {menu_label(suggested)} — Enter ile onayla ya da numaradan değiştir.")
            key = choose_provider(io, suggested)
            if not key:
                return 2
    if key not in PRESETS:
        if m == "oauth":
            t("HATA: bilinmeyen sağlayıcıda OAuth yok — sunucu bilginizle uygulama şifresi kullanın.")
            return 2
        t(f"'{addr.split('@')[-1]}' için hazır ayar yok — sunucuyu elle girelim.")
        custom_host = io.ask("IMAP sunucusu: ").strip()
        port_raw = io.ask("IMAP portu [993]: ").strip() or "993"
        if not custom_host or not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
            t("HATA: geçerli bir sunucu/port girin.")
            return 2
        host, port, label = custom_host, int(port_raw), "Özel"
        oauth_ok, url, steps, notes = False, "", (), ""
        m = "app-password"
    else:
        p = PRESETS[key]
        host, port, label = p["imap_host"], p["imap_port"], p["label"]
        oauth_ok, url, steps, notes = p["oauth"], p["app_password_url"], p["steps"], p["notes"]

    t(f"Sağlayıcı: {label} ({host}:{port})")

    if not m:
        if oauth_ok:
            t("Giriş yöntemi: [1] Uygulama şifresi (kolay, önerilir)")
            t("                [2] OAuth (tarayıcı onayı, client_id kaydı gerekir)")
            m = (io.ask("Seçim [1/2, varsayılan 1]: ").strip() or "1")
            m = {"1": "app-password", "2": "oauth"}.get(m, "")
            if not m:
                t("HATA: seçim 1 ya da 2 olmalı.")
                return 2
        else:
            m = "app-password"
    if m == "oauth":
        return "OAUTH:" + key  # type: ignore[return-value]

    # --- uygulama şifresi yolu ---
    if do_save:
        do_save("IMAP_HOST", host, False)
        do_save("IMAP_USER", addr, False)
    if notes:
        t(f"Not: {notes}")
    if not no_browser and url:
        if io.browse(url):
            t("Tarayıcıda uygulama-şifresi sayfası açıldı.")
        else:
            t(f"Tarayıcı açılamadı — şu adrese kendiniz gidin:\n{url}")
    elif url:
        t(f"Şu adrese gidin:\n{url}")
    for i, step in enumerate(steps, 1):
        t(f"  Adım {i}: {step}")

    env_pw = os.environ.get("ELFSEC_SETUP_PASSWORD", "")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        secret = env_pw if env_pw else io.secret(f"Uygulama şifresi (deneme {attempt}/{MAX_ATTEMPTS}): ").strip().replace(" ", "")
        if not secret:
            t("HATA: boş şifre girildi.")
            if attempt >= MAX_ATTEMPTS:
                return 2
            continue
        if do_save:
            do_save("IMAP_PASSWORD", secret, True)
        t("Bağlantı test ediliyor...")
        try:
            folders = do_test(host, addr, secret, port)
            t(f"OK: giriş başarılı — {len(folders)} klasör bulundu "
              f"({', '.join(folders[:5])}).")
            t("Sonraki adım: `elfsec triage --limit 20` ya da `elfsec guard --once`")
            return 0
        except Exception as e:
            kind, guidance = classify_error(e)
            t(f"BAŞARISIZ ({kind}): {e}")
            t(guidance)
            if attempt >= MAX_ATTEMPTS:
                t(f"HATA: {MAX_ATTEMPTS} denemede bağlanılamadı. `elfsec config setup` "
                  f"ile yeniden deneyin ya da OAuth yöntemini seçin.")
                return 2
    return 2


SUPPORTED = tuple(sorted(PRESETS)) + ("custom",)
