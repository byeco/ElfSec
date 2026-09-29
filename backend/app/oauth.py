"""Şifresiz giriş (OAuth2) — IMAP şifresiyle uğraşmak istemeyenler için yazdım.

Önce "Windows'taki hazır mail hesabını sessizce kullansam" diye
uğraştım ama olmuyormuş: kimlik bilgileri Mail uygulamasına DPAPI ile
bağlıymış, admin bile çıkaramıyor (tasarım gereğiymiş, öğrenmiş oldum).
O yüzden doğru akış şu: kullanıcı tarayıcıda BİR KEZ onay veriyor,
refresh-token kasada (ENC) duruyor, her turda kısa ömürlü access-token alınıyor.

Destek: outlook (Hotmail/Outlook/Office365) + gmail. Herkes KENDİ uygulama
kaydını açar (paylaşımlı client-id yok — güvenlik gereği):
  Outlook: Azure Portal → App registrations → public client + IMAP scope
  Gmail:   Google Cloud → OAuth client (Desktop) + gmail scope

Akış: `elfsec config login --provider outlook|gmail`
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

PROVIDERS: dict[str, dict] = {
    "outlook": {
        "auth_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scope": "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access openid profile email",
        "imap_host": "outlook.office365.com",
        "label": "Outlook / Hotmail / Office365",
    },
    "gmail": {
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "https://mail.google.com/",
        "imap_host": "imap.gmail.com",
        "label": "Gmail",
    },
}

CALLBACK_PATH = "/callback"


def detect_provider(host: str) -> str:
    """IMAP hostundan sağlayıcı tahmin et (boşsa bilinmiyor)."""
    h = (host or "").lower()
    if any(k in h for k in ("outlook", "office365", "hotmail", "live.com", "msn.com")):
        return "outlook"
    if "gmail" in h or "googlemail" in h:
        return "gmail"
    return ""


def build_auth_url(provider: str, client_id: str, port: int, state: str) -> str:
    p = PROVIDERS[provider]
    q = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": f"http://127.0.0.1:{port}{CALLBACK_PATH}",
        "scope": p["scope"],
        "state": state,
        "prompt": "select_account",
    }
    if provider == "gmail":
        q["access_type"] = "offline"  # refresh-token şart
    return p["auth_url"] + "?" + urllib.parse.urlencode(q)


def _post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_for_code(port: int, expected_state: str, timeout: int = 180) -> str:
    """Loopback'te tek kullanımlık kod yakala. Dönüş: authorize code."""
    result: dict = {}
    done = threading.Event()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return
            qs = urllib.parse.parse_qs(parsed.query)
            result["code"] = (qs.get("code") or [""])[0]
            result["state"] = (qs.get("state") or [""])[0]
            result["error"] = (qs.get("error") or [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            ok = result["code"] and result["state"] == expected_state and not result["error"]
            msg = "ElfSec: giriş tamam, bu sekmeyi kapatabilirsiniz." if ok else "ElfSec: giriş başarısız, tekrar deneyin."
            self.wfile.write(f"<html><body><h3>{msg}</h3></body></html>".encode("utf-8"))
            done.set()

        def log_message(self, *args, **kwargs):
            pass

    srv = HTTPServer(("127.0.0.1", port), H)
    srv.timeout = 1
    import time
    start = time.time()
    while not done.is_set():
        srv.handle_request()
        if time.time() - start > timeout:
            break
    srv.server_close()
    if result.get("error"):
        raise OSError(f"Sağlayıcı hatası: {result['error']}")
    if not result.get("code") or result.get("state") != expected_state:
        raise OSError("Onay kodu alınamadı (zaman aşımı/iptal).")
    return result["code"]


def exchange_code(provider: str, client_id: str, port: int, code: str) -> dict:
    p = PROVIDERS[provider]
    data = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"http://127.0.0.1:{port}{CALLBACK_PATH}",
    }
    return _post_form(p["token_url"], data)


def refresh_access_token(provider: str, client_id: str, refresh_token: str) -> dict:
    p = PROVIDERS[provider]
    return _post_form(p["token_url"], {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    })


def _client_id_for(settings, provider: str) -> str:
    return settings.ms_client_id if provider == "outlook" else settings.google_client_id


def _refresh_for(settings, provider: str) -> str:
    return settings.oauth_refresh_outlook if provider == "outlook" else settings.oauth_refresh_gmail


def active_provider(settings) -> str:
    """Ayarlı sağlayıcı: açık seçim yoksa hosttan tahmin et."""
    p = (getattr(settings, "oauth_provider", "") or "").lower()
    if p in PROVIDERS:
        return p
    return detect_provider(getattr(settings, "imap_host", ""))


def resolve_access_token(settings) -> tuple[str, str]:
    """(provider, access_token). OAuth ayarlı değilse ("", "") döner.

    Refresh başarısızsa OSError (kullanıcı `config login` ile yenilemeli).
    """
    provider = active_provider(settings)
    if not provider:
        return "", ""
    client_id = _client_id_for(settings, provider)
    refresh = _refresh_for(settings, provider)
    if not client_id or not refresh:
        return "", ""
    try:
        tokens = refresh_access_token(provider, client_id, refresh)
    except Exception as e:
        raise OSError(f"OAuth yenileme başarısız ({provider}): {e}. "
                      f"`elfsec config login --provider {provider}` ile yeniden giriş yapın.")
    access = tokens.get("access_token", "")
    if not access:
        raise OSError(f"OAuth access-token alınamadı ({provider}). Yeniden giriş yapın.")
    return provider, access


def login_flow(provider: str, client_id: str, open_browser: bool = True) -> dict:
    """Tarayıcı onayı + kod takası. Dönüş: token yanıtı (refresh_token içerir)."""
    import webbrowser

    if provider not in PROVIDERS:
        raise ValueError(f"Bilinmeyen sağlayıcı: {provider} (outlook|gmail).")
    if not client_id.strip():
        raise ValueError("client_id boş. Önce kendi uygulama kaydınızı açın (README).")
    srv = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = srv.server_address[1]
    srv.server_close()
    state = secrets.token_urlsafe(16)
    url = build_auth_url(provider, client_id, port, state)
    print(f"Tarayıcıda {PROVIDERS[provider]['label']} girişi açılıyor...")
    print(f"Açılmazsa şu adresi kopyalayın:\n{url}\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    code = wait_for_code(port, state)
    tokens = exchange_code(provider, client_id, port, code)
    if "refresh_token" not in tokens:
        raise OSError("refresh_token alınamadı (outlook: offline_access, gmail: access_type=offline gerekli).")
    return tokens
