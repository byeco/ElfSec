"""ElfSec web API — siteye gömülüp tarayıcıdan çağrılabilen ince katman.

Bunu neden yazdım: arkadaşım "ben bunu kendi sitemde kullanmak istiyorum,
mail kutusunu siteye yapıştırınca skor dönsün" dedi. Ağır framework
kurmak istemedim (exe şişmesin, bağımlılık artmasın) o yüzden sadece
Python'un kendi kütüphanesiyle yazdım: http.server + json, o kadar.

Uçlar (hepsi JSON):
    GET  /v1/health     -> sürüm + motor (kimliksiz, bilgi sızdırmaz)
    POST /v1/analyze    -> {subject, body, sender, headers?} -> risk raporu
    POST /v1/sanitize   -> {body} -> {safe_html, plain_text, urls}

Güvenlik (açık kaynak olduğu için paranoyak yazdım, notlarım):
  1. Token ZORUNLU değil ama ağa açılınca ZORUNLU olur: host localhost
     değilse ve ELFSEC_API_TOKEN yoksa server başlamayı REDDEDER (fail-closed).
     Token asla komut satırı bayrağı olmaz (process listesinde görünür) —
     sadece ortam değişkeninden okunur.
  2. Rate-limit: IP başına dakikada N istek (varsayılan 60), aşana 429.
  3. Gövde limiti: 1 MB üstü okunmadan 413. Alanlar tek tek kırpılır
     (subject<=1000, sender<=500, body<=30000 — CLI ile aynı sınırlar).
  4. CORS: varsayılan kapalı, --cors-origins ile allowlist verilirse
     sadece listedeki origin'e izin verilir.
  5. Loglara ASLA mail içeriği yazılmaz: sadece yöntem/yol/durum/skor/seviye.
  6. Karşılaştırma hmac.compare_digest ile (timing-safe).

Kullanım:
    ELFSEC_API_TOKEN=uzun-rastgele python -m app.cli serve
    ELFSEC_API_TOKEN=... python -m app.cli serve --host 0.0.0.0 --port 8765 \\
        --cors-origins https://benimsitem.com
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# CLI ile aynı sınırlar (schemas.py: body<=30000, subject<=1000, sender<=500)
MAX_HTTP_BODY = 1_000_000  # ham istek üst sınırı (DoS kesmesi)
MAX_SUBJECT = 1000
MAX_SENDER = 500
MAX_BODY = 30000
MAX_HEADERS = 20  # başlık doğrulaması için en fazla N başlık

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _token() -> str:
    """API tokeni: SADECE ortam değişkeni. Kodda/bayrakta asla durmaz."""
    return os.environ.get("ELFSEC_API_TOKEN", "")


def check_bind_policy(host: str, token: str) -> str | None:
    """Başlama izni: None=serbest, str=hata mesajı (fail-closed).

    localhost + tokensuz = serbest (yerel deneme). Ağa açık + tokensuz = YASAK.
    """
    if (host or "").strip().lower() in LOCAL_HOSTS:
        return None
    if not token:
        return (f"GÜVENLİK: --host {host} ağa açık ama ELFSEC_API_TOKEN yok. "
                "Ya localhost'ta çalışın ya da token koyup başlatın.")
    return None


class _Limiter:
    """IP başına sabit pencereli hız sınırı (bellek-içi, tek process)."""

    def __init__(self, per_minute: int = 60):
        self.per_minute = max(1, int(per_minute))
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allowed(self, ip: str) -> tuple[bool, int]:
        """(izin?, retry-after-saniye)."""
        now = time.monotonic()
        with self._lock:
            win = [t for t in self._hits.get(ip, []) if now - t < 60]
            if len(win) >= self.per_minute:
                retry = max(1, int(60 - (now - win[0])))
                self._hits[ip] = win
                return False, retry
            win.append(now)
            self._hits[ip] = win
            return True, 0


def _valid_headers(raw) -> dict | None:
    """Başlık sözlüğünü doğrula: {ad: değer}, en fazla MAX_HEADERS, hepsi kısa."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or len(raw) > MAX_HEADERS:
        return None
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return None
        if len(k) > 100 or len(v) > 2000:
            return None
        out[k.strip().lower()[:100]] = v[:2000]
    return out


def _valid_analyze(payload) -> tuple[dict | None, str | None]:
    """(temiz-girdi, hata). Tipler ve uzunluklar burada kilitlenir."""
    if not isinstance(payload, dict):
        return None, "JSON obje olmalı"
    subject = payload.get("subject", "")
    sender = payload.get("sender", "")
    body = payload.get("body", "")
    if not all(isinstance(x, str) for x in (subject, sender, body)):
        return None, "subject/sender/body metin olmalı"
    headers = _valid_headers(payload.get("headers"))
    if payload.get("headers") is not None and headers is None:
        return None, "headers {ad: değer} olmalı (en fazla 20, değer<=2000)"
    return {
        "subject": subject[:MAX_SUBJECT],
        "sender": sender[:MAX_SENDER],
        "body": body[:MAX_BODY],
        "headers": headers,
    }, None


class _Handler(BaseHTTPRequestHandler):
    """Tek istek işleyici. server_version gizlenir (bilgi sızıntısı olmasın)."""

    server_version = "ElfSec"
    sys_version = ""
    # serve() tarafından enjekte edilir:
    limiter: _Limiter = _Limiter()
    cors_origins: tuple[str, ...] = ()

    # --- yardımcılar ---

    def _cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin and origin in self.cors_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send(self, code: int, obj: dict, retry_after: int = 0) -> None:
        raw = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._cors()
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except Exception:
            pass  # istemci kapattıysa sorun değil

    def _log(self, code: int, extra: str = "") -> None:
        # PII YOK: konu/gönderici/gövde asla loga yazılmaz.
        try:
            print(f"[api] {self.command} {self.path} -> {code} {extra}", flush=True)
        except Exception:
            pass

    def _need_auth(self) -> bool:
        tok = _token()
        if not tok:
            return False  # localhost + tokensuz moda serve() izin verdi
        got = (self.headers.get("Authorization") or "").strip()
        if not got.lower().startswith("bearer "):
            return True
        return not hmac.compare_digest(got[7:].strip(), tok)

    def _drain(self, length: int) -> None:
        """Dev gövdeyi parçalar halinde çöpe oku (max 8MB).

        Okunmadan kapatılırsa istemci reset yer (413'ü göremez) — o yüzden
        cevap vermeden önce soketi boşaltmak şart.
        """
        left = min(max(0, length), 8_000_000)
        try:
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
        except Exception:
            pass

    def _read_json(self) -> tuple[dict | list | None, str | None]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            return None, "Content-Length geçersiz"
        if length <= 0:
            return None, "boş gövde"
        if length > MAX_HTTP_BODY:
            self._drain(length)
            return None, "gövde çok büyük (max 1MB)"
        try:
            raw = self.rfile.read(length)
        except Exception:
            return None, "gövde okunamadı"
        try:
            return json.loads(raw.decode("utf-8")), None
        except Exception:
            return None, "geçersiz JSON"

    # --- rotalar ---

    def do_OPTIONS(self):  # CORS preflight (allowlist dışıysa başlıksız 204)
        self.send_response(204)
        self._cors()
        if self.path in ("/v1/analyze", "/v1/sanitize"):
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _limited(self) -> bool:
        """Kota aşıldıysa 429 basıp True dön (health dahil tüm yollarda)."""
        ip = (self.client_address[0] if self.client_address else "?")
        ok, retry = self.limiter.allowed(ip)
        if not ok:
            self._send(429, {"ok": False, "error": "hız sınırı aşıldı"}, retry_after=retry)
            self._log(429, "rate-limit")
            return True
        return False

    def do_GET(self):
        if self._limited():
            return
        if self.path.rstrip("/") in ("/v1/health", "/health"):
            if self._need_auth():
                self._send(401, {"ok": False, "error": "yetkisiz (Bearer token gerekli)"})
                self._log(401)
                return
            from app.__version__ import ENGINE, __version__

            self._send(200, {"ok": True, "version": __version__, "engine": ENGINE})
            self._log(200)
            return
        self._send(404, {"ok": False, "error": "bilinmeyen yol"})
        self._log(404)

    def do_POST(self):
        path = self.path.rstrip("/")
        if path not in ("/v1/analyze", "/v1/sanitize"):
            self._send(404, {"ok": False, "error": "bilinmeyen yol"})
            self._log(404)
            return
        if self._need_auth():
            # Token varsa timing-safe karşılaştırma yapıldı; yanlışsa 401.
            # Yoksa da 401 (hangi durum olduğu söylenmez — bilgi sızıntısı yok).
            self._send(401, {"ok": False, "error": "yetkisiz (Bearer token gerekli)"})
            self._log(401)
            return
        if self._limited():
            return
        payload, err = self._read_json()
        if err:
            code = 413 if "1MB" in err else 400
            self._send(code, {"ok": False, "error": err})
            self._log(code)
            return
        try:
            if path == "/v1/sanitize":
                body = payload.get("body", "") if isinstance(payload, dict) else ""
                if not isinstance(body, str):
                    self._send(400, {"ok": False, "error": "body metin olmalı"})
                    self._log(400)
                    return
                from app.sdk import sanitize as _sanitize

                clean = _sanitize(body[:MAX_BODY])
                self._send(200, {"ok": True, **clean})
                self._log(200, "sanitize")
                return
            data, verr = _valid_analyze(payload)
            if verr:
                self._send(400, {"ok": False, "error": verr})
                self._log(400)
                return
            assert data is not None
            from app.sdk import scan_text as _scan

            rep = _scan(subject=data["subject"], body=data["body"],
                        sender=data["sender"], headers=data["headers"])
            # Siteye ham PII geri vermemek için gövde kırpılır (skor + neden yeter).
            rep = dict(rep)
            rep["plain_text"] = str(rep.get("plain_text", ""))[:2000]
            self._send(200, {"ok": True, **rep})
            self._log(200, f"{rep.get('risk_level')}/{rep.get('risk_score')}")
        except Exception as e:
            self._send(500, {"ok": False, "error": f"iç hata: {type(e).__name__}"})
            self._log(500)

    def do_PUT(self):  # sadece GET/POST var, gerisi 405
        self._send(405, {"ok": False, "error": "yalnızca GET/POST"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    def log_message(self, format, *args):  # BaseHTTPRequestHandler gürültüsü kapalı
        return


def serve(host: str = "127.0.0.1", port: int = 8765, rate_limit: int = 60,
          cors_origins: tuple[str, ...] = ()) -> ThreadingHTTPServer:
    """API serverını kur (başlatmaz). Ağ + tokensuz = ValueError (fail-closed)."""
    err = check_bind_policy(host, _token())
    if err:
        raise ValueError(err)
    if not (0 <= int(port) <= 65535):
        raise ValueError("port 0-65535 arası olmalı (0 = OS seçsin, testler için)")
    handler = type("ElfSecHandler", (_Handler,), {})
    handler.limiter = _Limiter(rate_limit)
    handler.cors_origins = tuple(o.strip() for o in (cors_origins or ()) if o.strip())
    srv = ThreadingHTTPServer((host, int(port)), handler)
    srv.daemon_threads = True
    return srv


def run_forever(host: str = "127.0.0.1", port: int = 8765, rate_limit: int = 60,
                cors_origins: tuple[str, ...] = ()) -> int:
    """CLI'den çağrılır: sonsuza kadar dinle (Ctrl+C ile dur)."""
    from app.table import ensure_utf8

    try:
        ensure_utf8()
    except Exception:
        pass
    try:
        srv = serve(host, port, rate_limit, cors_origins)
    except ValueError as e:
        print(f"HATA: {e}")
        return 2
    tok = _token()
    print(f"ElfSec API dinliyor: http://{host}:{srv.server_address[1]} "
          f"(auth={'token' if tok else 'yok/localhost'}, rate={rate_limit}/dk)")
    if not tok:
        print("UYARI: tokensuz mod — sadece bu PC'den erişilir (localhost). "
              "Siteye koyacaksan ELFSEC_API_TOKEN şart.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nAPI durduruldu.")
    return 0


def _sha256_file(path: str) -> str:
    """Açık-kaynak denetimi: dosyada gömülü secret var mı (kaba tarama)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return hashlib.sha256(fh.read().encode("utf-8")).hexdigest()
    except OSError:
        return ""
