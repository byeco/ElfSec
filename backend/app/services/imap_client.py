"""IMAP e-posta çekme katmanı (imap-tools) — TOOL-only.

imap-tools senkron çalışır -> asyncio.to_thread ile arka planda koşturulur.
"""

import asyncio
from dataclasses import dataclass

from imap_tools import AND, MailBox


@dataclass
class FetchParams:
    host: str
    user: str
    password: str = ""
    port: int = 993
    folder: str = "INBOX"
    limit: int = 20
    unseen_only: bool = False
    # OAuth2 (XOAUTH2): access_token doluysa şifre yerine kullanılır.
    oauth_token: str = ""


def _open_box(p: FetchParams) -> MailBox:
    """Şifre veya OAuth ile giriş yapmış kutu aç (context-manager)."""
    box = MailBox(p.host, port=p.port)
    if p.oauth_token:
        return box.xoauth2(p.user, p.oauth_token, initial_folder=p.folder)
    if not p.password:
        raise ValueError("Ne şifre ne OAuth token var — `config login` ya da IMAP_PASSWORD gerekli.")
    return box.login(p.user, p.password, initial_folder=p.folder)


def extract_headers(m) -> dict:
    """v0.4.0: doğrulama için kritik başlıkları çıkar (küçük + sınırlı).

    Dönüş: {reply_to, return_path, auth_results, message_id}.
    Eksik başlık "" olur — ceza almaz, sadece çelişki puanlanır.
    """
    hdrs: dict = {}
    try:
        raw = m.headers or {}
        hdrs = {str(k).lower(): str(v) for k, v in dict(raw).items()}
    except Exception:
        hdrs = {}
    try:
        rt = m.reply_to or ""
    except Exception:
        rt = ""
    auth = hdrs.get("authentication-results", "")
    return {
        "reply_to": (rt or hdrs.get("reply-to", ""))[:500],
        "return_path": hdrs.get("return-path", "")[:500],
        "auth_results": auth[:2000],
        "message_id": hdrs.get("message-id", "")[:500],
    }


def _fetch_sync(p: FetchParams) -> list[dict]:
    criteria = AND(seen=False) if p.unseen_only else AND(all=True)
    out: list[dict] = []
    with _open_box(p) as mb:
        # en yeniler önce gelsin diye tersten al
        msgs = list(mb.fetch(criteria, limit=p.limit, reverse=True, headers_only=False))
        for m in msgs:
            # gövde: html varsa onu, yoksa text'i ver (sanitizer nasılsa temizleyecek)
            body = m.html or m.text or ""
            # v0.5.0: ek ÜSTVERİSİ (içerik indirilmez — gizlilik + çevrimdışı)
            atts: list[dict] = []
            try:
                for a in (m.attachments or []):
                    atts.append({
                        "filename": str(getattr(a, "filename", "") or "")[:200],
                        "size": int(getattr(a, "size", 0) or 0),
                        "content_type": str(getattr(a, "content_type", "") or "")[:100],
                    })
            except Exception:
                atts = []
            out.append({
                "uid": str(m.uid),
                "subject": m.subject or "(konu yok)",
                "from": m.from_ or "",
                "to": ", ".join(m.to) if isinstance(m.to, (list, tuple)) else str(m.to or ""),
                "date": m.date.strftime("%Y-%m-%d %H:%M") if m.date else "",
                "body": body,
                "headers": extract_headers(m),
                "attachments": atts,
            })
    return out


def _folders_sync(host: str, user: str, password: str, port: int, oauth_token: str = "") -> list[str]:
    p = FetchParams(host=host, user=user, password=password, port=port, oauth_token=oauth_token)
    with _open_box(p) as mb:
        return [f.name for f in mb.folder.list()]


async def fetch_emails(p: FetchParams) -> list[dict]:
    return await asyncio.to_thread(_fetch_sync, p)


async def list_folders(host: str, user: str, password: str, port: int = 993,
                       oauth_token: str = "") -> list[str]:
    return await asyncio.to_thread(_folders_sync, host, user, password, port, oauth_token)


def _quarantine_sync(host: str, user: str, password: str, port: int, folder: str,
                     uid: str, action: str, quarantine_folder: str = "Junk",
                     oauth_token: str = "") -> str:
    """Tehlikeyi durdur/yok et: taşı (quarantine) veya sil (delete).

    - quarantine: hedef klasöre kopyala + orijinali sil (geri alınabilir).
    - delete: kalıcı sil (sadece bayrakla, onaylı).
    Dönüş: yapılan işlem açıklaması.
    """

    if action not in ("quarantine", "delete"):
        raise ValueError(f"Bilinmeyen aksiyon: {action}")
    with _open_box(FetchParams(host=host, user=user, password=password, port=port,
                               folder=folder, oauth_token=oauth_token)) as mb:
        if action == "delete":
            mb.delete([uid])
            return f"deleted uid={uid} from {folder}"
        # quarantine: kopyala + sil
        try:
            mb.copy([uid], quarantine_folder)
        except Exception:
            # Hedef klasör yoksa taşıma yerine seen işaretle (kayıp önlenir)
            try:
                mb.flag([uid], ["\\Seen"], True)
            except Exception:
                pass
            return f"flagged-seen uid={uid} (quarantine klasörü yok: {quarantine_folder})"
        mb.delete([uid])
        return f"quarantined uid={uid} {folder}->{quarantine_folder}"


async def quarantine_email(host: str, user: str, password: str, port: int, folder: str,
                           uid: str, action: str, quarantine_folder: str = "Junk",
                           oauth_token: str = "") -> str:
    return await asyncio.to_thread(
        _quarantine_sync, host, user, password, port, folder, uid, action,
        quarantine_folder, oauth_token
    )
