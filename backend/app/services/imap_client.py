"""IMAP e-posta çekme katmanı (imap-tools).

imap-tools senkron çalışır -> FastAPI event loop'u kilitlememek için
asyncio.to_thread ile arka planda koşturulur (Uvicorn + async uyumlu).
"""

import asyncio
from dataclasses import dataclass

from imap_tools import AND, MailBox


@dataclass
class FetchParams:
    host: str
    user: str
    password: str
    port: int = 993
    folder: str = "INBOX"
    limit: int = 20
    unseen_only: bool = False


def _fetch_sync(p: FetchParams) -> list[dict]:
    criteria = AND(seen=False) if p.unseen_only else AND(all=True)
    out: list[dict] = []
    with MailBox(p.host, port=p.port).login(p.user, p.password, initial_folder=p.folder) as mb:
        # en yeniler önce gelsin diye tersten al
        msgs = list(mb.fetch(criteria, limit=p.limit, reverse=True, headers_only=False))
        for m in msgs:
            # gövde: html varsa onu, yoksa text'i ver (sanitizer nasılsa temizleyecek)
            body = m.html or m.text or ""
            out.append({
                "uid": str(m.uid),
                "subject": m.subject or "(konu yok)",
                "from": m.from_ or "",
                "to": ", ".join(m.to) if isinstance(m.to, (list, tuple)) else str(m.to or ""),
                "date": m.date.strftime("%Y-%m-%d %H:%M") if m.date else "",
                "body": body,
            })
    return out


def _folders_sync(host: str, user: str, password: str, port: int) -> list[str]:
    with MailBox(host, port=port).login(user, password) as mb:
        return [f.name for f in mb.folder.list()]


async def fetch_emails(p: FetchParams) -> list[dict]:
    return await asyncio.to_thread(_fetch_sync, p)


async def list_folders(host: str, user: str, password: str, port: int = 993) -> list[str]:
    return await asyncio.to_thread(_folders_sync, host, user, password, port)
