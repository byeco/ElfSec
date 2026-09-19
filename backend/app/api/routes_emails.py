"""E-posta listeleme/çekme endpoint'leri.

GET /api/emails         -> IMAP'tan çek + sanitize et (query: folder, limit, unseen_only)
GET /api/emails/folders -> klasör listesi
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.auth import require_token
from app.limiter import limiter
from app.schemas import EmailDetail, EmailFetchResponse
from app.services.imap_client import FetchParams, fetch_emails, list_folders
from app.services.sanitizer import sanitize_email
from app.settings_store import current_settings as get_settings

router = APIRouter(prefix="/api/emails", tags=["emails"], dependencies=[Depends(require_token)])


def _imap_or_400():
    s = get_settings()
    if not s.imap_configured:
        raise HTTPException(status_code=400, detail="IMAP yapılandırılmamış. backend/.env dosyasına IMAP_USER/IMAP_PASSWORD ekleyin.")
    return s


@router.get("", response_model=EmailFetchResponse)
@limiter.limit("20/minute")
async def get_emails(
    request: Request,
    folder: str = Query(default="INBOX", max_length=128),
    limit: int = Query(default=20, ge=1, le=100),
    unseen_only: bool = False,
):
    s = _imap_or_400()
    params = FetchParams(host=s.imap_host, user=s.imap_user, password=s.imap_password,
                         port=s.imap_port, folder=folder, limit=limit, unseen_only=unseen_only)
    try:
        raw = await fetch_emails(params)
    except Exception as e:
        print(f"[emails] IMAP hatası: {type(e).__name__}: {e}")  # detay sunucuda kalır
        raise HTTPException(status_code=502, detail="IMAP bağlantısı başarısız. Sunucu loguna bakın.")
    emails: list[EmailDetail] = []
    for m in raw:
        clean = sanitize_email(m["body"])
        emails.append(EmailDetail(
            uid=m["uid"], subject=m["subject"], **{"from": m["from"]},
            to_addr=m["to"], date=m["date"],
            snippet=clean["plain_text"][:300],
            safe_html=clean["safe_html"], plain_text=clean["plain_text"],
            urls=clean["urls"], tracking_pixels_blocked=clean["tracking_pixels_blocked"],
        ))
    return EmailFetchResponse(folder=folder, count=len(emails), emails=emails)


@router.get("/folders", response_model=list[str])
@limiter.limit("20/minute")
async def get_folders(request: Request):
    s = _imap_or_400()
    try:
        return await list_folders(s.imap_host, s.imap_user, s.imap_password, s.imap_port)
    except Exception as e:
        print(f"[emails/folders] IMAP hatası: {type(e).__name__}: {e}")
        raise HTTPException(status_code=502, detail="Klasör listesi alınamadı. Sunucu loguna bakın.")
