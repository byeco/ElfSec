"""API kimlik doğrulaması — Bearer token.

İlke: API_TOKEN boşsa API korumasızdır (yerel geliştirme). Doluysa /api/*
uçları Authorization: Bearer <token> ister; /health ve / açık kalır.
Karşılaştırma hmac.compare_digest ile (zamanlama saldırısına dayanıklı).
"""

import hmac

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.settings_store import current_settings

_bearer = HTTPBearer(auto_error=False)


def require_token(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> None:
    token = current_settings().api_token
    if not token:
        return  # korumasız mod — main.py açılışta uyarır
    given = creds.credentials if creds else ""
    if not hmac.compare_digest(given, token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Geçersiz veya eksik API token. Authorization: Bearer <API_TOKEN>")
