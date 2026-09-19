"""Health endpoint — rate limit'e takılmaz."""

from fastapi import APIRouter

from app.schemas import HealthResponse
from app.settings_store import current_settings as get_settings

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    from app.services.ai_analyzer import ENGINE

    s = get_settings()
    return HealthResponse(status="ok", env=s.env,
                          imap_configured=s.imap_configured, engine=ENGINE)
