"""Tehdit analizi endpoint'i.

POST /api/analyze -> ham gövdeyi sanitize eder, sonra yerel motorla analiz eder.
"""

from fastapi import APIRouter, Depends, Request

from app.api.auth import require_token
from app.limiter import limiter
from app.schemas import AnalyzeRequest, ThreatAnalysisResponse
from app.services.ai_analyzer import analyze_threat
from app.services.sanitizer import sanitize_email

router = APIRouter(prefix="/api/analyze", tags=["analyze"], dependencies=[Depends(require_token)])


@router.post("", response_model=ThreatAnalysisResponse)
@limiter.limit("10/minute")
async def analyze_email(request: Request, payload: AnalyzeRequest) -> ThreatAnalysisResponse:
    clean = sanitize_email(payload.body)
    result = await analyze_threat(
        subject=payload.subject,
        plain_text=clean["plain_text"],
        urls=clean["urls"],
        sender=payload.sender,
    )
    return ThreatAnalysisResponse(
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        summary=result["summary"],
        reasons=result["reasons"],
        suspicious_urls=result["suspicious_urls"],
        prompt_injection_detected=result["prompt_injection_detected"],
        phishing_detected=result["phishing_detected"],
        recommended_action=result["recommended_action"],
        engine=result["engine"],
        analyzed_at=result["analyzed_at"],
        tracking_pixels_blocked=clean["tracking_pixels_blocked"],
    )
