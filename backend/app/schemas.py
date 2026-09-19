"""Next.js <-> FastAPI arası katı veri doğrulama (Pydantic v2)."""

from datetime import datetime

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "elfsec-api"
    env: str = "dev"
    imap_configured: bool = False
    engine: str = "elfsec-local/1.0"


class EmailSummary(BaseModel):
    uid: str = Field(description="IMAP UID")
    subject: str = ""
    from_addr: str = Field(default="", alias="from")
    to_addr: str = ""
    date: str = ""
    snippet: str = Field(default="", description="Düz metnin ilk ~300 karakteri")

    model_config = {"populate_by_name": True}


class EmailDetail(EmailSummary):
    safe_html: str = Field(default="", description="Bleach ile temizlenmiş HTML")
    plain_text: str = Field(default="", description="bs4+lxml ile çıkarılmış saf metin")
    urls: list[str] = Field(default_factory=list)
    tracking_pixels_blocked: int = 0


class EmailFetchRequest(BaseModel):
    folder: str = Field(default="INBOX", max_length=128)
    limit: int = Field(default=20, ge=1, le=100)
    unseen_only: bool = False


class EmailFetchResponse(BaseModel):
    folder: str
    count: int
    emails: list[EmailDetail]


class AnalyzeRequest(BaseModel):
    subject: str = Field(default="", max_length=1000)
    body: str = Field(default="", max_length=30000, description="Ham e-posta gövdesi (HTML veya düz metin)")
    sender: str = Field(default="", max_length=500)


class ThreatAnalysisResponse(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: str = Field(description="LOW | MEDIUM | HIGH | CRITICAL")
    summary: str = ""
    reasons: list[str] = Field(default_factory=list)
    suspicious_urls: list[str] = Field(default_factory=list)
    prompt_injection_detected: bool = False
    phishing_detected: bool = False
    recommended_action: str = ""
    engine: str = Field(default="", description="Analiz motoru (elfsec-local/1.0)")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    tracking_pixels_blocked: int = 0
