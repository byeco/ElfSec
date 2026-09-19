"""ElfSec API çekirdeği — FastAPI + Uvicorn + slowapi.

- Frontend (Next.js) buraya konuşur.
- IMAP çekme işlemleri async/thread ile yapılır, sunucu kilitlenmez.
- slowapi: DDoS/Brute Force'a karşı rate limiting kalkanı.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes_analyze import router as analyze_router
from app.api.routes_emails import router as emails_router
from app.api.routes_health import router as health_router
from app.limiter import limiter
from app.settings_store import build_settings

settings, _config_file, _warnings = build_settings()
for _w in _warnings:
    print(f"UYARI: {_w}")
if not settings.api_token:
    print("UYARI: API_TOKEN boş — /api/* korumasız. LAN'a açıyorsanız "
          "`elfsec config set API_TOKEN --secret` ile token koyun.")

app = FastAPI(title="ElfSec API", version="0.1.0",
              description="E-posta güvenlik analiz API'si: IMAP çekme, Bleach sanitization, yerel tehdit analizi (anahtarsız).")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"detail": "Çok fazla istek. Lütfen biraz bekleyip tekrar deneyin."})


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(emails_router)
app.include_router(analyze_router)


@app.get("/", include_in_schema=False)
async def root():
    return {"service": "elfsec-api", "docs": "/docs", "health": "/health"}


def run() -> None:
    import uvicorn
    uvicorn.run("app.main:app", host=settings.api_host, port=settings.api_port, reload=(settings.env == "dev"))


if __name__ == "__main__":
    run()
