"""Ayarların şeması — hangi ayar ne tipte, varsayılanı ne, burada belli.

Öğrendiğim önemli ders: şifre gibi kritik veriler koda GÖMÜLMEZ,
.env dosyasından okunur. .env de GitHub'a yüklenmez (.gitignore'da).
İlk commit'imde yanlışlıkla yükleyecektim, son anda fark ettim.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # IMAP
    imap_host: str = Field(default="imap.gmail.com")
    imap_user: str = Field(default="")
    imap_password: str = Field(default="")
    imap_folder: str = Field(default="INBOX")
    imap_port: int = Field(default=993)

    # TOOL-only
    env: str = Field(default="dev")

    # OAuth2 (Windows hazır hesabı sessizce devralma YOKTUR — bir kez tarayıcı onayı,
    # refresh-token DPAPI kasada). Herkes kendi uygulama kaydını açar.
    oauth_provider: str = Field(default="", description="outlook|gmail (boşsa şifreli giriş)")
    ms_client_id: str = Field(default="")
    google_client_id: str = Field(default="")
    oauth_refresh_outlook: str = Field(default="")
    oauth_refresh_gmail: str = Field(default="")

    @property
    def oauth_configured(self) -> bool:
        p = (self.oauth_provider or "").lower()
        if p == "outlook":
            return bool(self.ms_client_id and self.oauth_refresh_outlook)
        if p == "gmail":
            return bool(self.google_client_id and self.oauth_refresh_gmail)
        return False

    @property
    def imap_configured(self) -> bool:
        return bool(self.imap_user and self.imap_password)


@lru_cache
def get_settings() -> Settings:
    return Settings()
