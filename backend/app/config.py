"""ElfSec merkezi ayar yönetimi.

Tüm kritik veriler .env dosyasından okunur, koda gömülmez.
byeco / açık kaynak: .env GitHub'a yüklenmez (.gitignore).
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

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    api_token: str = Field(default="", description="Boşsa API korumasız (yalnızca yerel kullanım). Doluysa Bearer gerekli.")
    env: str = Field(default="dev")
    cors_origins: str = Field(default="http://localhost:3000,http://127.0.0.1:3000")

    # Rate limit
    rate_limit_default: str = Field(default="30/minute")
    rate_limit_emails: str = Field(default="20/minute")
    rate_limit_analyze: str = Field(default="10/minute")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def imap_configured(self) -> bool:
        return bool(self.imap_user and self.imap_password)


@lru_cache
def get_settings() -> Settings:
    return Settings()
