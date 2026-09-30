import logging
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    port: int = 8000
    max_pages: int = 20
    max_assets: int = 30
    scan_timeout_seconds: int = 120
    request_timeout_seconds: int = 10
    scan_ttl_minutes: int = 30
    rate_limit_per_hour: int = 5
    allow_private_targets: bool = False
    user_agent: str = (
        "LLMSecurityCheck/1.0 (+https://github.com/placeholder/llm-security-check)"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def warn_if_unsafe(settings: Settings) -> None:
    if settings.allow_private_targets:
        logger.warning(
            "ALLOW_PRIVATE_TARGETS=true is set. "
            "The scanner will follow requests to private/local addresses. "
            "NEVER enable this in a public or shared deployment."
        )
