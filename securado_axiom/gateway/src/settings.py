from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    audit_log_path: Path
    state_store_path: Path
    sad_signing_secret: str
    max_chain_length: int
    rate_limit_per_minute: int
    admin_api_key: str
    strict_production: bool


def _read_secret(name: str, default: str) -> str:
    file_var = f"{name}_FILE"
    if os.getenv(file_var):
        return Path(os.environ[file_var]).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)


def validate_settings(settings: Settings) -> None:
    if not settings.strict_production:
        return
    if settings.admin_api_key in {"", "change-me"}:
        raise ValueError("Invalid AXIOM_ADMIN_API_KEY for strict production mode")
    if settings.sad_signing_secret in {"", "dev-sad-secret"}:
        raise ValueError("Invalid AXIOM_SAD_SIGNING_SECRET for strict production mode")


def load_settings() -> Settings:
    settings = Settings(
        audit_log_path=Path(os.getenv("AXIOM_AUDIT_LOG_PATH", "securado_axiom/audit/audit.log")),
        state_store_path=Path(os.getenv("AXIOM_STATE_STORE_PATH", "securado_axiom/state/state.json")),
        sad_signing_secret=_read_secret("AXIOM_SAD_SIGNING_SECRET", "dev-sad-secret"),
        max_chain_length=int(os.getenv("AXIOM_MAX_CHAIN_LENGTH", "10")),
        rate_limit_per_minute=int(os.getenv("AXIOM_RATE_LIMIT_PER_MINUTE", "60")),
        admin_api_key=_read_secret("AXIOM_ADMIN_API_KEY", "change-me"),
        strict_production=os.getenv("AXIOM_STRICT_PRODUCTION", "false").lower() == "true",
    )
    validate_settings(settings)
    return settings
