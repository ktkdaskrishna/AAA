from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    audit_log_path: Path
    sad_signing_secret: str
    max_chain_length: int
    rate_limit_per_minute: int
    admin_api_key: str



def load_settings() -> Settings:
    return Settings(
        audit_log_path=Path(os.getenv("AXIOM_AUDIT_LOG_PATH", "securado_axiom/audit/audit.log")),
        sad_signing_secret=os.getenv("AXIOM_SAD_SIGNING_SECRET", "dev-sad-secret"),
        max_chain_length=int(os.getenv("AXIOM_MAX_CHAIN_LENGTH", "10")),
        rate_limit_per_minute=int(os.getenv("AXIOM_RATE_LIMIT_PER_MINUTE", "60")),
        admin_api_key=os.getenv("AXIOM_ADMIN_API_KEY", "change-me"),
    )
