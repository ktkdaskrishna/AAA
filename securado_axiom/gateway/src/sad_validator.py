from __future__ import annotations

from .models import SAD


class SADValidationError(ValueError):
    pass


EXPECTED_SIGNATURE = "SIGNED_BY_AUTHORIZED_KEY"


def validate_sad(sad: SAD, now_ts: int) -> None:
    if sad.signature != EXPECTED_SIGNATURE:
        raise SADValidationError("SAD signature is invalid")
    if now_ts < sad.window_start or now_ts > sad.window_end:
        raise SADValidationError("SAD is outside engagement window")
    if not sad.allowed_cidrs:
        raise SADValidationError("SAD missing allowed CIDRs")
