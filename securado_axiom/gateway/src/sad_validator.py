from __future__ import annotations

import hashlib
import hmac
import json

from .models import SAD


class SADValidationError(ValueError):
    pass



def canonical_sad_payload(sad: SAD) -> str:
    data = {
        "engagement_id": sad.engagement_id,
        "allowed_cidrs": sad.allowed_cidrs,
        "excluded_ips": sad.excluded_ips,
        "window_start": sad.window_start,
        "window_end": sad.window_end,
        "permitted_tactics": sad.permitted_tactics,
        "session_secret": sad.session_secret,
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":"))



def sign_sad(sad: SAD, signing_secret: str) -> str:
    payload = canonical_sad_payload(sad)
    return hmac.new(signing_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()



def validate_sad(sad: SAD, now_ts: int, signing_secret: str) -> None:
    expected = sign_sad(sad, signing_secret)
    if not hmac.compare_digest(sad.signature, expected):
        raise SADValidationError("SAD signature is invalid")
    if now_ts < sad.window_start or now_ts > sad.window_end:
        raise SADValidationError("SAD is outside engagement window")
    if not sad.allowed_cidrs:
        raise SADValidationError("SAD missing allowed CIDRs")
