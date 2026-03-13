from __future__ import annotations

import sys
from pathlib import Path

from securado_axiom.gateway.src.audit_logger import AuditLogger



def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("securado_axiom/audit/audit.log")
    logger = AuditLogger(path)
    ok = logger.verify_integrity()
    print("OK" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
