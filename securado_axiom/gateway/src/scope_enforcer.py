from __future__ import annotations

import ipaddress


class ScopeError(ValueError):
    pass


def _in_any_cidr(ip: str, cidrs: list[str]) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


def enforce_scope(targets: list[str], allowed_cidrs: list[str], excluded_ips: list[str]) -> None:
    for target in targets:
        if target in excluded_ips:
            raise ScopeError(f"EXCLUDED_TARGET:{target}")
        if not _in_any_cidr(target, allowed_cidrs):
            raise ScopeError(f"OUT_OF_SCOPE:{target}")
