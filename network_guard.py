"""Decide which addresses this tool is allowed to contact.

Allowed: loopback, link-local, IPv6 unique-local, and RFC 1918.
Carrier-grade NAT (100.64.0.0/10) is refused on purpose. Those addresses
can belong to an access provider rather than the home LAN.
There is no setting that turns this check off.
"""

import ipaddress


class GuardError(ValueError):
    """The target is not a private home-network range."""


_ALLOWED = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def assert_private_target(value: str):
    """Return the parsed network, or raise GuardError before any packet is sent."""
    text = str(value).strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise GuardError(
            f"Refusing {text!r}. Use a private IP or CIDR such as 192.168.1.0/24. "
            "Hostnames are not accepted."
        ) from exc
    first = network[0]
    last = network[-1]
    if not any(first in block and last in block for block in _ALLOWED):
        raise GuardError(
            f"Refusing {text}. This tool only scans loopback, link-local, and private "
            "home ranges (10/8, 172.16/12, 192.168/16, and IPv6 unique-local)."
        )
    return network


def address_is_allowed(value) -> bool:
    """True when a single address sits inside an allowed range."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return any(address in block for block in _ALLOWED)
