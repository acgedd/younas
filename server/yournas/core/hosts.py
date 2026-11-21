"""Host names and the Host header (DNS-rebinding defence).

The app answers only for host names it was told about. A page on `evil.example` that is rebound
to 127.0.0.1 still sends `Host: evil.example`, so refusing every Host that is not on the list keeps
a browser on another origin away from the loopback port. These helpers are strict on purpose:
no wildcard, no port in a configured name, no userinfo, no trailing dot, ASCII only (an
internationalised name must be given in its punycode form).
"""

from __future__ import annotations

import ipaddress
import re

# Always accepted, whatever is configured: a local health check or a browser on the machine.
LOOPBACK_HOST_NAMES = frozenset({"localhost", "127.0.0.1", "[::1]"})

MAX_HOST_HEADER_LENGTH = 255
MAX_HOST_NAME_LENGTH = 253

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DIGITS_AND_DOTS = re.compile(r"[0-9.]+")
# ASCII digits only: `\d` would match other scripts' digits.
_BRACKETED = re.compile(r"\[([0-9a-f:.]+)\](?::([0-9]{1,5}))?")
_PLAIN = re.compile(r"([^:\[\]]+)(?::([0-9]{1,5}))?")


def normalize_host_name(value: str) -> str | None:
    """Canonical form of a host name or IP literal (no port), or None if `value` is not one.

    Lower case. An IPv4 address is in dotted form, an IPv6 address is compressed and in brackets
    (a bare IPv6 address is accepted and bracketed, for configuration files). Wildcards, ports,
    schemes, paths, userinfo, zone ids and empty or over-long labels give None.
    """
    if not value or not value.isascii() or len(value) > MAX_HOST_NAME_LENGTH:
        return None
    name = value.lower()
    if ":" in name:
        inner = name[1:-1] if name.startswith("[") and name.endswith("]") else name
        if "%" in inner:
            return None
        try:
            return f"[{ipaddress.IPv6Address(inner).compressed}]"
        except ValueError:
            return None
    if _DIGITS_AND_DOTS.fullmatch(name):
        try:
            return str(ipaddress.IPv4Address(name))
        except ValueError:
            return None
    if all(_LABEL.fullmatch(label) for label in name.split(".")):
        return name
    return None


def parse_host_header(raw: str) -> str | None:
    """The normalized host name of a Host header value, without its port, or None if the value is
    malformed. Accepts `name`, `name:port`, `a.b.c.d[:port]` and `[v6][:port]`; the port must be
    1-65535. Control characters, spaces, non-ASCII and more than 255 characters are refused."""
    if not raw or len(raw) > MAX_HOST_HEADER_LENGTH:
        return None
    if not raw.isascii() or not raw.isprintable() or " " in raw:
        return None
    lowered = raw.lower()
    match = _BRACKETED.fullmatch(lowered)
    if match is not None:
        host = f"[{match.group(1)}]"
    else:
        match = _PLAIN.fullmatch(lowered)
        if match is None:
            return None
        host = match.group(1)
    port = match.group(2)
    if port is not None and not 1 <= int(port) <= 65535:
        return None
    return normalize_host_name(host)
