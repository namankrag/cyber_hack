"""Deterministic destination extraction + allow-list matching.

This is the *non-LLM*, non-keyword half of the defense: structurally pull every
outbound destination (email address or URL) out of a tool call's arguments and
check it against an explicit allow-list. It cannot be talked around by an
injection, because it reasons about where data would actually go, not about the
wording of the request.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"\b(?:https?://|ftp://|//)[^\s'\"<>()]+", re.I)


def extract_destinations(arguments: dict, keys: list[str] | None = None) -> list[str]:
    """Return every email/URL found in the argument values.

    If `keys` is given, only those argument names are scanned; otherwise all
    string (and nested) values are scanned — an injection can't hide a sink by
    renaming the field.
    """
    out: list[str] = []
    items = ((k, arguments[k]) for k in keys if k in arguments) if keys \
        else arguments.items()
    for _k, v in items:
        _scan_value(v, out)
    # de-dupe, preserve order
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def _scan_value(v, out: list[str]) -> None:
    if isinstance(v, str):
        out.extend(_URL_RE.findall(v))
        out.extend(_EMAIL_RE.findall(v))
    elif isinstance(v, dict):
        for x in v.values():
            _scan_value(x, out)
    elif isinstance(v, (list, tuple)):
        for x in v:
            _scan_value(x, out)


def destination_host(dest: str) -> str:
    """The host/domain a destination resolves to (for allow-list matching)."""
    if "@" in dest and "://" not in dest:
        return dest.rsplit("@", 1)[1].lower()
    parsed = urlparse(dest if "://" in dest else "//" + dest, scheme="")
    return (parsed.hostname or "").lower()


def destination_allowed(dest: str, allowlist: list[str]) -> bool:
    """A destination is allowed if it exactly matches an allow-list entry, or
    its host equals or is a sub-domain of an allow-listed host/domain.
    """
    if not allowlist:
        return False
    dest_l = dest.lower()
    host = destination_host(dest)
    for entry in allowlist:
        e = entry.lower().strip()
        if not e:
            continue
        if dest_l == e:                       # exact address/URL
            return True
        if host == e or host.endswith("." + e):   # domain / sub-domain
            return True
    return False


def disallowed_destinations(arguments: dict, allowlist: list[str],
                            keys: list[str] | None = None) -> list[str]:
    """Destinations present in the call that are NOT on the allow-list."""
    return [d for d in extract_destinations(arguments, keys)
            if not destination_allowed(d, allowlist)]
