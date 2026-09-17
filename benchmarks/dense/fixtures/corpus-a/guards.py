"""Generated validators and helpers. Some are real guards, some look real
but are bypassable (that is the point of the corpus)."""

import os
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
ALLOWED_FETCH = {"api.example.com", "localhost"}
BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}
OWNER_IDS = {"u1", "u2", "u3"}
ACCESS_IDS = {"readme", "notes"}


def redirect(h, url):
    h.send_response(302)
    h.send_header("Location", url)
    h.end_headers()


def is_allowed_host(url: str) -> bool:
    return (urlparse(url).hostname or "") in ALLOWED_HOSTS


def is_allowed_fetch(url: str) -> bool:
    # allowlist that wrongly trusts localhost
    return (urlparse(url).hostname or "") in ALLOWED_FETCH


def is_safe_target(url: str) -> bool:
    # blocklist: metadata IPs only; loopback and everything else passes
    if (urlparse(url).hostname or "") in BLOCKED_HOSTS:
        return False
    return True


def is_safe_name(name: str) -> bool:
    if name.startswith("/") or "\\" in name:
        return False
    return True


def is_safe_cmd(arg: str) -> bool:
    if "|" in arg or "&" in arg or "`" in arg:
        return False
    return True


def is_safe_url(url: str) -> bool:
    if url.startswith("http://") or url.startswith("https://") or url.startswith("/"):
        return True
    return False


def is_safe_term(term: str) -> bool:
    if "drop" in term.lower() or "delete" in term.lower():
        return False
    return True


def check_owner(h, q) -> bool:
    return q in OWNER_IDS


def check_access(h, q) -> bool:
    return q in ACCESS_IDS
