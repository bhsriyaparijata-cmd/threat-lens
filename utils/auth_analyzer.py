"""
auth_analyzer.py
-----------------
Parses the Authentication-Results header to report SPF, DKIM and DMARC
outcomes. This is a protocol/header parsing step - no ML, no external
lookups, and it never crashes when the header is missing or malformed.
"""

from __future__ import annotations

import re
from typing import Any, Dict

VALID_STATES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}

EXPLANATIONS = {
    "SPF": "Checks whether the sending mail server is authorized to send on behalf of the domain.",
    "DKIM": "Checks the cryptographic signature attached to the email to verify it was not altered in transit.",
    "DMARC": "Checks alignment between SPF/DKIM and the visible From domain, applying the domain owner's policy.",
}


def _extract_result(auth_text: str, mechanism: str) -> str:
    pattern = rf"{mechanism}\s*=\s*(\w+)"
    match = re.search(pattern, auth_text, re.IGNORECASE)
    if not match:
        return "UNKNOWN"
    value = match.group(1).lower()
    if value not in VALID_STATES:
        return "UNKNOWN"
    if value == "pass":
        return "PASS"
    if value in ("fail", "permerror"):
        return "FAIL"
    if value == "none":
        return "NONE"
    return value.upper()  # softfail / neutral / temperror


def analyze_auth(record: Dict[str, Any]) -> Dict[str, Any]:
    auth_raw = record.get("authentication_results_raw", "") or ""

    if not auth_raw.strip():
        return {
            "spf": "NONE",
            "dkim": "NONE",
            "dmarc": "NONE",
            "raw": "",
            "note": "No Authentication-Results header was found in this email.",
            "explanations": EXPLANATIONS,
        }

    spf = _extract_result(auth_raw, "spf")
    dkim = _extract_result(auth_raw, "dkim")
    dmarc = _extract_result(auth_raw, "dmarc")

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "raw": auth_raw,
        "note": "",
        "explanations": EXPLANATIONS,
    }
