"""
sender_analyzer.py
-------------------
Rule-based sender / identity analysis.

No machine learning is used here.

The analyzer checks:
- From / Reply-To mismatch
- From / Return-Path mismatch
- Display-name impersonation
- Typosquatting
- Brand impersonation
- Free email provider abuse
- Suspicious business/support identities
- Suspicious sender usernames

All findings are heuristic indicators and should be treated as
investigation evidence, not automatic proof of malicious activity.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Known free email providers
# ---------------------------------------------------------------------------

FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "protonmail.com",
    "gmx.com",
    "rediffmail.com",
    "yandex.com",
    "zoho.com",
}


# ---------------------------------------------------------------------------
# Known brand domains
# ---------------------------------------------------------------------------

COMMON_BRAND_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "bankofamerica.com",
    "chase.com",
    "hdfcbank.com",
    "icicibank.com",
    "sbi.co.in",
    "irctc.co.in",
    "gov.in",
    "income-tax.gov.in",
]


# Display-name words commonly used by business/support identities.
BUSINESS_IDENTITY_KEYWORDS = {
    "support",
    "billing",
    "security",
    "bank",
    "official",
    "team",
    "helpdesk",
    "admin",
    "administrator",
    "customer",
    "service",
    "account",
    "verification",
    "verification team",
    "finance",
    "payroll",
    "hr",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain_of(addr: str) -> str:
    """
    Extract the domain from an email address.
    """

    if not addr or "@" not in addr:
        return ""

    return (
        addr.rsplit("@", 1)[-1]
        .lower()
        .strip()
        .rstrip(">")
    )


def _local_part(addr: str) -> str:
    """
    Extract the username/local part from an email address.
    """

    if not addr or "@" not in addr:
        return ""

    return (
        addr.rsplit("@", 1)[0]
        .strip()
        .lower()
        .strip("<>")
    )


def _normalize_domain(domain: str) -> str:
    """
    Normalize a domain for similarity comparison.

    Example:
        micro-soft.com -> microsoft
        micros0ft.com -> micros0ft
    """

    domain = domain.lower()

    # Remove common TLDs.
    for suffix in [
        ".com",
        ".org",
        ".net",
        ".co.in",
        ".in",
        ".gov",
    ]:
        if domain.endswith(suffix):
            domain = domain[:-len(suffix)]
            break

    return re.sub(
        r"[^a-z0-9]",
        "",
        domain,
    )


def _brand_root(domain: str) -> str:
    """
    Get the first meaningful domain component.

    microsoft.com -> microsoft
    login.microsoft.com -> login
    """

    if not domain:
        return ""

    return domain.split(".")[0].lower()


def _looks_like_typosquat(domain: str) -> List[str]:
    """
    Detect domains that closely resemble known brands.
    """

    hits = []

    if not domain:
        return hits

    normalized_domain = _normalize_domain(domain)

    if not normalized_domain:
        return hits

    for brand in COMMON_BRAND_DOMAINS:

        if domain.lower() == brand.lower():
            continue

        normalized_brand = _normalize_domain(brand)

        similarity = difflib.SequenceMatcher(
            None,
            normalized_domain,
            normalized_brand,
        ).ratio()

        if similarity >= 0.82:

            hits.append(
                f"{brand} ({similarity:.2f} similarity)"
            )

    return hits


def _find_brand_references(display_name: str) -> List[str]:
    """
    Find known brands referenced in the display name.
    """

    found = []

    lowered = display_name.lower()

    for brand in COMMON_BRAND_DOMAINS:

        brand_root = brand.split(".")[0].lower()

        if brand_root in lowered:
            found.append(brand_root)

    return sorted(set(found))


def _is_business_identity(display_name: str) -> bool:
    """
    Determine whether the display name resembles a business/support
    identity.
    """

    lowered = display_name.lower()

    return any(
        keyword in lowered
        for keyword in BUSINESS_IDENTITY_KEYWORDS
    )


def _detect_suspicious_local_part(local_part: str) -> List[str]:
    """
    Detect suspicious patterns in the username before '@'.
    """

    findings = []

    if not local_part:
        return findings

    # Many numeric characters can be used in throwaway identities.
    digit_count = sum(
        char.isdigit()
        for char in local_part
    )

    if digit_count >= 4:

        findings.append(
            "Sender username contains an unusually high number of digits"
        )

    # Excessive separators.
    if local_part.count(".") >= 4:

        findings.append(
            "Sender username contains many dot separators"
        )

    if local_part.count("-") >= 3:

        findings.append(
            "Sender username contains many hyphens"
        )

    # Common security/business impersonation words.
    suspicious_words = [
        "verify",
        "security",
        "support",
        "admin",
        "billing",
        "account",
        "payment",
        "official",
    ]

    hits = [
        word
        for word in suspicious_words
        if word in local_part
    ]

    if hits:

        findings.append(
            "Sender username contains identity-related keyword(s): "
            + ", ".join(sorted(set(hits)))
        )

    return findings


# ---------------------------------------------------------------------------
# Main sender analysis
# ---------------------------------------------------------------------------

def analyze_sender(
    record: Dict[str, Any]
) -> Dict[str, Any]:

    from_addr = (
        record.get("from", "")
        or ""
    )

    display_name = (
        record.get("from_display_name", "")
        or ""
    )

    reply_to = (
        record.get("reply_to", "")
        or ""
    )

    return_path = (
        record.get("return_path", "")
        or ""
    )

    # ------------------------------------------------------------
    # Extract domains
    # ------------------------------------------------------------

    from_domain = _domain_of(
        from_addr
    )

    reply_to_domain = _domain_of(
        reply_to
    )

    return_path_domain = _domain_of(
        return_path
    )

    sender_local_part = _local_part(
        from_addr
    )

    reasons: List[str] = []
    evidence: List[str] = []

    # ============================================================
    # 1. Reply-To mismatch
    # ============================================================

    if (
        reply_to
        and reply_to_domain
        and from_domain
        and reply_to_domain != from_domain
    ):

        reasons.append(
            f"Reply-To domain ('{reply_to_domain}') "
            f"differs from sender domain ('{from_domain}')"
        )

        evidence.append(
            "The Reply-To address points to a different domain "
            "than the visible sender address."
        )

    # ============================================================
    # 2. Return-Path mismatch
    # ============================================================

    if (
        return_path
        and return_path_domain
        and from_domain
        and return_path_domain != from_domain
    ):

        reasons.append(
            f"Return-Path domain ('{return_path_domain}') "
            f"differs from sender domain ('{from_domain}')"
        )

        evidence.append(
            "The Return-Path domain differs from the visible "
            "From domain."
        )

    # ============================================================
    # 3. Display-name brand impersonation
    # ============================================================

    brand_references = _find_brand_references(
        display_name
    )

    if brand_references:

        for brand_root in brand_references:

            official_domains = [
                brand
                for brand in COMMON_BRAND_DOMAINS
                if brand.split(".")[0].lower()
                == brand_root
            ]

            official_domain = (
                official_domains[0]
                if official_domains
                else brand_root
            )

            # If sender domain isn't the actual brand domain.
            if (
                from_domain
                and from_domain != official_domain
                and not from_domain.endswith(
                    "." + official_domain
                )
            ):

                reasons.append(
                    f"Display name references '{brand_root}' "
                    f"but sender domain is '{from_domain}'"
                )

                evidence.append(
                    f"The sender presents itself as '{brand_root}' "
                    f"but does not originate from the expected "
                    f"domain '{official_domain}'."
                )

    # ============================================================
    # 4. Typosquatting
    # ============================================================

    typosquat_hits = _looks_like_typosquat(
        from_domain
    )

    if typosquat_hits:

        reasons.append(
            "Sender domain closely resembles a well-known domain: "
            + ", ".join(typosquat_hits)
            + " (possible typosquatting)"
        )

        evidence.append(
            "The sender domain is visually similar to a known "
            "brand domain but is not identical to it."
        )

    # ============================================================
    # 5. Brand keyword inside suspicious domain
    # ============================================================

    domain_lower = from_domain.lower()

    for brand in COMMON_BRAND_DOMAINS:

        brand_root = brand.split(".")[0].lower()

        if (
            brand_root in domain_lower
            and from_domain != brand
            and not from_domain.endswith(
                "." + brand
            )
        ):

            reasons.append(
                f"Sender domain contains the brand name "
                f"'{brand_root}' but is not the official domain"
            )

            evidence.append(
                f"The domain '{from_domain}' contains the brand "
                f"name '{brand_root}' while using a different "
                f"registered domain."
            )

            break

    # ============================================================
    # 6. Free email provider + business identity
    # ============================================================

    if (
        from_domain in FREE_EMAIL_PROVIDERS
        and _is_business_identity(display_name)
    ):

        reasons.append(
            f"Free email provider ('{from_domain}') used for "
            "a business/support-style identity"
        )

        evidence.append(
            "The sender uses a consumer email provider while "
            "presenting itself as an organization or support team."
        )

    # ============================================================
    # 7. Suspicious sender username
    # ============================================================

    username_findings = (
        _detect_suspicious_local_part(
            sender_local_part
        )
    )

    reasons.extend(
        username_findings
    )

    if username_findings:

        evidence.append(
            "The username portion of the sender address "
            "contains patterns that may warrant investigation."
        )

    # ============================================================
    # 8. Missing sender domain
    # ============================================================

    if from_addr and not from_domain:

        reasons.append(
            "Sender address does not contain a valid domain"
        )

        evidence.append(
            "The From address could not be parsed into "
            "a normal email domain."
        )

    # ============================================================
    # 9. Missing display name
    # ============================================================

    if not display_name:

        evidence.append(
            "No sender display name was available for "
            "identity comparison."
        )

    # ============================================================
    # 10. Risk calculation
    # ============================================================

    reason_count = len(
        reasons
    )

    # High-value identity signals.
    high_value_signals = 0

    for reason in reasons:

        lowered = reason.lower()

        if any(
            keyword in lowered
            for keyword in [
                "typosquatting",
                "impersonation",
                "display name references",
                "reply-to domain",
                "return-path domain",
                "brand name",
            ]
        ):

            high_value_signals += 1

    if reason_count == 0:

        risk = "Low"

    elif (
        high_value_signals >= 2
        or reason_count >= 4
    ):

        risk = "High"

    else:

        risk = "Medium"

    # ============================================================
    # 11. Identity classification
    # ============================================================

    if (
        typosquat_hits
        or brand_references
    ):

        identity_type = "POSSIBLE IMPERSONATION"

    elif (
        from_domain in FREE_EMAIL_PROVIDERS
        and _is_business_identity(display_name)
    ):

        identity_type = "SUSPICIOUS BUSINESS IDENTITY"

    elif (
        reply_to_domain
        and reply_to_domain != from_domain
    ):

        identity_type = "SENDER MISMATCH"

    else:

        identity_type = "NORMAL / UNKNOWN"

    # ============================================================
    # 12. Return result
    # ============================================================

    return {
        "from": from_addr,

        "from_domain": from_domain,

        "display_name": display_name,

        "reply_to": reply_to,

        "return_path": return_path,

        "reasons": reasons,

        "evidence": evidence,

        "risk": risk,

        # New fields
        "identity_type": identity_type,

        "typosquat_hits": typosquat_hits,

        "brand_references": brand_references,

        "sender_local_part": sender_local_part,

        "is_free_email_provider": (
            from_domain in FREE_EMAIL_PROVIDERS
        ),

        "is_business_identity": (
            _is_business_identity(display_name)
        ),
    }