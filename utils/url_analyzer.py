"""
url_analyzer.py
----------------
Rule-based (NOT machine-learned) URL risk analysis.

The analyzer combines multiple URL heuristics such as:
- HTTPS usage
- IP-based URLs
- URL length
- host spoofing
- excessive subdomains
- punycode
- URL shorteners
- suspicious keywords
- numeric/hyphen-heavy domains
- typosquatting
- brand impersonation
- suspicious ports
- redirect parameters
- credential-related parameters
- URL encoding
- suspicious user-info sections

Every indicator is a heuristic. No single indicator proves that a URL
is malicious.

The module returns:
- observed indicators
- structured evidence
- domain information
- risk level
- threat-intelligence result

This module works offline.
"""

from __future__ import annotations

import difflib
import ipaddress
import re

from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlparse


# ---------------------------------------------------------------------------
# Optional tldextract
# ---------------------------------------------------------------------------

try:
    import tldextract

    # Offline public suffix list.
    _TLD_EXTRACTOR = tldextract.TLDExtract(
        suffix_list_urls=()
    )

    _HAS_TLDEXTRACT = True

except ImportError:

    _HAS_TLDEXTRACT = False
    _TLD_EXTRACTOR = None


# ---------------------------------------------------------------------------
# Detection configuration
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login",
    "log-in",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "update",
    "payment",
    "bank",
    "confirm",
    "urgent",
    "signin",
    "sign-in",
    "wallet",
    "suspended",
    "unlock",
    "invoice",
    "reset",
    "credential",
    "authenticate",
    "authentication",
]

KNOWN_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
    "tiny.cc",
}

# Common brands frequently impersonated in phishing emails.
COMMON_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "adobe": "adobe.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "github": "github.com",
    "whatsapp": "whatsapp.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "chase": "chase.com",
}

# Parameters commonly used to redirect victims to another website.
REDIRECT_PARAMETERS = {
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnto",
    "next",
    "continue",
    "destination",
    "dest",
    "target",
    "link",
}

# Parameters commonly associated with credential harvesting.
CREDENTIAL_PARAMETERS = {
    "user",
    "username",
    "email",
    "login",
    "password",
    "pass",
    "passwd",
    "token",
    "session",
    "auth",
    "credential",
}

LONG_URL_THRESHOLD = 75
EXCESSIVE_SUBDOMAIN_THRESHOLD = 3
SUSPICIOUS_PORTS = {21, 22, 23, 25, 110, 143, 445, 3389, 5900}

# A slightly lower threshold prevents obvious variations such as
# micros0ft / paypa1 from being missed.
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.82


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def _get_domain_parts(url: str):

    if _HAS_TLDEXTRACT:

        ext = _TLD_EXTRACTOR(url)

        domain = ".".join(
            part
            for part in [ext.domain, ext.suffix]
            if part
        )

        subdomain = ext.subdomain

        return (
            domain or urlparse(url).netloc,
            subdomain,
        )

    # Fallback when tldextract is unavailable.
    netloc = urlparse(
        url if "://" in url else f"http://{url}"
    ).netloc

    parts = netloc.split(".")

    if len(parts) >= 2:

        domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

    else:

        domain = netloc
        subdomain = ""

    return domain, subdomain


def _is_ip_host(host: str) -> bool:

    host = host.strip("[]")

    try:

        ipaddress.ip_address(host)
        return True

    except ValueError:

        return False


def _normalize_domain(domain: str) -> str:
    """
    Normalize a domain for comparison.

    Removes:
    - dots
    - hyphens
    - underscores

    This helps detect variations such as:
    micro-soft
    micros0ft
    pay-pal
    """

    return re.sub(
        r"[^a-z0-9]",
        "",
        domain.lower(),
    )


def _looks_like_typosquat(domain: str):
    """
    Compare the registered domain against known brand domains.

    Returns:
        (brand, similarity)
        or
        (None, 0.0)
    """

    domain_only = domain.lower().split(".")[0]

    normalized_domain = _normalize_domain(
        domain_only
    )

    if not normalized_domain:
        return None, 0.0

    best_brand = None
    best_similarity = 0.0

    for brand in COMMON_BRANDS:

        normalized_brand = _normalize_domain(
            brand
        )

        similarity = difflib.SequenceMatcher(
            None,
            normalized_domain,
            normalized_brand,
        ).ratio()

        if similarity > best_similarity:

            best_similarity = similarity
            best_brand = brand

    if (
        best_brand is not None
        and best_similarity >= TYPOSQUAT_SIMILARITY_THRESHOLD
        and normalized_domain != _normalize_domain(best_brand)
    ):

        return best_brand, round(best_similarity, 3)

    return None, 0.0


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------

def _detect_brand_impersonation(
    domain: str,
    host: str,
):
    """
    Detect domains that appear to contain a known brand name but are not
    the official domain.
    """

    lowered_host = host.lower()

    for brand, official_domain in COMMON_BRANDS.items():

        if brand in lowered_host:

            if not (
                lowered_host == official_domain
                or lowered_host.endswith(
                    "." + official_domain
                )
            ):

                return brand, official_domain

    return None, None


# ---------------------------------------------------------------------------
# Suspicious query analysis
# ---------------------------------------------------------------------------

def _analyze_query(parsed_url):

    indicators = []
    evidence = []

    query = parsed_url.query

    if not query:
        return indicators, evidence

    query_lower = query.lower()

    # ------------------------------------------------------------
    # Redirect parameters
    # ------------------------------------------------------------

    parameters = parse_qs(
        parsed_url.query,
        keep_blank_values=True,
    )

    redirect_hits = []

    credential_hits = []

    for key in parameters:

        key_lower = key.lower()

        if key_lower in REDIRECT_PARAMETERS:
            redirect_hits.append(key)

        if key_lower in CREDENTIAL_PARAMETERS:
            credential_hits.append(key)

    if redirect_hits:

        indicators.append(
            "Contains redirect parameter(s): "
            + ", ".join(sorted(set(redirect_hits)))
        )

        evidence.append(
            "The URL contains parameters that may redirect "
            "the user to another destination."
        )

    if credential_hits:

        indicators.append(
            "Contains credential-related parameter(s): "
            + ", ".join(sorted(set(credential_hits)))
        )

        evidence.append(
            "The URL contains parameters associated with "
            "login or credential submission."
        )

    # ------------------------------------------------------------
    # Encoded URL
    # ------------------------------------------------------------

    encoded_count = len(
        re.findall(
            r"%[0-9a-fA-F]{2}",
            query,
        )
    )

    if encoded_count >= 2:

        indicators.append(
            f"Contains multiple URL-encoded sequences ({encoded_count})"
        )

        evidence.append(
            "Multiple encoded characters were found in the URL query."
        )

    # ------------------------------------------------------------
    # External URL inside parameter
    # ------------------------------------------------------------

    decoded_query = unquote(
        query_lower
    )

    if (
        "http://" in decoded_query
        or "https://" in decoded_query
    ):

        indicators.append(
            "Contains an embedded URL inside query parameters"
        )

        evidence.append(
            "An additional URL appears inside the query string, "
            "which may indicate redirect or tracking behavior."
        )

    return indicators, evidence


# ---------------------------------------------------------------------------
# Single URL analysis
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyze a single URL and return its structured risk record.
    """

    if not raw_url:

        return {
            "url": raw_url,
            "domain": "",
            "https": False,
            "ip_based": False,
            "length": 0,
            "indicators": ["Empty URL"],
            "evidence": ["No URL was provided for analysis."],
            "risk": "Medium",
        }

    # Preserve original URL in output.
    original_url = raw_url.strip()

    url = (
        original_url
        if "://" in original_url
        else f"http://{original_url}"
    )

    parsed = urlparse(url)

    host = parsed.hostname or ""

    domain, subdomain = _get_domain_parts(url)

    indicators: List[str] = []
    evidence: List[str] = []

    # ============================================================
    # 1. HTTPS
    # ============================================================

    is_https = parsed.scheme.lower() == "https"

    if not is_https:

        indicators.append(
            "Uses HTTP instead of HTTPS"
        )

        evidence.append(
            "The URL does not use encrypted HTTPS transport."
        )

    # ============================================================
    # 2. IP address
    # ============================================================

    is_ip_based = _is_ip_host(host)

    if is_ip_based:

        indicators.append(
            "Uses an IP address instead of a domain name"
        )

        evidence.append(
            "The destination is identified directly by an IP address "
            "rather than a registered domain."
        )

    # ============================================================
    # 3. URL length
    # ============================================================

    if len(original_url) > LONG_URL_THRESHOLD:

        indicators.append(
            f"Very long URL ({len(original_url)} characters)"
        )

        evidence.append(
            "The URL is unusually long and may contain "
            "multiple parameters or obfuscation."
        )

    # ============================================================
    # 4. @ symbol
    # ============================================================

    if "@" in original_url.split("://")[-1]:

        indicators.append(
            "Contains an '@' symbol (possible host spoofing)"
        )

        evidence.append(
            "An '@' symbol can make the visible part of a URL "
            "appear different from its actual destination."
        )

    # ============================================================
    # 5. Excessive subdomains
    # ============================================================

    subdomain_count = (
        len(
            [
                s
                for s in subdomain.split(".")
                if s
            ]
        )
        if subdomain
        else 0
    )

    if subdomain_count >= EXCESSIVE_SUBDOMAIN_THRESHOLD:

        indicators.append(
            f"Excessive number of subdomains ({subdomain_count})"
        )

        evidence.append(
            "The domain contains an unusually deep subdomain structure."
        )

    # ============================================================
    # 6. Punycode
    # ============================================================

    if "xn--" in host.lower():

        indicators.append(
            "Punycode / internationalized domain detected"
        )

        evidence.append(
            "The domain uses Punycode, which can be abused "
            "for visually deceptive look-alike domains."
        )

    # ============================================================
    # 7. URL shortener
    # ============================================================

    normalized_host = host.lower()

    if (
        domain.lower() in KNOWN_SHORTENERS
        or normalized_host in KNOWN_SHORTENERS
    ):

        indicators.append(
            "Known URL shortener (destination is hidden)"
        )

        evidence.append(
            "The URL uses a known shortening service, "
            "so the final destination is not immediately visible."
        )

    # ============================================================
    # 8. Suspicious keywords
    # ============================================================

    lowered = original_url.lower()

    hit_keywords = [
        kw
        for kw in SUSPICIOUS_KEYWORDS
        if kw in lowered
    ]

    if hit_keywords:

        unique_keywords = sorted(
            set(hit_keywords)
        )

        indicators.append(
            "Contains suspicious keyword(s): "
            + ", ".join(unique_keywords)
        )

        evidence.append(
            "The URL contains keywords commonly seen in "
            "account, authentication, payment or urgency workflows."
        )

    # ============================================================
    # 9. Numeric-heavy domain
    # ============================================================

    if re.search(
        r"[0-9]{4,}",
        host,
    ):

        indicators.append(
            "Domain contains an unusually long numeric sequence"
        )

        evidence.append(
            "The domain contains an unusually long numeric sequence."
        )

    # ============================================================
    # 10. Excessive hyphens
    # ============================================================

    if host.count("-") >= 3:

        indicators.append(
            "Domain has an unusually high number of hyphens"
        )

        evidence.append(
            "Multiple hyphens can be used in deceptive "
            "look-alike domain names."
        )

    # ============================================================
    # 11. Suspicious port
    # ============================================================

    try:

        port = parsed.port

    except ValueError:

        port = None

        indicators.append(
            "Invalid or malformed port information"
        )

        evidence.append(
            "The URL contains malformed port information."
        )

    if port is not None and port in SUSPICIOUS_PORTS:

        indicators.append(
            f"Uses unusual service port ({port})"
        )

        evidence.append(
            f"The URL explicitly uses port {port}, "
            "which is commonly associated with network services "
            "rather than normal web browsing."
        )

    # ============================================================
    # 12. User information in URL
    # ============================================================

    if parsed.username or parsed.password:

        indicators.append(
            "Contains username/password information in URL"
        )

        evidence.append(
            "Credentials or user information appear before "
            "the host portion of the URL."
        )

    # ============================================================
    # 13. Typosquatting
    # ============================================================

    typosquat_brand, similarity = _looks_like_typosquat(
        domain
    )

    if typosquat_brand:

        official_domain = COMMON_BRANDS.get(
            typosquat_brand
        )

        indicators.append(
            f"Possible typosquatting of {typosquat_brand} "
            f"(similarity {similarity})"
        )

        evidence.append(
            f"The domain resembles the known brand "
            f"'{typosquat_brand}' but is not the official "
            f"domain '{official_domain}'."
        )

    # ============================================================
    # 14. Brand impersonation
    # ============================================================

    impersonated_brand, official_domain = (
        _detect_brand_impersonation(
            domain,
            host,
        )
    )

    if impersonated_brand:

        # Avoid duplicating an already detected typosquat.
        if impersonated_brand != typosquat_brand:

            indicators.append(
                f"Possible {impersonated_brand} brand impersonation"
            )

            evidence.append(
                f"The URL contains the brand name "
                f"'{impersonated_brand}' but does not use "
                f"the official domain '{official_domain}'."
            )

    # ============================================================
    # 15. Query / redirect / credential analysis
    # ============================================================

    query_indicators, query_evidence = (
        _analyze_query(parsed)
    )

    indicators.extend(
        query_indicators
    )

    evidence.extend(
        query_evidence
    )

    # ============================================================
    # 16. Obfuscation / encoding
    # ============================================================

    encoded_sequences = re.findall(
        r"%[0-9a-fA-F]{2}",
        original_url,
    )

    if len(encoded_sequences) >= 4:

        indicators.append(
            f"Heavy URL encoding detected "
            f"({len(encoded_sequences)} encoded sequences)"
        )

        evidence.append(
            "The URL contains multiple encoded characters, "
            "which may indicate obfuscation."
        )

    # ============================================================
    # 17. Double slash after host
    # ============================================================

    after_scheme = re.sub(
        r"^[a-zA-Z]+://",
        "",
        original_url,
    )

    if "//" in after_scheme:

        indicators.append(
            "Contains additional double-slash URL structure"
        )

        evidence.append(
            "Additional '//' characters appear after the host, "
            "which may be used for unusual URL construction."
        )

    # ============================================================
    # 18. Domain vs keyword analysis
    # ============================================================

    domain_keyword_hits = [
        kw
        for kw in SUSPICIOUS_KEYWORDS
        if kw in domain.lower()
    ]

    if domain_keyword_hits:

        indicators.append(
            "Suspicious keyword appears directly in domain: "
            + ", ".join(
                sorted(set(domain_keyword_hits))
            )
        )

        evidence.append(
            "A security-sensitive keyword appears directly "
            "inside the registered domain."
        )

    # ============================================================
    # 19. Risk calculation
    # ============================================================

    indicator_count = len(
        indicators
    )

    # High-value indicators.
    high_signal_count = sum(
        1
        for indicator in indicators
        if any(
            keyword in indicator.lower()
            for keyword in [
                "typosquatting",
                "impersonation",
                "known url shortener",
                "credential-related",
                "embedded url",
                "host spoofing",
                "punycode",
                "ip address",
                "threat intelligence",
            ]
        )
    )

    if indicator_count == 0:

        risk = "Low"

    elif (
        high_signal_count >= 2
        or indicator_count >= 5
    ):

        risk = "High"

    elif (
        high_signal_count >= 1
        or indicator_count >= 2
    ):

        risk = "Medium"

    else:

        risk = "Medium"

    # ============================================================
    # 20. Structured return
    # ============================================================

    return {
        "url": original_url,

        "domain": domain or host,

        "https": is_https,

        "ip_based": is_ip_based,

        "length": len(original_url),

        "indicators": indicators,

        "evidence": evidence,

        "risk": risk,

        # New structured intelligence fields.
        "typosquat_brand": typosquat_brand,

        "typosquat_similarity": similarity,

        "impersonated_brand": impersonated_brand,

        "official_brand_domain": official_domain,

        "subdomain_count": subdomain_count,

        "port": port,

        "has_redirect_parameters": any(
            "redirect parameter" in i.lower()
            for i in indicators
        ),

        "has_credential_parameters": any(
            "credential-related parameter" in i.lower()
            for i in indicators
        ),

        "has_encoded_content": len(
            encoded_sequences
        ) >= 2,
    }


# ---------------------------------------------------------------------------
# Multiple URL analysis
# ---------------------------------------------------------------------------

def analyze_urls(
    urls: List[str],
    phishing_lookup=None,
) -> List[Dict[str, Any]]:
    """
    Analyze a list of URLs.

    `phishing_lookup` is an optional callable:
        url -> bool

    It can be connected to a source such as PhishTank.
    The application continues working if the source is unavailable.
    """

    results = []

    for u in urls:

        record = analyze_url(u)

        # --------------------------------------------------------
        # Threat intelligence
        # --------------------------------------------------------

        if phishing_lookup is not None:

            try:

                found = phishing_lookup(u)

            except Exception:

                found = None

            if found is True:

                record[
                    "threat_intel"
                ] = "Known phishing indicator detected"

                record["risk"] = "High"

                record["indicators"].append(
                    "URL matched available phishing threat intelligence"
                )

                record["evidence"].append(
                    "The URL matched a known phishing indicator "
                    "from the configured threat-intelligence source."
                )

            elif found is False:

                record[
                    "threat_intel"
                ] = "Not found in available intelligence"

            else:

                record[
                    "threat_intel"
                ] = "Threat intelligence unavailable"

        else:

            record[
                "threat_intel"
            ] = "Threat intelligence source not configured"

        results.append(record)

    return results