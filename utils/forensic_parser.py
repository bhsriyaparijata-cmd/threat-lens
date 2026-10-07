"""
forensic_parser.py
------------------
Parses raw email (.eml) content into a structured dictionary that every
other analysis module (URL, sender, auth, geoip, attachment) consumes.

This module performs NO machine learning and NO risk scoring. It is a
pure forensic extraction layer: headers, body text/html, URLs, IP
addresses found in Received headers, attachments, and approximate
IP-based location information.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import requests

from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Dict, List, Optional


URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)


# Extract IPv4 and IPv6 candidates from Received headers
IP_IN_HEADER_REGEX = re.compile(
    r"""
    (?:
        (?:\d{1,3}\.){3}\d{1,3}
        |
        [0-9A-Fa-f]*:[0-9A-Fa-f:.]+
    )
    """,
    re.VERBOSE,
)


def _safe_decode(payload: bytes, charset: Optional[str]) -> str:
    """Best-effort decode of a message payload."""

    if payload is None:
        return ""

    for enc in filter(None, [charset, "utf-8", "latin-1"]):
        try:
            return payload.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            continue

    return payload.decode("utf-8", errors="replace")


def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw .eml bytes into a structured dictionary."""

    msg = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)

    return _extract(msg)


def parse_pasted_email(
    from_addr: str,
    to_addr: str,
    subject: str,
    headers_text: str,
    body_text: str,
) -> Dict[str, Any]:
    """
    Build a structured record from manually pasted fields.

    Headers pasted by the user are combined with the basic fields so
    header-based checks such as Authentication-Results, Received,
    Reply-To and Return-Path still work.
    """

    synthetic = (
        f"From: {from_addr}\n"
        f"To: {to_addr}\n"
        f"Subject: {subject}\n"
        f"{headers_text.strip()}\n\n"
        f"{body_text}"
    )

    try:
        msg = Parser(
            policy=policy.default
        ).parsestr(synthetic)

        record = _extract(msg)

    except Exception:
        # Fall back to a minimal manual record if header text is malformed.
        record = _empty_record()

        record["subject"] = subject
        record["from"] = from_addr
        record["to"] = to_addr
        record["body_text"] = body_text

        record["urls"] = sorted(
            set(URL_REGEX.findall(body_text))
        )

    return record


def _empty_record() -> Dict[str, Any]:
    return {
        "subject": "",
        "from": "",
        "from_display_name": "",
        "to": "",
        "date": "",
        "date_parsed": None,
        "reply_to": "",
        "return_path": "",
        "headers": {},
        "authentication_results_raw": "",
        "received_headers": [],
        "public_ips": [],

        # GeoIP information
        "geoip": [],

        "body_text": "",
        "body_html": "",
        "urls": [],
        "attachments": [],
        "parse_warnings": [],
    }


def _extract(msg) -> Dict[str, Any]:
    record = _empty_record()
    warnings: List[str] = []

    # ---------------------------------------------------------
    # BASIC HEADER INFORMATION
    # ---------------------------------------------------------

    try:
        record["subject"] = msg.get("Subject", "") or ""

        from_header = msg.get("From", "") or ""

        display_name, from_addr = parseaddr(from_header)

        record["from"] = from_addr or from_header
        record["from_display_name"] = display_name

        record["to"] = msg.get("To", "") or ""

        record["reply_to"] = parseaddr(
            msg.get("Reply-To", "") or ""
        )[1]

        record["return_path"] = parseaddr(
            msg.get("Return-Path", "") or ""
        )[1]

        date_hdr = msg.get("Date", "")
        record["date"] = date_hdr or ""

        if date_hdr:
            try:
                record["date_parsed"] = parsedate_to_datetime(
                    date_hdr
                )
            except Exception:
                record["parse_warnings"].append(
                    "Could not parse Date header."
                )

    except Exception as exc:
        warnings.append(
            f"Header parsing issue: {exc}"
        )

    # ---------------------------------------------------------
    # ALL HEADERS
    # ---------------------------------------------------------

    try:
        record["headers"] = {
            k: v for k, v in msg.items()
        }

    except Exception:
        record["headers"] = {}

    # ---------------------------------------------------------
    # AUTHENTICATION RESULTS
    # SPF / DKIM / DMARC
    # ---------------------------------------------------------

    auth_headers = (
        msg.get_all(
            "Authentication-Results",
            []
        )
        or []
    )

    record["authentication_results_raw"] = "\n".join(
        auth_headers
    )

    # ---------------------------------------------------------
    # RECEIVED HEADERS
    # ---------------------------------------------------------

    received_headers = (
        msg.get_all(
            "Received",
            []
        )
        or []
    )

    record["received_headers"] = received_headers

    # ---------------------------------------------------------
    # PUBLIC IP EXTRACTION
    # ---------------------------------------------------------

    ips_found: List[str] = []

    for hop in received_headers:

        candidates = IP_IN_HEADER_REGEX.findall(
            hop
        )

        for candidate in candidates:

            candidate_clean = candidate.strip(
                "[](),;"
            )

            # Validate using Python's IP parser.
            try:
                ip_obj = ipaddress.ip_address(
                    candidate_clean
                )
            except ValueError:
                continue

            if _is_public_ip(candidate_clean):

                ip_string = str(ip_obj)

                if ip_string not in ips_found:
                    ips_found.append(ip_string)

    record["public_ips"] = ips_found

    # ---------------------------------------------------------
    # GEOIP LOOKUP
    # ---------------------------------------------------------

    geoip_results = []

    for ip in record["public_ips"]:

        location = _lookup_geoip(ip)

        if location:
            geoip_results.append(location)

    record["geoip"] = geoip_results

    # ---------------------------------------------------------
    # BODY + ATTACHMENTS
    # ---------------------------------------------------------

    body_text_parts: List[str] = []
    body_html_parts: List[str] = []

    attachments: List[Dict[str, Any]] = []

    try:

        if msg.is_multipart():

            for part in msg.walk():

                content_disposition = str(
                    part.get(
                        "Content-Disposition",
                        ""
                    )
                )

                content_type = (
                    part.get_content_type()
                )

                if part.is_multipart():
                    continue

                # Attachment
                if (
                    "attachment"
                    in content_disposition
                    or part.get_filename()
                ):

                    attachments.append(
                        _build_attachment_record(
                            part
                        )
                    )

                    continue

                # Plain text
                if content_type == "text/plain":

                    body_text_parts.append(
                        _safe_decode(
                            part.get_payload(
                                decode=True
                            ),
                            part.get_content_charset(),
                        )
                    )

                # HTML
                elif content_type == "text/html":

                    body_html_parts.append(
                        _safe_decode(
                            part.get_payload(
                                decode=True
                            ),
                            part.get_content_charset(),
                        )
                    )

        else:

            content_type = (
                msg.get_content_type()
            )

            payload = _safe_decode(
                msg.get_payload(
                    decode=True
                ),
                msg.get_content_charset(),
            )

            if content_type == "text/html":

                body_html_parts.append(
                    payload
                )

            else:

                body_text_parts.append(
                    payload
                )

    except Exception as exc:

        warnings.append(
            f"Body/attachment parsing issue: {exc}"
        )

    record["body_text"] = (
        "\n".join(body_text_parts)
        .strip()
    )

    record["body_html"] = (
        "\n".join(body_html_parts)
        .strip()
    )

    record["attachments"] = attachments

    # ---------------------------------------------------------
    # URL EXTRACTION
    # ---------------------------------------------------------

    combined_for_urls = (
        f"{record['body_text']}\n"
        f"{record['body_html']}"
    )

    urls = URL_REGEX.findall(
        combined_for_urls
    )

    cleaned = []

    for u in urls:

        u = u.rstrip(
            '.,;:!?\'")'
        )

        cleaned.append(u)

    record["urls"] = sorted(
        set(cleaned),
        key=cleaned.index
    )

    record["parse_warnings"] = warnings

    return record


# -------------------------------------------------------------
# ATTACHMENT INFORMATION
# -------------------------------------------------------------

def _build_attachment_record(part) -> Dict[str, Any]:

    filename = (
        part.get_filename()
        or "unnamed_attachment"
    )

    try:

        payload = (
            part.get_payload(
                decode=True
            )
            or b""
        )

    except Exception:

        payload = b""

    sha256 = (
        hashlib.sha256(
            payload
        ).hexdigest()
        if payload
        else ""
    )

    return {
        "filename": filename,
        "content_type": part.get_content_type(),
        "size_bytes": len(payload),
        "sha256": sha256,
    }


# -------------------------------------------------------------
# CHECK WHETHER IP IS PUBLIC
# -------------------------------------------------------------

def _is_public_ip(ip_str: str) -> bool:

    try:

        ip_obj = ipaddress.ip_address(
            ip_str
        )

    except ValueError:

        return False

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_reserved
        or ip_obj.is_link_local
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
    ):
        return False

    return True


# -------------------------------------------------------------
# GEOIP LOOKUP
# -------------------------------------------------------------

def _lookup_geoip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get approximate location/network information
    for a public IP address.

    This is NOT the exact physical location of the sender.
    It represents IP-based location intelligence.
    """

    try:

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
            timeout=5
        )

        if response.status_code != 200:
            return {
                "ip": ip,
                "status": "lookup_failed",
                "message": "GeoIP service unavailable"
            }

        data = response.json()

        if not data.get("success", False):
            return {
                "ip": ip,
                "status": "lookup_failed",
                "message": data.get(
                    "message",
                    "Unknown GeoIP error"
                )
            }

        connection = (
            data.get("connection")
            or {}
        )

        return {
            "ip": ip,

            "country": data.get(
                "country",
                ""
            ),

            "country_code": data.get(
                "country_code",
                ""
            ),

            "region": data.get(
                "region",
                ""
            ),

            "city": data.get(
                "city",
                ""
            ),

            "latitude": data.get(
                "latitude"
            ),

            "longitude": data.get(
                "longitude"
            ),

            "postal": data.get(
                "postal",
                ""
            ),

            "timezone": (
                data.get("timezone")
                or {}
            ).get(
                "id",
                ""
            ),

            "isp": connection.get(
                "isp",
                ""
            ),

            "organization": connection.get(
                "org",
                ""
            ),

            "asn": connection.get(
                "asn",
                ""
            ),

            "domain": connection.get(
                "domain",
                ""
            ),

            "source": "IP-based GeoIP",

            "accuracy_note": (
                "Approximate IP-based location. "
                "It may represent a mail server, "
                "VPN, proxy, ISP or hosting provider "
                "rather than the attacker's physical location."
            ),

            "status": "success"
        }

    except requests.RequestException as exc:

        return {
            "ip": ip,
            "status": "lookup_failed",
            "message": str(exc)
        }

    except Exception as exc:

        return {
            "ip": ip,
            "status": "lookup_failed",
            "message": str(exc)
        }