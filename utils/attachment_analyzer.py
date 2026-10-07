"""
attachment_analyzer.py
------------------------
Rule-based attachment risk analysis: filename patterns, MIME-type
mismatches and (optionally) VirusTotal hash reputation lookups.

VirusTotal is entirely optional. If VT_API_KEY is not set, or the
network call fails, the app must keep working with a clear
"not checked" status.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

EXECUTABLE_EXTENSIONS = {
    "exe", "bat", "cmd", "com", "scr", "msi", "pif", "vbs", "vbe", "ws",
    "wsf", "jar", "cpl", "gadget", "app",
}
SCRIPT_EXTENSIONS = {"js", "jse", "ps1", "psm1", "sh", "py", "pl"}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "iso"}

# Extension -> commonly expected MIME type prefixes, for basic mismatch checks
EXPECTED_MIME_PREFIX = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats",
    "jpg": "image/",
    "jpeg": "image/",
    "png": "image/",
    "gif": "image/",
    "txt": "text/",
}

VT_API_KEY = os.environ.get("VT_API_KEY", "")


def _extensions(filename: str) -> List[str]:
    parts = filename.lower().rsplit(".", maxsplit=2)
    return parts[1:] if len(parts) > 1 else []


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def virustotal_status() -> Dict[str, Any]:
    return {"configured": bool(VT_API_KEY)}


def _virustotal_lookup(sha256: str, timeout: float = 5.0) -> Dict[str, Any]:
    if not VT_API_KEY or not sha256:
        return {"checked": False, "verdict": "VirusTotal not configured"}
    try:
        import requests
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=timeout,
        )
        if resp.status_code == 404:
            return {"checked": True, "verdict": "Hash not found in VirusTotal"}
        if resp.status_code != 200:
            return {"checked": False, "verdict": f"VirusTotal lookup failed (HTTP {resp.status_code})"}
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious > 0:
            verdict = f"{malicious} engine(s) flagged this file as malicious"
        elif suspicious > 0:
            verdict = f"{suspicious} engine(s) flagged this file as suspicious"
        else:
            verdict = "No engines flagged this file"
        return {"checked": True, "verdict": verdict, "stats": stats}
    except Exception:
        return {"checked": False, "verdict": "VirusTotal lookup unavailable"}


def analyze_attachment(att: Dict[str, Any]) -> Dict[str, Any]:
    filename = att.get("filename", "unnamed_attachment")
    content_type = att.get("content_type", "application/octet-stream")
    size_bytes = att.get("size_bytes", 0)
    sha256 = att.get("sha256", "")

    exts = _extensions(filename)
    final_ext = exts[-1] if exts else ""

    indicators: List[str] = []

    if len(exts) >= 2:
        indicators.append(
            f"Double extension detected: '.{exts[-2]}.{exts[-1]}' "
            "(often used to disguise executables as documents)"
        )

    if final_ext in EXECUTABLE_EXTENSIONS:
        indicators.append(f"Executable file type (.{final_ext})")

    if final_ext in SCRIPT_EXTENSIONS:
        indicators.append(f"Script file type (.{final_ext})")

    if final_ext in MACRO_EXTENSIONS:
        indicators.append(f"Macro-enabled document (.{final_ext})")

    expected_prefix = EXPECTED_MIME_PREFIX.get(final_ext)
    if expected_prefix and not content_type.startswith(expected_prefix):
        indicators.append(
            f"MIME type mismatch: extension suggests '{expected_prefix}*' "
            f"but declared type is '{content_type}'"
        )

    if final_ext in ARCHIVE_EXTENSIONS:
        indicators.append(f"Archive file (.{final_ext}) - contents could not be inspected")

    if size_bytes == 0:
        indicators.append("Attachment has zero byte size (possibly corrupted or stripped)")

    n = len(indicators)
    if n == 0:
        risk = "Low"
    elif n <= 1:
        risk = "Medium"
    else:
        risk = "High"

    vt_result = _virustotal_lookup(sha256) if sha256 else {"checked": False, "verdict": "No hash available"}

    return {
        "filename": filename,
        "content_type": content_type,
        "size_human": _human_size(size_bytes),
        "size_bytes": size_bytes,
        "extension": final_ext,
        "sha256": sha256,
        "indicators": indicators,
        "risk": risk,
        "virustotal": vt_result,
    }


def analyze_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [analyze_attachment(a) for a in attachments]
