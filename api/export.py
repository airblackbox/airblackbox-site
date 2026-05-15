"""
AIR Blackbox - Evidence Bundle Export API

POST /api/export
Body: { "scan_results": { ...scan output from /api/scan... } }
Auth: Bearer airbb_sk_... (requires Pro subscription or credits)

Returns: application/zip (.air-evidence bundle)

The evidence bundle contains:
  - scan-results.json   (raw scan data)
  - report.pdf          (professional compliance report)
  - manifest.json       (signed manifest with integrity hashes)

This is the PAID feature. Free users get JSON scan results.
Paid users get auditor-ready evidence bundles.
"""

import hashlib
import hmac as hmac_lib
import io
import json
import os
import secrets
import time
import zipfile
from http.server import BaseHTTPRequestHandler

import redis as redis_lib

# PDF generation
from fpdf import FPDF


# ============================================================
# Config & Redis
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")
HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
KEY_PREFIX = "airbb_sk_"
MAX_BODY_SIZE = 512_000  # 500KB

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        if not REDIS_URL:
            return None
        _redis_client = redis_lib.from_url(
            REDIS_URL, decode_responses=True,
            socket_timeout=5, socket_connect_timeout=5,
        )
    return _redis_client


# ============================================================
# Auth helpers
# ============================================================

def _validate_api_key(api_key):
    if not api_key or not api_key.startswith(KEY_PREFIX):
        return {"valid": False, "reason": "Invalid key format"}
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    r = _get_redis()
    if not r:
        return {"valid": False, "reason": "Service unavailable"}
    try:
        raw = r.get(f"apikey:{key_hash}")
    except Exception:
        return {"valid": False, "reason": "Service unavailable"}
    if not raw:
        return {"valid": False, "reason": "Key not found"}
    try:
        metadata = json.loads(raw)
    except json.JSONDecodeError:
        return {"valid": False, "reason": "Corrupted key data"}
    if not metadata.get("active", False):
        return {"valid": False, "reason": "Key has been revoked"}
    return {
        "valid": True,
        "email": metadata.get("email", ""),
        "tier": metadata.get("tier", "starter"),
        "key_hash": key_hash,
    }


def _get_credit_balance(key_hash):
    r = _get_redis()
    if not r:
        return 0
    try:
        bal = r.get(f"credits:{key_hash}")
        return int(bal) if bal else 0
    except Exception:
        return 0


def _deduct_credits(key_hash, amount=5):
    """Evidence bundle export costs 5 credits (vs 1 for a scan)."""
    r = _get_redis()
    if not r:
        return -1
    try:
        return r.decrby(f"credits:{key_hash}", amount)
    except Exception:
        return -1


# ============================================================
# Signing (same as policy.py)
# ============================================================

def _hmac_sha256(data_bytes):
    if not HMAC_SECRET:
        return "no-hmac-secret-configured"
    return hmac_lib.new(
        HMAC_SECRET.encode("utf-8"),
        data_bytes,
        hashlib.sha256,
    ).hexdigest()


def _hmac_sha512_sign(data_bytes, signing_key):
    return hmac_lib.new(
        signing_key,
        data_bytes,
        hashlib.sha512,
    ).hexdigest()


def sign_manifest(data):
    """Sign the manifest with HMAC-SHA512 + HMAC-SHA256 integrity."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    data_bytes = canonical.encode("utf-8")

    signing_key = secrets.token_bytes(64)
    signing_key_id = hashlib.sha256(signing_key).hexdigest()[:16]

    signature = _hmac_sha512_sign(data_bytes, signing_key)
    integrity = _hmac_sha256(data_bytes)

    evidence_id = f"airbb_ev_{secrets.token_hex(12)}"

    return {
        "evidence_id": evidence_id,
        "signed_data": data,
        "signature": f"HMAC-SHA512:{signature}",
        "signing_key_id": signing_key_id,
        "algorithm": "HMAC-SHA512 + HMAC-SHA256",
        "integrity_hash": f"HMAC-SHA256:{integrity}",
        "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verification_url": f"https://airblackbox.ai/verify/{evidence_id}",
    }


# ============================================================
# PDF Report Generator
# ============================================================

# Color palette
COLOR_DARK = (17, 24, 39)       # Near-black for text
COLOR_ACCENT = (234, 179, 8)    # AIR Blackbox yellow
COLOR_GREEN = (34, 197, 94)
COLOR_RED = (239, 68, 68)
COLOR_ORANGE = (249, 115, 22)
COLOR_GRAY = (107, 114, 128)
COLOR_LIGHT_BG = (249, 250, 251)
COLOR_WHITE = (255, 255, 255)


def _severity_color(severity):
    s = severity.lower()
    if s == "high":
        return COLOR_RED
    if s == "medium":
        return COLOR_ORANGE
    return COLOR_GRAY


def _score_color(score):
    if score >= 80:
        return COLOR_GREEN
    if score >= 60:
        return COLOR_ORANGE
    return COLOR_RED


def generate_pdf(scan_results):
    """Generate a professional compliance report PDF from scan results."""

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=25)

    score = scan_results.get("score", 0)
    articles = scan_results.get("articles", [])
    findings = scan_results.get("findings", [])
    meta = scan_results.get("meta", {})

    timestamp = time.strftime("%B %d, %Y at %H:%M UTC", time.gmtime())

    # ---- Cover Page ----
    pdf.add_page()

    # Yellow accent bar at top
    pdf.set_fill_color(*COLOR_ACCENT)
    pdf.rect(0, 0, 210, 8, "F")

    # Title block
    pdf.set_y(40)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(*COLOR_DARK)
    pdf.cell(0, 14, "EU AI Act", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 14, "Compliance Report", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(10)

    # Score circle (simulated with text)
    sc = _score_color(score)
    pdf.set_font("Helvetica", "B", 72)
    pdf.set_text_color(*sc)
    pdf.cell(0, 40, f"{score}", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*COLOR_GRAY)
    pdf.cell(0, 8, "Overall Compliance Score", new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(8)

    # Summary stats
    high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
    medium = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
    low = sum(1 for f in findings if f.get("severity", "").lower() == "low")

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(*COLOR_DARK)
    summary = f"{len(findings)} findings: {high} high, {medium} medium, {low} low"
    pdf.cell(0, 8, summary, new_x="LMARGIN", new_y="NEXT", align="C")

    pdf.ln(4)

    frameworks = meta.get("frameworks_detected", [])
    if frameworks:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*COLOR_GRAY)
        pdf.cell(0, 6, f"Frameworks detected: {', '.join(frameworks)}", new_x="LMARGIN", new_y="NEXT", align="C")

    # Footer info on cover
    pdf.set_y(250)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*COLOR_GRAY)
    pdf.cell(0, 5, f"Generated: {timestamp}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 5, f"Scanner: AIR Blackbox v{meta.get('scanner_version', '1.0.0')}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 5, "https://airblackbox.ai", new_x="LMARGIN", new_y="NEXT", align="C")

    # ---- Article Scores Page ----
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*COLOR_DARK)
    pdf.cell(0, 12, "Article-by-Article Scores", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Table header
    pdf.set_fill_color(*COLOR_DARK)
    pdf.set_text_color(*COLOR_WHITE)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(20, 8, "Art.", fill=True, align="C")
    pdf.cell(70, 8, "Requirement", fill=True)
    pdf.cell(25, 8, "Score", fill=True, align="C")
    pdf.cell(25, 8, "Passing", fill=True, align="C")
    pdf.cell(25, 8, "Warning", fill=True, align="C")
    pdf.cell(25, 8, "Failing", fill=True, align="C")
    pdf.ln()

    pdf.set_text_color(*COLOR_DARK)
    pdf.set_font("Helvetica", "", 10)

    for i, art in enumerate(articles):
        bg = COLOR_LIGHT_BG if i % 2 == 0 else COLOR_WHITE
        pdf.set_fill_color(*bg)

        art_score = art.get("score", 0)
        sc = _score_color(art_score)

        pdf.cell(20, 7, str(art.get("number", "")), fill=True, align="C")
        pdf.cell(70, 7, str(art.get("title", ""))[:35], fill=True)

        # Score cell in color
        pdf.set_text_color(*sc)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(25, 7, f"{art_score}%", fill=True, align="C")

        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(25, 7, str(art.get("passing", 0)), fill=True, align="C")
        pdf.cell(25, 7, str(art.get("warning", 0)), fill=True, align="C")
        pdf.cell(25, 7, str(art.get("failing", 0)), fill=True, align="C")
        pdf.ln()

    pdf.ln(8)

    # EU AI Act reference
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*COLOR_GRAY)
    pdf.multi_cell(0, 5,
        "Articles 9-15 of EU Regulation 2024/1689 (EU AI Act) define technical "
        "requirements for high-risk AI systems. Enforcement date: August 2, 2026. "
        "Penalties: up to EUR 35M or 7% of global annual turnover."
    )

    # ---- Findings Page(s) ----
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*COLOR_DARK)
    pdf.cell(0, 12, "Compliance Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    if not findings:
        pdf.set_font("Helvetica", "", 12)
        pdf.set_text_color(*COLOR_GREEN)
        pdf.cell(0, 10, "No compliance findings detected.", new_x="LMARGIN", new_y="NEXT")
    else:
        for idx, f in enumerate(findings):
            # Check if we need a new page (leave room for the finding block)
            if pdf.get_y() > 240:
                pdf.add_page()

            severity = f.get("severity", "low").upper()
            sev_color = _severity_color(severity)

            # Finding header
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*sev_color)
            pdf.cell(0, 7,
                f"[{severity}] {f.get('name', 'Unknown')}",
                new_x="LMARGIN", new_y="NEXT",
            )

            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*COLOR_GRAY)
            art_title = f.get("article_title", "")
            art_num = f.get("article", "")
            pdf.cell(0, 5,
                f"Article {art_num} - {art_title}",
                new_x="LMARGIN", new_y="NEXT",
            )

            # Evidence
            evidence = f.get("evidence", "")
            if evidence:
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(*COLOR_DARK)
                pdf.set_x(15)
                pdf.multi_cell(180, 4.5, f"Evidence: {evidence[:300]}")

            # Fix guidance
            fix = f.get("fix", "") or f.get("fix_hint", "")
            if fix:
                pdf.set_font("Helvetica", "I", 9)
                pdf.set_text_color(180, 140, 10)
                pdf.set_x(15)
                pdf.multi_cell(180, 4.5, f"Recommendation: {fix[:300]}")

            pdf.ln(4)

    # ---- Verification Page ----
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*COLOR_DARK)
    pdf.cell(0, 12, "Verification & Integrity", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*COLOR_DARK)
    pdf.multi_cell(0, 5,
        "This report is part of a signed evidence bundle (.air-evidence). "
        "The bundle contains a cryptographic manifest that can be independently "
        "verified to confirm the scan results have not been tampered with."
    )
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*COLOR_GRAY)
    info_lines = [
        f"Report generated: {timestamp}",
        f"Scanner version: {meta.get('scanner_version', '1.0.0')}",
        f"Code size: {meta.get('code_lines', 'N/A')} lines ({meta.get('code_size_bytes', 'N/A')} bytes)",
        f"Scan duration: {meta.get('scan_duration_ms', 'N/A')}ms",
        "Signing algorithm: HMAC-SHA512 + HMAC-SHA256",
        "",
        "To verify this bundle:",
        "  1. Extract the .air-evidence ZIP",
        "  2. Check manifest.json contains the same scan-results.json hash",
        "  3. Verify the HMAC-SHA256 integrity hash matches",
        "  4. Or visit the verification URL in manifest.json",
    ]
    for line in info_lines:
        pdf.cell(0, 5, line, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)

    # Disclaimer
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*COLOR_GRAY)
    pdf.multi_cell(0, 4,
        "Disclaimer: This report checks technical requirements mapped to EU AI Act "
        "Articles 9, 10, 11, 12, 14, and 15 using automated static analysis. "
        "It does not constitute legal advice or guarantee regulatory compliance. "
        "Consult qualified legal counsel for compliance determinations."
    )

    # Bottom bar
    pdf.set_fill_color(*COLOR_ACCENT)
    pdf.rect(0, 289, 210, 8, "F")

    return pdf.output()


# ============================================================
# Bundle Packager
# ============================================================

def build_evidence_bundle(scan_results):
    """
    Build a signed .air-evidence bundle (ZIP) containing:
      - scan-results.json
      - report.pdf
      - manifest.json (signed)
    """

    # 1. Generate the PDF report
    pdf_bytes = generate_pdf(scan_results)

    # 2. Prepare scan results JSON (canonical)
    scan_json = json.dumps(scan_results, indent=2, sort_keys=True)
    scan_bytes = scan_json.encode("utf-8")

    # 3. Build manifest with file hashes
    manifest_data = {
        "bundle_version": "1.0.0",
        "generator": "airblackbox-export",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": {
            "scan-results.json": {
                "sha256": hashlib.sha256(scan_bytes).hexdigest(),
                "size_bytes": len(scan_bytes),
            },
            "report.pdf": {
                "sha256": hashlib.sha256(pdf_bytes).hexdigest(),
                "size_bytes": len(pdf_bytes),
            },
        },
        "scan_summary": {
            "score": scan_results.get("score", 0),
            "total_findings": len(scan_results.get("findings", [])),
            "high_findings": sum(
                1 for f in scan_results.get("findings", [])
                if f.get("severity", "").lower() == "high"
            ),
            "frameworks_checked": ["eu-ai-act"],
            "scanner_version": scan_results.get("meta", {}).get("scanner_version", "1.0.0"),
        },
    }

    # 4. Sign the manifest
    signed_manifest = sign_manifest(manifest_data)
    manifest_json = json.dumps(signed_manifest, indent=2)
    manifest_bytes = manifest_json.encode("utf-8")

    # 5. Package into ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("scan-results.json", scan_json)
        zf.writestr("report.pdf", pdf_bytes)
        zf.writestr("manifest.json", manifest_json)

    return zip_buffer.getvalue(), signed_manifest.get("evidence_id", "unknown")


# ============================================================
# HTTP Handler
# ============================================================

class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        try:
            # Read body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return self._error(400, "Request body is empty.")
            if content_length > MAX_BODY_SIZE:
                return self._error(413, "Request too large.")

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._error(400, "Invalid JSON.")

            scan_results = data.get("scan_results")
            if not scan_results or not isinstance(scan_results, dict):
                return self._error(400,
                    "Missing 'scan_results' field. Send the full output from /api/scan.")

            # Validate scan_results has required fields
            if "score" not in scan_results or "findings" not in scan_results:
                return self._error(400,
                    "Invalid scan_results. Must contain 'score' and 'findings'.")

            # ---- Auth: require API key with credits ----
            auth_header = self.headers.get("Authorization", "")
            api_key = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""

            if not api_key:
                return self._error(401,
                    "Evidence bundle export requires an API key. "
                    "Get one at https://airblackbox.ai/shadow-ai")

            validation = _validate_api_key(api_key)
            if not validation["valid"]:
                return self._error(401, f"Invalid API key: {validation['reason']}")

            key_hash = validation["key_hash"]
            credits = _get_credit_balance(key_hash)
            if credits < 5:
                return self._error(402,
                    "Evidence bundle export requires 5 credits. "
                    f"You have {credits}. Buy more at https://airblackbox.ai/shadow-ai")

            # ---- Generate bundle BEFORE deducting credits ----
            bundle_bytes, evidence_id = build_evidence_bundle(scan_results)

            # ---- Bundle generated successfully, NOW deduct credits ----
            remaining = _deduct_credits(key_hash, 5)
            if remaining < 0:
                return self._error(402, "Credit deduction failed.")

            # ---- Return ZIP ----
            filename = f"air-evidence-{evidence_id}.zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(bundle_bytes)))
            self.send_header("X-Evidence-ID", evidence_id)
            self.send_header("X-Credits-Remaining", str(remaining))
            self._cors_headers()
            self.end_headers()
            self.wfile.write(bundle_bytes)

        except Exception as e:
            self._error(500, f"Export failed: {str(e)[:200]}")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "https://airblackbox.ai")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _error(self, status, message):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode("utf-8"))
