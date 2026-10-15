"""
AIR Blackbox Console - Scan API

Vercel serverless function that accepts a piece of code and returns
compliance findings from the air-blackbox SDK: EU AI Act articles 9-15,
GDPR, US state AI laws and (for hiring code) the US hiring checks.

POST /api/scan
Body: { "code": "...", "language": "kotlin" (optional), "filename": "Agent.kt" (optional) }
  language: python, notebook, typescript, javascript, java or kotlin;
  detected from the filename or the code when omitted.
Returns: { "score": 68, "articles": [...], "findings": [...], "meta": {...} }
"""

import json
import os
import re
import hashlib
import tempfile
import time
from dataclasses import dataclass, field
from typing import List
from http.server import BaseHTTPRequestHandler

import redis as redis_lib


# ============================================================
# Config & Redis
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")
KEY_PREFIX = "airbb_sk_"
FREE_TIER_SCANS = 25
MAX_CODE_SIZE = 512_000  # 500KB

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
# Auth helpers (same as detect.py and policy.py)
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


def _deduct_credit(key_hash):
    r = _get_redis()
    if not r:
        return -1
    try:
        new_val = r.decr(f"credits:{key_hash}")
        if new_val < 0:
            r.incr(f"credits:{key_hash}")
            return -1
        return new_val
    except Exception:
        return -1


def _get_credit_balance(key_hash):
    r = _get_redis()
    if not r:
        return 0
    try:
        val = r.get(f"credits:{key_hash}")
        return int(val) if val else 0
    except Exception:
        return 0


def _current_month():
    return time.strftime("%Y-%m", time.gmtime())


def _check_free_tier(client_ip):
    if not REDIS_URL:
        return {"allowed": True, "used": 0, "limit": FREE_TIER_SCANS, "fallback": True}
    r = _get_redis()
    if not r:
        return {"allowed": True, "used": 0, "limit": FREE_TIER_SCANS, "fallback": True}
    try:
        month = _current_month()
        raw = r.get(f"free:{client_ip}:{month}")
        current = int(raw) if raw else 0
        return {"allowed": current < FREE_TIER_SCANS, "used": current, "limit": FREE_TIER_SCANS}
    except Exception:
        return {"allowed": True, "used": 0, "limit": FREE_TIER_SCANS, "fallback": True}


def _increment_free_tier(client_ip):
    r = _get_redis()
    if not r:
        return 0
    try:
        month = _current_month()
        key = f"free:{client_ip}:{month}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 45 * 24 * 3600)
        return count
    except Exception:
        return 0


def _track_usage(key_hash):
    r = _get_redis()
    if not r:
        return 0
    try:
        month = _current_month()
        key = f"usage:{key_hash}:{month}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 90 * 24 * 3600)
        return count
    except Exception:
        return 0


# ============================================================
# Code Scanner: the air-blackbox SDK, not a copy of it
# ============================================================
# This file used to carry an "extracted" copy of the SDK's checks. It
# drifted: fewer checks, its own context rules, Python only, and a bug the
# SDK fixed (any chat app counted as a hiring system). The pasted code now
# goes through air_blackbox.compliance.snippet, the same path the CLI and the
# SDK's parity corpus use, so a paste gets the verdict the repository would.

from air_blackbox import __version__ as SDK_VERSION
from air_blackbox.compliance.snippet import LANGUAGE_ALIASES, scan_snippet

SUPPORTED_LANGUAGES = sorted(set(LANGUAGE_ALIASES.values()))

#: Group keys for findings outside EU AI Act articles 9-15. 16 is the
#: console's long-standing key for the US hiring checks.
ARTICLE_US_HIRING = 16
ARTICLE_GDPR = "GDPR"
ARTICLE_US_STATE = "US"


@dataclass
class CodeFinding:
    """A single compliance finding, as the console renders it."""
    article: object  # 9-15, 16 (US hiring), "GDPR" or "US"
    name: str
    status: str  # "pass", "warn", "fail"
    evidence: str
    detection: str = "auto"
    fix_hint: str = ""
    files: list = field(default_factory=list)
    severity: str = ""  # "high", "medium", "low" - set after scan

    def to_dict(self):
        return {
            "article": self.article,
            "name": self.name,
            "status": self.status,
            "evidence": self.evidence,
            "fix_hint": self.fix_hint,
            "severity": self.severity,
            "tier": "static",
            "detection": self.detection,
        }


def _severity(f: CodeFinding) -> str:
    """Same rule the console has always used; GDPR and US state-law groups
    take the medium/low branches."""
    if f.status == "fail":
        return "high" if f.article in (9, 12, 14, 15, 16) else "medium"
    if f.status == "warn":
        return "medium" if f.article in (9, 12, 16) else "low"
    return "low"


def findings_from_sdk(result: dict) -> List[CodeFinding]:
    """Flatten a scan_snippet result into console findings."""
    out = []
    for f in result["findings"]:
        if f["name"] == "Source files":
            continue  # only fires on an empty project; a snippet is one file
        article = ARTICLE_US_HIRING if f.get("framework") == "us_hiring" else f["article"]
        out.append(CodeFinding(article=article, name=f["name"], status=f["status"],
                               evidence=f["evidence"], detection=f.get("detection", "auto"),
                               fix_hint=f.get("fix_hint", "")))
    for f in result["gdpr"]:
        out.append(CodeFinding(article=ARTICLE_GDPR, name=f["name"], status=f["status"],
                               evidence=f["evidence"], fix_hint=f.get("fix_hint", "")))
    for f in result["us"]:
        out.append(CodeFinding(article=ARTICLE_US_STATE, name=f["name"], status=f["status"],
                               evidence=f["evidence"], fix_hint=f.get("fix_hint", "")))
    for f in out:
        f.severity = _severity(f)
    return out


def has_llm_calls(findings: List[CodeFinding]) -> bool:
    """The SDK says so in the error-handling check's evidence."""
    for f in findings:
        if f.name == "LLM call error handling":
            return not f.evidence.startswith("No direct LLM API calls")
    return False


def scan_code_string(code: str, language=None, filename=None) -> dict:
    """Scan pasted code with the SDK. Returns the SDK result plus console
    findings under "console_findings"."""
    result = scan_snippet(code, language=language, filename=filename)
    result["console_findings"] = findings_from_sdk(result)
    return result


# ============================================================
# Plain-English explanations
# ============================================================

EXPLANATIONS = {
    "LLM call error handling": {
        "fail": {
            "meaning": "Your code calls an LLM API (like OpenAI or Anthropic) without any error handling. If the API goes down, times out, or rate-limits you, your application will crash with an unhandled exception. Your users see a stack trace instead of a graceful error message.",
            "fix": "Wrap your LLM calls in try/except blocks. Catch specific errors like openai.APIError, openai.RateLimitError, and requests.Timeout. Return a friendly error to the user and log the failure for debugging.",
            "time": "15 minutes",
        },
        "pass": {
            "meaning": "Your code has error handling around LLM calls. This means API failures, timeouts, and rate limits are caught and handled gracefully instead of crashing your application.",
        },
    },
    "Retry and fallback logic": {
        "warn": {
            "meaning": "Your code doesn't have automatic retry logic for LLM calls. If an API call fails due to a temporary issue (network blip, rate limit), it fails permanently instead of retrying.",
            "fix": "Add the tenacity or backoff library for automatic retries with exponential backoff. This handles transient failures without you writing retry loops manually.",
            "time": "20 minutes",
        },
    },
    "PII handling in code": {
        "fail": {
            "meaning": "Your code sends data to LLMs without checking for personally identifiable information (PII) like email addresses, phone numbers, or social security numbers. This is a GDPR risk and an EU AI Act data governance gap. If user data leaks into model prompts, you may be processing personal data without proper safeguards.",
            "fix": "Add PII detection before sending prompts to the LLM. The AIR Gateway does this automatically, or you can use the presidio library for on-device PII scanning. Strip or redact PII before it reaches the model.",
            "time": "30 minutes with AIR Gateway, 1-2 hours with custom implementation",
        },
    },
    "Logging implementation": {
        "fail": {
            "meaning": "Your code has no logging. When something goes wrong in production, you have no record of what happened. The EU AI Act Article 12 requires that AI systems automatically log events so you can reconstruct what the system did and when.",
            "fix": "Add Python's built-in logging module. At minimum, log every LLM call with the model name, timestamp, and whether it succeeded or failed. For tamper-evident logging that satisfies Article 12, route calls through the AIR Gateway.",
            "time": "15 minutes for basic logging, 5 minutes for AIR Gateway setup",
        },
    },
    "Tracing / observability": {
        "fail": {
            "meaning": "Your code has no distributed tracing. In a multi-step AI pipeline, you can't see which step failed, how long each step took, or trace a user request through the full chain. Without observability, debugging production issues is guesswork.",
            "fix": "Add OpenTelemetry for distributed tracing, or LangSmith if you're using LangChain. This gives you a timeline view of every step in your AI pipeline with timing, errors, and token usage.",
            "time": "30 minutes for OpenTelemetry setup, 10 minutes for LangSmith",
        },
    },
    "Audit trail for AI actions": {
        "fail": {
            "meaning": "Your AI system has no tamper-evident audit trail. If a regulator asks 'what did your AI do on March 15th?', you cannot answer that question with verifiable evidence. EU AI Act Article 12 requires automatic recording of events that can be independently verified.",
            "fix": "Route your LLM calls through the AIR Gateway (one URL change) or add the AIR trust layer to your framework. This creates HMAC-SHA256 chained, ML-DSA-65 signed records of every AI action automatically. No code changes beyond swapping the base URL.",
            "time": "5 minutes with AIR Gateway",
        },
    },
    "Human-in-the-loop mechanism": {
        "fail": {
            "meaning": "Your AI agent can take actions (sending emails, making API calls, processing data) with no way for a human to intervene before execution. The EU AI Act Article 14 requires that humans can effectively oversee the AI system and intervene when necessary, including the ability to stop the system.",
            "fix": "Add air-gate to your pipeline. It intercepts agent actions, checks them against a YAML policy, and routes risky actions to a human approver via Slack before the AI executes them. Low-risk actions auto-approve; high-risk actions pause for human review.",
            "time": "15 minutes to set up air-gate with basic policy",
        },
    },
    "Prompt injection defense": {
        "fail": {
            "meaning": "Your code has no defense against prompt injection attacks. A malicious user could craft an input that overrides your system prompt and makes the AI behave in unintended ways -- leaking data, ignoring safety rules, or executing harmful actions.",
            "fix": "Add input sanitization or a guardrails library. The AIR Gateway includes a prompt injection scanner (20 patterns across 5 attack categories) that checks every prompt before it reaches the model. Or use NeMo Guardrails for custom rule-based filtering.",
            "time": "5 minutes with AIR Gateway, 1 hour with custom guardrails",
        },
    },
    "Code documentation (docstrings)": {
        "fail": {
            "meaning": "Most of your functions lack docstrings. For EU AI Act Article 11 (Technical Documentation), your codebase itself is part of the documentation. Undocumented AI logic makes it harder for auditors, teammates, and your future self to understand what the system does and why.",
            "fix": "Add docstrings to your key functions, especially those that handle AI logic, data processing, and decision-making. Focus on the 'why' not just the 'what'.",
            "time": "Variable, depending on codebase size",
        },
    },
    "Input validation": {
        "warn": {
            "meaning": "Your code doesn't use structured input validation (like pydantic models or JSON schema). Unvalidated inputs flowing into AI systems can cause unexpected behavior, data quality issues, and potential security vulnerabilities.",
            "fix": "Define pydantic models for your input data. This ensures data conforms to expected types and constraints before it reaches your AI logic.",
            "time": "30 minutes to add pydantic models for key inputs",
        },
    },
    "Output validation": {
        "warn": {
            "meaning": "Your code doesn't validate LLM outputs before acting on them. LLMs can produce malformed JSON, hallucinated data, or outputs that don't match your expected format. Acting on unvalidated output can cause downstream failures.",
            "fix": "Use pydantic output parsers or structured output modes (OpenAI's response_format, LangChain's PydanticOutputParser) to validate and parse LLM responses before acting on them.",
            "time": "20 minutes to add output parsing",
        },
    },
    "Illinois HB 3773: ZIP code as proxy": {
        "fail": {
            "meaning": "Your hiring AI uses ZIP or postal code as a feature in candidate scoring. Illinois HB 3773 (effective January 2026) prohibits AI hiring tools from using ZIP code as a proxy for race, ethnicity, or other protected characteristics. This applies to any employer using AI to evaluate candidates for positions in Illinois.",
            "fix": "Remove ZIP code from your scoring model's feature set. If ZIP is needed for logistics (work location eligibility), separate it from the scoring pipeline. If you keep it, you must conduct and document a statistical disparity analysis proving ZIP is not proxying for protected classes.",
            "time": "1-2 hours to audit feature pipeline and remove or isolate ZIP",
        },
        "warn": {
            "meaning": "ZIP or postal code is referenced in your hiring code but may not be used in scoring. Illinois HB 3773 prohibits using ZIP as a proxy for protected characteristics. Verify ZIP is not influencing candidate ranking.",
            "fix": "Audit your code to confirm ZIP code does not flow into any scoring, ranking, or filtering logic. Document the audit.",
            "time": "30 minutes to audit",
        },
    },
    "NYC LL144: Bias audit framework": {
        "fail": {
            "meaning": "Your hiring AI has no bias audit framework. NYC Local Law 144 (in effect since July 2023) requires any employer or employment agency using an automated employment decision tool (AEDT) in New York City to have an independent bias audit conducted within one year before use. The audit must calculate selection rates and impact ratios for race/ethnicity and sex categories.",
            "fix": "Integrate a fairness metrics library (fairlearn, aequitas, or AI Fairness 360) to calculate disparate impact ratios. You need: selection rate by race/ethnicity, selection rate by sex, and impact ratios (must pass the four-fifths rule: no group's selection rate below 80% of the highest group). Publish a summary of audit results on your website.",
            "time": "2-4 hours for initial fairness pipeline, plus annual independent auditor engagement",
        },
    },
    "California FEHA: Data retention": {
        "fail": {
            "meaning": "Your hiring AI has no data retention policy. California FEHA amendments require AI hiring vendors to retain all application materials, candidate evaluation data, and AI-generated recommendations for a minimum of 4 years. This protects candidates' ability to file discrimination complaints within the statute of limitations.",
            "fix": "Add a retention_policy configuration with a minimum 1460-day (4-year) retention period. Store: candidate data submitted, AI scores/rankings generated, model version used, features evaluated, and final recommendation. Use append-only storage or tamper-evident logs for auditability.",
            "time": "1-2 hours to add retention config and storage logic",
        },
    },
}



#: The SDK renamed some checks after these explanations were written.
LEGACY_EXPLANATION_NAMES = {
    "Input validation / schema enforcement": "Input validation",
    "Application logging": "Logging implementation",
    "LLM output validation": "Output validation",
    "Retry / backoff logic": "Retry and fallback logic",
    "Fallback/recovery patterns": "Retry and fallback logic",
    "Agent action audit trail": "Audit trail for AI actions",
    "Human-in-the-loop patterns": "Human-in-the-loop mechanism",
}


def _get_explanation(finding: CodeFinding) -> dict:
    """Get plain-English explanation for a finding."""
    key = LEGACY_EXPLANATION_NAMES.get(finding.name, finding.name)
    name_map = EXPLANATIONS.get(key, {})
    status_map = name_map.get(finding.status, {})
    return {
        "meaning": status_map.get("meaning", finding.evidence),
        "fix": status_map.get("fix", finding.fix_hint),
        "time_estimate": status_map.get("time", ""),
    }


# ============================================================
# Score calculation
# ============================================================

ARTICLE_NAMES = {
    9: "Risk Management",
    10: "Data Governance",
    11: "Technical Documentation",
    12: "Record-Keeping",
    14: "Human Oversight",
    15: "Accuracy, Robustness & Cybersecurity",
    16: "Hiring AI Compliance (US)",
    ARTICLE_GDPR: "GDPR Data Protection",
    ARTICLE_US_STATE: "US State AI Laws (CO, IL, CA, TX)",
}

ARTICLE_WEIGHTS = {9: 1.0, 10: 1.0, 11: 0.8, 12: 1.2, 14: 1.2, 15: 1.0, 16: 1.0,
                   ARTICLE_GDPR: 0.8, ARTICLE_US_STATE: 0.8}

_ARTICLE_ORDER = [9, 10, 11, 12, 14, 15, 16, ARTICLE_GDPR, ARTICLE_US_STATE]


def article_order(key) -> int:
    return _ARTICLE_ORDER.index(key) if key in _ARTICLE_ORDER else len(_ARTICLE_ORDER)


def calculate_score(findings: List[CodeFinding]) -> dict:
    """Calculate overall and per-article compliance scores."""
    by_article = {}
    for f in findings:
        by_article.setdefault(f.article, []).append(f)

    article_scores = {}
    for art_num, art_findings in by_article.items():
        total = len(art_findings)
        if total == 0:
            continue
        # pass=1.0, warn=0.5, fail=0.0
        score_sum = sum(
            1.0 if f.status == "pass" else 0.5 if f.status == "warn" else 0.0
            for f in art_findings
        )
        pct = int(score_sum / total * 100)
        passing = sum(1 for f in art_findings if f.status == "pass")
        warning = sum(1 for f in art_findings if f.status == "warn")
        failing = sum(1 for f in art_findings if f.status == "fail")
        article_scores[art_num] = {
            "number": art_num,
            "title": ARTICLE_NAMES.get(art_num, f"Article {art_num}"),
            "score": pct,
            "passing": passing,
            "warning": warning,
            "failing": failing,
            "total": total,
        }

    # Weighted overall score
    weighted_sum = 0
    weight_total = 0
    for art_num, data in article_scores.items():
        w = ARTICLE_WEIGHTS.get(art_num, 1.0)
        weighted_sum += data["score"] * w
        weight_total += w

    overall = int(weighted_sum / weight_total) if weight_total > 0 else 0

    return {
        "overall": overall,
        "articles": article_scores,
    }


# ============================================================
# HTTP Handler (Vercel serverless)
# ============================================================

class handler(BaseHTTPRequestHandler):
    """Vercel serverless function handler."""

    def do_POST(self):
        try:
            # Read body
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return self._error(400, "Request body is empty. Send JSON with a 'code' field.")
            if content_length > MAX_CODE_SIZE:
                return self._error(413, f"Code too large. Maximum size is {MAX_CODE_SIZE // 1024}KB.")

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._error(400, "Invalid JSON. Send: {\"code\": \"...your code...\"}")

            code = data.get("code", "")
            if not code or not code.strip():
                return self._error(400, "No code provided. Send JSON with a 'code' field containing your code.")
            language = data.get("language") or None
            filename = data.get("filename") or None
            if language and str(language).strip().lower() not in LANGUAGE_ALIASES:
                return self._error(400, "Unknown language. Use one of: " + ", ".join(SUPPORTED_LANGUAGES))
            if filename is not None and not isinstance(filename, str):
                return self._error(400, "filename must be a string")

            if len(code) > MAX_CODE_SIZE:
                return self._error(413, f"Code too large. Maximum size is {MAX_CODE_SIZE // 1024}KB.")

            # Auth & credits (same pattern as detect.py and policy.py)
            auth_header = self.headers.get("Authorization", "")
            api_key = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
            client_ip = self.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()

            auth_info = {}
            key_hash = None
            is_free = False
            if api_key:
                validation = _validate_api_key(api_key)
                if not validation["valid"]:
                    return self._error(401, f"Invalid API key: {validation['reason']}")

                key_hash = validation["key_hash"]
                credits = _get_credit_balance(key_hash)
                if credits <= 0:
                    return self._error(402, "No scan credits remaining. Buy more at /shadow-ai")

                auth_info = {
                    "authenticated": True,
                    "tier": validation["tier"],
                }
            else:
                free_check = _check_free_tier(client_ip)
                if not free_check["allowed"]:
                    return self._error(429,
                        f"Free tier limit reached ({FREE_TIER_SCANS}/month). Get an API key at /shadow-ai")
                is_free = True
                auth_info = {
                    "authenticated": False,
                    "tier": "free",
                    "scans_remaining": FREE_TIER_SCANS - free_check["used"] - 1,
                }

            # Run scan BEFORE deducting credits -- if scan errors, no charge
            start = time.time()
            result = scan_code_string(code, language=language, filename=filename)
            findings = result["console_findings"]
            scores = calculate_score(findings)

            # Scan succeeded -- NOW deduct credit / increment free tier
            if key_hash:
                remaining = _deduct_credit(key_hash)
                if remaining < 0:
                    return self._error(402, "No scan credits remaining.")
                _track_usage(key_hash)
                auth_info["credits_remaining"] = remaining
            elif is_free:
                _increment_free_tier(client_ip)
            duration_ms = int((time.time() - start) * 1000)

            # Build response
            frameworks = result["frameworks"]
            has_llm = has_llm_calls(findings)

            # Group findings by article for the frontend
            articles_out = []
            by_article = {}
            for f in findings:
                by_article.setdefault(f.article, []).append(f)

            for art_num in sorted(by_article.keys(), key=article_order):
                art_data = scores["articles"].get(art_num, {})
                articles_out.append({
                    "number": art_num,
                    "title": ARTICLE_NAMES.get(art_num, f"Article {art_num}"),
                    "score": art_data.get("score", 0),
                    "passing": art_data.get("passing", 0),
                    "warning": art_data.get("warning", 0),
                    "failing": art_data.get("failing", 0),
                })

            # Build findings list with explanations
            findings_out = []
            for f in findings:
                explanation = _get_explanation(f)
                findings_out.append({
                    "name": f.name,
                    "article": f.article,
                    "article_title": ARTICLE_NAMES.get(f.article, ""),
                    "status": f.status,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "meaning": explanation["meaning"],
                    "fix": explanation["fix"],
                    "time_estimate": explanation["time_estimate"],
                    "fix_hint": f.fix_hint,
                })

            # Sort: high severity first, then medium, then low
            severity_order = {"high": 0, "medium": 1, "low": 2}
            findings_out.sort(key=lambda x: severity_order.get(x["severity"], 3))

            response = {
                "score": scores["overall"],
                "articles": articles_out,
                "findings": findings_out,
                "meta": {
                    "scan_duration_ms": duration_ms,
                    "code_size_bytes": len(code),
                    "code_lines": code.count("\n") + 1,
                    "frameworks_detected": frameworks,
                    "has_llm_calls": has_llm,
                    "total_findings": len(findings),
                    "high_severity": sum(1 for f in findings if f.severity == "high"),
                    "medium_severity": sum(1 for f in findings if f.severity == "medium"),
                    "low_severity": sum(1 for f in findings if f.severity == "low"),
                    "language": result["language"],
                    "language_source": result["language_source"],
                    "scanner_version": SDK_VERSION,
                    "engine": "air-blackbox",
                },
                "auth": auth_info,
            }

            self._json_response(200, response)

        except Exception as e:
            self._error(500, f"Scan failed: {str(e)[:200]}")

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _error(self, status, message):
        self._json_response(status, {"error": message})

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
