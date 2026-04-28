"""
AIR Blackbox Console — Scan API

Vercel serverless function that accepts Python code and returns
EU AI Act compliance findings. Uses the code scanner from the
air-blackbox package (stdlib only, no external deps needed).

POST /api/scan
Body: { "code": "...python code..." }
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


# ============================================================
# Rate limiting (in-memory, resets on cold start)
# Production: replace with Vercel KV or Redis
# ============================================================
_SCAN_LOG = {}  # ip -> [timestamp, ...]
FREE_SCANS_PER_MONTH = 3  # generous for beta
RATE_WINDOW = 30 * 24 * 3600  # 30 days in seconds
MAX_CODE_SIZE = 512_000  # 500KB


# ============================================================
# Code Scanner (extracted from air_blackbox.compliance.code_scanner)
# All stdlib — zero external dependencies
# ============================================================

@dataclass
class CodeFinding:
    """A single compliance finding from code analysis."""
    article: int
    name: str
    status: str  # "pass", "warn", "fail"
    evidence: str
    detection: str = "auto"
    fix_hint: str = ""
    files: list = field(default_factory=list)
    severity: str = ""  # "high", "medium", "low" — set after scan

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


# --- Pattern detection functions ---

# LLM call patterns
LLM_CALL_PATTERNS = [
    r"\.chat\.completions\.create\(",
    r"\.completions\.create\(",
    r"\.generate\(",
    r"ChatOpenAI\(",
    r"OpenAI\(",
    r"Anthropic\(",
    r"client\.messages\.create\(",
    r"llm\.invoke\(",
    r"chain\.invoke\(",
    r"agent\.invoke\(",
    r"crew\.kickoff\(",
    r"agent\.run\(",
]

FRAMEWORK_PATTERNS = {
    "langchain": [r"from langchain", r"import langchain", r"ChatOpenAI\(", r"LLMChain\("],
    "crewai": [r"from crewai", r"import crewai", r"Agent\(", r"Crew\("],
    "openai": [r"from openai", r"import openai", r"OpenAI\("],
    "anthropic": [r"from anthropic", r"import anthropic", r"Anthropic\("],
    "autogen": [r"from autogen", r"import autogen"],
    "haystack": [r"from haystack", r"import haystack"],
    "google_adk": [r"from google.adk", r"from google_adk", r"from vertexai"],
}

ERROR_HANDLING_PATTERNS = [
    r"try:\s*\n\s*.*(?:chat|completions|generate|invoke|create|run|kickoff)",
    r"except\s+(?:Exception|openai\.\w+Error|anthropic\.\w+Error|requests\.exceptions)",
]

LOGGING_PATTERNS = [
    r"logging\.getLogger",
    r"logging\.basicConfig",
    r"logger\s*=\s*logging\.getLogger",
    r"structlog",
    r"logging\.(?:debug|info|warning|error|critical)\(",
]

TRACING_PATTERNS = [
    r"from opentelemetry",
    r"trace\.get_tracer",
    r"tracer\.start_span",
    r"from langsmith",
    r"LangSmithCallbackHandler",
    r"from llama_index\.core\.instrumentation",
    r"dispatcher\.add_event_handler",
]

HITL_PATTERNS = [
    r"human_in_the_loop",
    r"require_approval",
    r"approval_required",
    r"human_review",
    r"confirmation_strategy",
    r"interrupt_before",
    r"air_gate",
    r"GateClient",
]

INPUT_VALIDATION_PATTERNS = [
    r"field_validator",
    r"json_schema",
    r"jsonschema\.validate",
]

# These patterns only count as input validation if LLM calls
# are also present in the code. A Pydantic BaseModel for a
# database schema is NOT AI input validation.
INPUT_VALIDATION_LLM_CONTEXT_PATTERNS = [
    r"pydantic",
    r"BaseModel",
    r"Field\(",
    r"validator\(",
]

OUTPUT_VALIDATION_PATTERNS = [
    r"output_pydantic",
    r"expected_output",
    r"OutputParser",
    r"PydanticOutputParser",
    r"JsonOutputParser",
    r"response_model",
]

PII_PATTERNS = [
    r"pii_detect",
    r"redact.*(?:pii|ssn|email|phone|name|address|personal)",
    r"anonymize.*(?:data|user|pii|record)",
    r"mask_pii",
    r"detect_pii",
    r"scrub_pii",
    r"presidio",
    r"from air_blackbox\.injection",
    r"(?:pii|personal).*(?:redact|filter|remove|strip|mask)",
]

INJECTION_DEFENSE_PATTERNS = [
    r"guardrail",
    r"hallucination_guardrail",
    r"content_filter",
    r"prompt_guard",
    r"NeMoGuardrails",
    r"from nemoguardrails",
    r"sanitize.*prompt",
    r"sanitize.*llm",
    r"prompt.*injection",
    r"prompt.*sanitiz",
    r"input.*filter.*(?:llm|prompt|model|agent)",
]

RETRY_PATTERNS = [
    r"@retry",
    r"tenacity",
    r"backoff",
    r"max_retries",
    r"retry_on_exception",
    r"Retry\(",
]

RATE_LIMIT_PATTERNS = [
    r"rate_limit",
    r"throttle",
    r"RateLimiter",
    r"max_requests_per",
    r"token_bucket",
]

AUDIT_TRAIL_PATTERNS = [
    r"audit_log\s*[\.\(=]",
    r"audit_trail\s*[\.\(=]",
    r"event_log\s*[\.\(=]",
    r"emit_event\s*\(",
    r"agent_events",
    r"crew_events",
    r"from air_blackbox",
    r"air_blackbox\.\w+\(",
    r"\.air\.json",
    r"GateClient\(",
]

DOC_PATTERNS = {
    "risk_assessment": ["RISK_ASSESSMENT.md", "risk_assessment.md", "RISK_MANAGEMENT.md"],
    "data_governance": ["DATA_GOVERNANCE.md", "data_governance.md"],
    "model_card": ["MODEL_CARD.md", "model_card.md", "SYSTEM_CARD.md"],
    "readme": ["README.md", "readme.md"],
    "operator_guide": ["OPERATOR_GUIDE.md", "RUNBOOK.md"],
    "redteam": ["REDTEAM.md", "ADVERSARIAL_TESTING.md"],
}


def _detect_patterns(code: str, patterns: list) -> list:
    """Return list of patterns that match anywhere in the code."""
    found = []
    for p in patterns:
        if re.search(p, code, re.MULTILINE | re.IGNORECASE):
            found.append(p)
    return found


# ============================================================
# Context-aware pattern matching
# Prevents false positives by checking surrounding code context
# before flagging a match. A pattern only counts if it appears
# in a relevant context, not just anywhere in the file.
# ============================================================

# Lines within this window of a match are checked for context.
# 15 lines covers most function/class bodies where a pattern
# might appear far from its framework constructor.
_CONTEXT_WINDOW = 15

# Patterns that look like compliance features but are often
# something else entirely. Each entry maps a trigger pattern
# to a list of nearby-context patterns that CANCEL the match
# (i.e., if the context pattern is found near the trigger,
# the trigger is a false positive and should be skipped).
CONTEXT_EXCLUSIONS = {
    # allow_delegation=True in CrewAI is agent-to-agent delegation,
    # NOT human oversight. Only count it if there is NO CrewAI
    # Agent/Task constructor nearby.
    r"allow_delegation\s*=\s*True": [
        r"Agent\(",
        r"Task\(",
        r"from crewai",
        r"import crewai",
    ],
    # max_age in config is almost always cache TTL, not token
    # revocation. Skip if near cache/config/TTL context.
    r"max_age": [
        r"cache",
        r"ttl",
        r"Cache-Control",
        r"max_age\s*=\s*\d+",
        r"config",
        r"session",
    ],
    # user_id in telemetry/logging/analytics is not OAuth
    # delegation. Skip if near analytics/telemetry context.
    r"user_id": [
        r"telemetry",
        r"analytics",
        r"log",
        r"metric",
        r"event_track",
        r"stats",
    ],
}


def _get_line_context(code: str, match_pos: int, window: int = _CONTEXT_WINDOW) -> str:
    """Get surrounding lines around a match position for context checking."""
    lines = code.split("\n")
    char_count = 0
    match_line = 0
    for i, line in enumerate(lines):
        char_count += len(line) + 1  # +1 for newline
        if char_count > match_pos:
            match_line = i
            break
    start = max(0, match_line - window)
    end = min(len(lines), match_line + window + 1)
    return "\n".join(lines[start:end])


def _detect_with_context(code: str, pattern: str) -> bool:
    """
    Check if a pattern matches in the code, but filter out false
    positives by checking surrounding context. Returns True only
    if the match appears in a relevant (non-excluded) context.
    """
    if pattern not in CONTEXT_EXCLUSIONS:
        # No exclusion rules for this pattern, use simple match
        return bool(re.search(pattern, code, re.MULTILINE | re.IGNORECASE))

    exclusion_patterns = CONTEXT_EXCLUSIONS[pattern]
    matches = list(re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE))
    if not matches:
        return False

    # Check each match location -- if ANY match is in a valid
    # (non-excluded) context, the pattern counts as found
    for m in matches:
        context = _get_line_context(code, m.start())
        excluded = False
        for exc in exclusion_patterns:
            if re.search(exc, context, re.IGNORECASE):
                excluded = True
                break
        if not excluded:
            # Found a match that is NOT in an excluded context
            return True

    # All matches were in excluded contexts -- false positive
    return False


def _detect_frameworks(code: str) -> list:
    """Detect which AI frameworks are used in the code."""
    detected = []
    for fw, patterns in FRAMEWORK_PATTERNS.items():
        for p in patterns:
            if re.search(p, code):
                detected.append(fw)
                break
    return detected


def _has_llm_calls(code: str) -> bool:
    """Check if the code contains any LLM API calls."""
    for p in LLM_CALL_PATTERNS:
        if re.search(p, code):
            return True
    return False


# ============================================================
# Hiring AI Compliance (US jurisdictions)
# These checks only fire when hiring/employment AI context is
# detected in the code. No false positives on general-purpose code.
# ============================================================

HIRING_CONTEXT_PATTERNS = [
    r"candidate", r"applicant", r"hiring", r"screening",
    r"resume", r"interview", r"recruitment", r"job_posting",
    r"job_application", r"talent_acquisition", r"ats\b",
    r"applicant_tracking", r"shortlist", r"reject.*candidate",
    r"rank.*candidate", r"score.*candidate", r"evaluate.*candidate",
]

# Illinois HB 3773: ZIP code used as proxy for protected characteristics
ZIP_PROXY_PATTERNS = [
    r"zip_code", r"zipcode", r"zip_prefix", r"postal_code",
    r"zip\s*[\[=]",  # zip used as variable/key, not the built-in function
]

ZIP_SCORING_CONTEXT = [
    r"score", r"rank", r"weight", r"predict", r"feature",
    r"model\.", r"classifier", r"decision", r"filter",
]

# NYC Local Law 144: Bias audit requirement for AEDT
BIAS_AUDIT_PATTERNS = [
    r"bias_audit", r"disparate_impact", r"adverse_impact",
    r"four_fifths_rule", r"selection_rate", r"demographic_parity",
    r"impact_ratio", r"fairness_metric", r"protected_class",
    r"equal_opportunity", r"statistical_parity",
    r"aequitas", r"fairlearn", r"ai_fairness_360",
]

# California FEHA: 4-year data retention for hiring AI decisions
RETENTION_PATTERNS = [
    r"retention_period", r"retention_policy", r"data_retention",
    r"record_retention", r"archive.*(?:year|day|month)",
    r"retention.*(?:year|day|month)", r"keep.*record.*(?:year|day)",
    r"(?:1460|1461)\s*day", r"4\s*year.*retain", r"retain.*4\s*year",
    r"purge_after", r"ttl.*(?:year|day)",
]


def _has_hiring_context(code: str) -> bool:
    """Check if code is related to hiring/employment AI."""
    matches = 0
    for p in HIRING_CONTEXT_PATTERNS:
        if re.search(p, code, re.IGNORECASE):
            matches += 1
            if matches >= 2:  # require at least 2 hiring signals
                return True
    return False


def scan_code_string(code: str) -> List[CodeFinding]:
    """
    Scan a code string for EU AI Act compliance patterns.
    Returns a list of findings grouped by article.
    """
    findings = []
    has_llm = _has_llm_calls(code)
    frameworks = _detect_frameworks(code)

    # --- Article 9: Risk Management ---
    # Check for error handling around LLM calls
    eh = _detect_patterns(code, ERROR_HANDLING_PATTERNS)
    if has_llm:
        if eh:
            findings.append(CodeFinding(
                article=9, name="LLM call error handling", status="pass",
                evidence=f"Error handling found around LLM calls",
                fix_hint=""))
        else:
            findings.append(CodeFinding(
                article=9, name="LLM call error handling", status="fail",
                evidence="LLM calls detected without try/except error handling",
                fix_hint="Wrap LLM calls in try/except blocks to handle API errors, timeouts, and rate limits gracefully"))

    # Retry logic
    retries = _detect_patterns(code, RETRY_PATTERNS)
    if has_llm:
        findings.append(CodeFinding(
            article=9, name="Retry and fallback logic", status="pass" if retries else "warn",
            evidence="Retry/fallback patterns detected" if retries else "No retry logic found for LLM calls",
            fix_hint="" if retries else "Add retry logic with exponential backoff (e.g., tenacity or backoff library)"))

    # Rate limiting
    rl = _detect_patterns(code, RATE_LIMIT_PATTERNS)
    findings.append(CodeFinding(
        article=9, name="Rate limiting", status="pass" if rl else "warn",
        evidence="Rate limiting patterns detected" if rl else "No rate limiting found",
        fix_hint="" if rl else "Add rate limiting to prevent abuse and control costs"))

    # --- Article 10: Data Governance ---
    # PII handling
    pii = _detect_patterns(code, PII_PATTERNS)
    findings.append(CodeFinding(
        article=10, name="PII handling in code", status="pass" if pii else "fail",
        evidence="PII detection/redaction patterns found" if pii else "No PII handling detected in code",
        fix_hint="" if pii else "Add PII detection and redaction before sending data to LLMs (e.g., presidio, or AIR Gateway PII scanner)"))

    # Input validation
    # Strong patterns (jsonschema, field_validator) always count.
    # Weak patterns (BaseModel, Field) only count if LLM calls
    # are also present -- a BaseModel for a database schema is
    # NOT AI input validation.
    iv = _detect_patterns(code, INPUT_VALIDATION_PATTERNS)
    if not iv and has_llm:
        iv = _detect_patterns(code, INPUT_VALIDATION_LLM_CONTEXT_PATTERNS)
    findings.append(CodeFinding(
        article=10, name="Input validation", status="pass" if iv else "warn",
        evidence="Input validation patterns detected (pydantic/schema)" if iv else "No structured input validation found",
        fix_hint="" if iv else "Use pydantic or jsonschema to validate inputs before processing"))

    # --- Article 11: Technical Documentation ---
    # Docstrings
    docstring_count = len(re.findall(r'"""[\s\S]*?"""', code))
    total_functions = len(re.findall(r'def\s+\w+', code))
    if total_functions > 0:
        ratio = docstring_count / total_functions
        findings.append(CodeFinding(
            article=11, name="Code documentation (docstrings)",
            status="pass" if ratio > 0.5 else "warn" if ratio > 0.2 else "fail",
            evidence=f"{docstring_count}/{total_functions} functions have docstrings ({ratio*100:.0f}%)",
            fix_hint="" if ratio > 0.5 else "Add docstrings to functions, especially those handling AI logic"))

    # Type hints
    typed_funcs = len(re.findall(r'def\s+\w+\([^)]*:\s*\w+', code))
    if total_functions > 0:
        type_ratio = typed_funcs / total_functions
        findings.append(CodeFinding(
            article=11, name="Type annotations",
            status="pass" if type_ratio > 0.5 else "warn" if type_ratio > 0.2 else "fail",
            evidence=f"{typed_funcs}/{total_functions} functions have type hints ({type_ratio*100:.0f}%)",
            fix_hint="" if type_ratio > 0.5 else "Add type hints to function signatures for better documentation and safety"))

    # --- Article 12: Record-Keeping ---
    # Logging
    logs = _detect_patterns(code, LOGGING_PATTERNS)
    findings.append(CodeFinding(
        article=12, name="Logging implementation", status="pass" if logs else "fail",
        evidence="Logging framework detected" if logs else "No logging detected in code",
        fix_hint="" if logs else "Add Python logging to record AI system events (import logging)"))

    # Tracing / observability
    tracing = _detect_patterns(code, TRACING_PATTERNS)
    findings.append(CodeFinding(
        article=12, name="Tracing / observability", status="pass" if tracing else "fail",
        evidence="Tracing/observability patterns detected" if tracing else "No tracing or observability framework found",
        fix_hint="" if tracing else "Add OpenTelemetry or LangSmith for distributed tracing of AI calls"))

    # Audit trail
    audit = _detect_patterns(code, AUDIT_TRAIL_PATTERNS)
    findings.append(CodeFinding(
        article=12, name="Audit trail for AI actions", status="pass" if audit else "fail",
        evidence="Audit trail patterns detected" if audit else "No tamper-evident audit trail for AI actions",
        fix_hint="" if audit else "Route calls through AIR Gateway or add air-blackbox trust layer for signed audit records"))

    # --- Article 14: Human Oversight ---
    hitl = _detect_patterns(code, HITL_PATTERNS)
    # Context-aware check: allow_delegation=True only counts as
    # human oversight if it's NOT inside a CrewAI Agent/Task
    # constructor (where it means agent-to-agent delegation)
    if not hitl and _detect_with_context(code, r"allow_delegation\s*=\s*True"):
        hitl = [r"allow_delegation\s*=\s*True"]
    findings.append(CodeFinding(
        article=14, name="Human-in-the-loop mechanism", status="pass" if hitl else "fail",
        evidence="Human oversight patterns detected" if hitl else "No human-in-the-loop mechanism found",
        fix_hint="" if hitl else "Add human approval gates for high-risk actions (e.g., air-gate for Slack-based approvals)"))

    # --- Article 15: Robustness ---
    # Injection defense
    inj = _detect_patterns(code, INJECTION_DEFENSE_PATTERNS)
    findings.append(CodeFinding(
        article=15, name="Prompt injection defense", status="pass" if inj else "fail",
        evidence="Injection defense patterns detected" if inj else "No prompt injection defense found",
        fix_hint="" if inj else "Add input sanitization or guardrails to prevent prompt injection attacks"))

    # Output validation
    ov = _detect_patterns(code, OUTPUT_VALIDATION_PATTERNS)
    findings.append(CodeFinding(
        article=15, name="Output validation", status="pass" if ov else "warn",
        evidence="Output validation patterns detected" if ov else "No structured output validation found",
        fix_hint="" if ov else "Validate LLM outputs with pydantic models or output parsers before acting on them"))

    # --- Article 16: Hiring AI Compliance (US) ---
    # These checks only fire when the code looks like a hiring/employment AI system.
    # No false positives on general-purpose code.
    is_hiring = _has_hiring_context(code)
    if is_hiring:
        # Illinois HB 3773: ZIP code as proxy for protected characteristics
        zip_found = _detect_patterns(code, ZIP_PROXY_PATTERNS)
        zip_in_scoring = False
        if zip_found:
            # Only flag if ZIP is used in a scoring/ranking/prediction context
            zip_in_scoring = bool(_detect_patterns(code, ZIP_SCORING_CONTEXT))
        if zip_found and zip_in_scoring:
            findings.append(CodeFinding(
                article=16, name="Illinois HB 3773: ZIP code as proxy",
                status="fail",
                evidence="ZIP/postal code used as a feature in candidate scoring or ranking. Illinois HB 3773 prohibits using ZIP code as a proxy for protected characteristics in AI hiring decisions.",
                fix_hint="Remove ZIP code from scoring features or add a documented disparity analysis showing ZIP is not proxying for race, ethnicity, or other protected classes"))
        elif zip_found:
            findings.append(CodeFinding(
                article=16, name="Illinois HB 3773: ZIP code as proxy",
                status="warn",
                evidence="ZIP/postal code referenced in hiring context. Verify it is not used as a scoring feature.",
                fix_hint="Audit whether ZIP code influences candidate ranking. If it does, remove it or document a disparity analysis"))
        else:
            findings.append(CodeFinding(
                article=16, name="Illinois HB 3773: ZIP code as proxy",
                status="pass",
                evidence="No ZIP/postal code usage detected in hiring scoring context"))

        # NYC Local Law 144: Bias audit for automated employment decision tools
        bias_audit = _detect_patterns(code, BIAS_AUDIT_PATTERNS)
        if bias_audit:
            findings.append(CodeFinding(
                article=16, name="NYC LL144: Bias audit framework",
                status="pass",
                evidence="Bias audit or fairness metrics detected in hiring AI code",
                fix_hint=""))
        else:
            findings.append(CodeFinding(
                article=16, name="NYC LL144: Bias audit framework",
                status="fail",
                evidence="No bias audit framework detected. NYC Local Law 144 requires an annual bias audit by an independent auditor for any automated employment decision tool (AEDT) used in NYC.",
                fix_hint="Add bias auditing with disparate impact analysis (e.g., fairlearn, aequitas, or AI Fairness 360). Must calculate selection rates and impact ratios across race/ethnicity and sex categories"))

        # California FEHA: 4-year data retention for hiring AI decisions
        retention = _detect_patterns(code, RETENTION_PATTERNS)
        if retention:
            findings.append(CodeFinding(
                article=16, name="California FEHA: Data retention",
                status="pass",
                evidence="Data retention policy detected in hiring AI code",
                fix_hint=""))
        else:
            findings.append(CodeFinding(
                article=16, name="California FEHA: Data retention",
                status="fail",
                evidence="No data retention policy detected. California FEHA amendments require AI hiring vendors to retain application and decision data for a minimum of 4 years.",
                fix_hint="Add a retention_policy config with a minimum 4-year (1460-day) retention period for all candidate evaluation data and AI-generated recommendations"))

    # Assign severity
    for f in findings:
        if f.status == "fail":
            if f.article in (12, 14):  # Record-keeping and oversight are high
                f.severity = "high"
            elif f.article in (9, 15):  # Risk and robustness are high if fail
                f.severity = "high"
            elif f.article == 16:  # Hiring compliance violations are high
                f.severity = "high"
            else:
                f.severity = "medium"
        elif f.status == "warn":
            f.severity = "medium" if f.article in (9, 12, 16) else "low"
        else:
            f.severity = "low"

    return findings


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


def _get_explanation(finding: CodeFinding) -> dict:
    """Get plain-English explanation for a finding."""
    name_map = EXPLANATIONS.get(finding.name, {})
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
}

ARTICLE_WEIGHTS = {9: 1.0, 10: 1.0, 11: 0.8, 12: 1.2, 14: 1.2, 15: 1.0, 16: 1.0}


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
                return self._error(400, "Invalid JSON. Send: {\"code\": \"...your python code...\"}")

            code = data.get("code", "")
            if not code or not code.strip():
                return self._error(400, "No code provided. Send JSON with a 'code' field containing Python code.")

            if len(code) > MAX_CODE_SIZE:
                return self._error(413, f"Code too large. Maximum size is {MAX_CODE_SIZE // 1024}KB.")

            # Rate limiting (basic, in-memory)
            client_ip = self.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()
            now = time.time()
            if client_ip in _SCAN_LOG:
                _SCAN_LOG[client_ip] = [t for t in _SCAN_LOG[client_ip] if now - t < RATE_WINDOW]
                if len(_SCAN_LOG[client_ip]) >= FREE_SCANS_PER_MONTH:
                    return self._error(429, f"Free tier limit reached ({FREE_SCANS_PER_MONTH} scans per month). Upgrade to Pro for unlimited scans.")
            else:
                _SCAN_LOG[client_ip] = []
            _SCAN_LOG[client_ip].append(now)

            # Run scan
            start = time.time()
            findings = scan_code_string(code)
            scores = calculate_score(findings)
            duration_ms = int((time.time() - start) * 1000)

            # Build response
            frameworks = _detect_frameworks(code)
            has_llm = _has_llm_calls(code)

            # Group findings by article for the frontend
            articles_out = []
            by_article = {}
            for f in findings:
                by_article.setdefault(f.article, []).append(f)

            for art_num in sorted(by_article.keys()):
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
                    "scanner_version": "1.0.0",
                    "engine": "air-blackbox-console",
                },
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
        self.send_header("Access-Control-Allow-Origin", "https://airblackbox.ai")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
