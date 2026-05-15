"""
AIR Blackbox - Shadow AI Detection API

Vercel serverless function that analyzes text for AI-generated
content across any industry. Returns a confidence score and
context-aware regulatory exposure mapping.

POST /api/detect
Body: { "text": "...", "context": "legal_brief" }
Returns: { "score": 0.82, "verdict": "likely_ai", "signals": [...], ... }

Supported contexts:
  hiring        - recruiter notes, candidate evaluations, screening
  legal         - briefs, memos, contract analysis, case summaries
  finance       - analyst reports, risk assessments, filings
  healthcare    - clinical notes, chart documentation, referrals
  insurance     - claims assessments, policy analysis, adjustments
  customer_support - ticket responses, escalation notes
  education     - student evaluations, academic assessments
  general       - any professional text

Detection approach: statistical feature extraction (no external ML
dependencies). Catches LLM writing patterns through:
  1. Hedging phrase density (LLMs hedge constantly)
  2. Sentence length uniformity (humans vary, LLMs don't)
  3. Vocabulary sophistication consistency
  4. Formulaic structure detection
  5. Filler phrase patterns unique to LLMs
  6. Paragraph uniformity
  7. Context-specific AI patterns (per industry)
"""

import json
import math
import os
import re
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler

import hashlib
import secrets

import redis as redis_lib


# ============================================================
# Config & Redis Storage
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")
MAX_TEXT_SIZE = 50_000  # 50KB
FREE_TIER_SCANS = 25   # per month, no key needed
KEY_PREFIX = "airbb_sk_"

# Valid context values
VALID_CONTEXTS = [
    "hiring", "legal", "finance", "healthcare", "insurance",
    "customer_support", "education", "general",
    # Legacy aliases (map to new contexts)
    "screening_note", "candidate_evaluation", "interview_feedback",
    "rejection_reason", "other",
]

# Map legacy context names to new industry contexts
CONTEXT_ALIASES = {
    "screening_note": "hiring",
    "candidate_evaluation": "hiring",
    "interview_feedback": "hiring",
    "rejection_reason": "hiring",
    "other": "general",
}


# ============================================================
# Redis helpers (duplicated from keys.py -- Vercel can't share
# modules between serverless functions without a build step)
# ============================================================

_redis_client = None

def _get_redis():
    """Get a Redis client, reusing the connection across calls."""
    global _redis_client
    if _redis_client is None:
        if not REDIS_URL:
            return None
        _redis_client = redis_lib.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
        )
    return _redis_client


def _kv_get(key: str):
    r = _get_redis()
    if not r:
        return None
    try:
        return r.get(key)
    except Exception:
        return None


def _kv_incr(key: str) -> int:
    r = _get_redis()
    if not r:
        return 0
    try:
        return r.incr(key)
    except Exception:
        return 0


def _kv_expire(key: str, seconds: int):
    r = _get_redis()
    if not r:
        return
    try:
        r.expire(key, seconds)
    except Exception:
        pass


def _current_month() -> str:
    return time.strftime("%Y-%m", time.gmtime())


# ============================================================
# API Key Auth & Usage Tracking
# ============================================================

def _validate_api_key(api_key: str) -> dict:
    """Validate an API key against KV store."""
    if not api_key or not api_key.startswith(KEY_PREFIX):
        return {"valid": False, "reason": "Invalid key format"}
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    raw = _kv_get(f"apikey:{key_hash}")
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


def _track_usage(key_hash: str) -> int:
    """Increment and return monthly scan count for a key."""
    month = _current_month()
    counter_key = f"usage:{key_hash}:{month}"
    count = _kv_incr(counter_key)
    if count == 1:
        _kv_expire(counter_key, 90 * 24 * 3600)
    return count


def _get_credit_balance(key_hash: str) -> int:
    """Get remaining prepaid scan credits for a key."""
    r = _get_redis()
    if not r:
        return 0
    try:
        val = r.get(f"credits:{key_hash}")
        return int(val) if val else 0
    except Exception:
        return 0


def _deduct_credit(key_hash: str) -> int:
    """Deduct one scan credit. Returns new balance (or -1 if none left)."""
    r = _get_redis()
    if not r:
        return -1
    try:
        new_val = r.decr(f"credits:{key_hash}")
        if new_val < 0:
            # Went negative, restore and reject
            r.incr(f"credits:{key_hash}")
            return -1
        return new_val
    except Exception:
        return -1


def _check_free_tier(client_ip: str) -> dict:
    """Check if free tier IP has scans remaining."""
    if not REDIS_URL:
        return {"allowed": True, "used": 0, "limit": FREE_TIER_SCANS, "fallback": True}
    month = _current_month()
    counter_key = f"free:{client_ip}:{month}"
    raw = _kv_get(counter_key)
    current = int(raw) if raw else 0
    return {"allowed": current < FREE_TIER_SCANS, "used": current, "limit": FREE_TIER_SCANS}


def _increment_free_tier(client_ip: str) -> int:
    """Increment free tier counter for IP."""
    if not REDIS_URL:
        return 0
    month = _current_month()
    counter_key = f"free:{client_ip}:{month}"
    count = _kv_incr(counter_key)
    if count == 1:
        _kv_expire(counter_key, 45 * 24 * 3600)
    return count


# ============================================================
# Universal Signal Detectors
# These fire on ALL text regardless of industry context.
# ============================================================

# --- Signal 1: Hedging Phrases ---
# LLMs use hedging language at 3-5x the rate of human writers.

HEDGING_PHRASES = [
    r"\bit[''']?s worth noting\b",
    r"\bit[''']?s important to note\b",
    r"\bit should be noted\b",
    r"\bthat being said\b",
    r"\bthat said\b",
    r"\bhowever,? it\b",
    r"\bwhile .{5,30} it is\b",
    r"\bgenerally speaking\b",
    r"\bon the other hand\b",
    r"\bin terms of\b",
    r"\bwith that in mind\b",
    r"\bwith respect to\b",
    r"\bwith regard to\b",
    r"\bit is also worth\b",
    r"\boverall[,.]?\s",
    r"\bin summary[,.]?\s",
    r"\bto summarize[,.]?\s",
    r"\bnotably[,.]?\s",
    r"\bimportantly[,.]?\s",
    r"\bfurthermore[,.]?\s",
    r"\bmoreover[,.]?\s",
    r"\bnonetheless[,.]?\s",
    r"\bnevertheless[,.]?\s",
    r"\bconversely[,.]?\s",
    r"\badditionally[,.]?\s",
    r"\bsubsequently[,.]?\s",
]

# --- Signal 2: Formulaic Structure ---
# LLMs produce text with characteristic structural patterns
# that appear across all industries.

FORMULAIC_PATTERNS = [
    r"\bdemonstrates?\s+(?:strong|solid|excellent|good|clear)\s+(?:competenc|skill|abilit|understand|knowledge|experience|command|grasp)",
    r"\bexhibits?\s+(?:strong|solid|excellent|good|clear)\s+",
    r"\bshowcases?\s+(?:strong|solid|excellent|a deep|a clear)\s+",
    r"\bpossesses?\s+(?:strong|solid|excellent|good|the)\s+",
    r"\baligns?\s+(?:well|closely|strongly)\s+with\b",
    r"\bwell[- ]suited\s+for\b",
    r"\bbrings?\s+(?:a\s+)?(?:wealth|breadth|depth)\s+of\b",
    r"\bhas\s+a\s+(?:proven|strong|solid)\s+track\s+record\b",
    r"\bleverage[sd]?\s+(?:their|his|her|its|the)\s+(?:experience|expertise|skills|knowledge|capabilities)\b",
    r"\bkey\s+(?:strengths?|takeaways?|highlights?|points?|findings?|considerations?)\s+include\b",
    r"\b(?:in\s+)?conclusion\b",
    r"\barea[s]?\s+(?:for|of)\s+(?:improvement|growth|development|concern)\b",
    r"\bpotential\s+(?:areas?\s+)?(?:for|of)\s+(?:growth|improvement|development)\b",
    r"\b(?:strong|excellent|exceptional)\s+(?:communication|interpersonal|leadership|analytical)\s+skills\b",
    r"\bwould\s+be\s+(?:a\s+)?(?:strong|great|good|excellent|ideal|valuable)\s+(?:addition|asset|fit|candidate|choice|option)\b",
]

# --- Signal 3: LLM-Specific Filler ---
# Phrases that are signature LLM output across all contexts.

LLM_FILLER_PHRASES = [
    r"\bdelve\s+(?:into|deeper)\b",
    r"\blet[''']?s\s+(?:delve|explore|examine|take a closer look)\b",
    r"\btake\s+a\s+closer\s+look\b",
    r"\bworth\s+mentioning\b",
    r"\bunderscores?\s+the\s+importance\b",
    r"\bhighly\s+recommend\b",
    r"\bcertainly\b",
    r"\babsolutely\b",
    r"\bindeed\b",
    r"\bultimately\b",
    r"\bspecifically\b.*\bspecifically\b",
    r"\brobust\s+(?:experience|background|skill|understanding|framework|approach|methodology|analysis)\b",
    r"\bcomprehensive\s+(?:experience|background|skill|understanding|knowledge|analysis|review|assessment|overview)\b",
    r"\bmeticulous(?:ly)?\b",
    r"\bseamless(?:ly)?\b",
    r"\bholistic(?:ally)?\b",
    r"\bsynerg(?:y|ies|istic)\b",
    r"\bmultifaceted\b",
    r"\bnuanced\s+(?:understanding|approach|perspective|analysis|view)\b",
    r"\bpivotal\s+(?:role|moment|factor|aspect)\b",
    r"\bparamount\s+(?:importance|concern|consideration)\b",
    r"\bunderscore[sd]?\b",
    r"\bfacilitat(?:e[sd]?|ing)\b",
]


# ============================================================
# Industry-Specific AI Pattern Sets
# Each context has patterns typical of LLM output in that field.
# ============================================================

INDUSTRY_PATTERNS = {
    "hiring": {
        "name": "Hiring & Recruiting AI patterns",
        "patterns": [
            # Structured evaluation headers
            r"(?:^|\n)\s*(?:Strengths?|Weaknesses?|Areas?\s+(?:of|for)\s+(?:Improvement|Concern)|Summary|Assessment|Recommendation|Evaluation|Key\s+(?:Points?|Observations?|Findings?)|Pros?|Cons?)\s*[:\-]",
            # Numbered evaluations
            r"(?:^|\n)\s*(?:\d+[\.\)]\s+|[-*]\s+)(?:Strong|Demonstrates?|Has|Possesses?|Exhibits?|Shows?)\s+",
            # Rating scales
            r"\b(?:rating|score)\s*:\s*\d+\s*/\s*\d+\b",
            r"\b\d+\s*/\s*(?:5|10)\b",
            # Ideal candidate comparison
            r"\bcompared\s+to\s+(?:the\s+)?(?:ideal|typical|average|standard)\b",
            # Meta-commentary
            r"\bbased\s+on\s+(?:the\s+)?(?:resume|CV|application|materials?|information)\s+(?:provided|reviewed|submitted)\b",
            # Culture fit language
            r"\b(?:culture|cultural)\s+(?:fit|alignment|add)\b",
            r"\bthroughout\s+(?:their|his|her)\s+career\b",
        ],
    },
    "legal": {
        "name": "Legal & Compliance AI patterns",
        "patterns": [
            # Legal structure headers
            r"(?:^|\n)\s*(?:Analysis|Legal\s+Analysis|Discussion|Holding|Conclusion|Issue|Rule|Application|Counter[- ]?argument|Jurisdictional\s+Analysis)\s*[:\-]",
            # IRAC structure markers
            r"\bthe\s+(?:court|tribunal|board)\s+(?:held|found|determined|concluded|noted|observed)\s+that\b",
            r"\bpursuant\s+to\s+(?:section|article|\d+\s+U\.?S\.?C|the\s+(?:agreement|contract|statute))\b",
            # LLM legal hedging
            r"\bit\s+(?:is|would\s+be)\s+(?:advisable|prudent|recommended|important)\s+to\s+(?:note|consider|consult)\b",
            r"\bthis\s+(?:analysis|memorandum|brief|opinion)\s+(?:does\s+not\s+constitute|is\s+not\s+intended\s+as)\s+legal\s+advice\b",
            # Formulaic legal conclusions
            r"\bbased\s+on\s+the\s+(?:foregoing|above)\s+(?:analysis|discussion|facts)\b",
            r"\bin\s+light\s+of\s+the\s+(?:foregoing|above|circumstances)\b",
            r"\bthe\s+(?:totality|weight|preponderance)\s+of\s+(?:the\s+)?(?:evidence|circumstances|factors)\b",
        ],
    },
    "finance": {
        "name": "Finance & Analyst AI patterns",
        "patterns": [
            # Analyst report headers
            r"(?:^|\n)\s*(?:Investment\s+Thesis|Risk\s+(?:Factors?|Assessment)|Valuation|Financial\s+(?:Summary|Overview|Analysis|Highlights)|Market\s+(?:Outlook|Analysis)|Key\s+(?:Metrics|Drivers|Risks))\s*[:\-]",
            # LLM financial language
            r"\b(?:poised|positioned)\s+(?:for|to)\s+(?:growth|outperform|benefit|capitalize)\b",
            r"\b(?:strong|solid|robust)\s+(?:fundamentals?|balance\s+sheet|cash\s+flow|revenue\s+growth)\b",
            r"\btailwinds?\s+(?:from|include|such\s+as)\b",
            r"\bheadwinds?\s+(?:from|include|such\s+as)\b",
            # Formulaic risk language
            r"\binvestors\s+should\s+(?:note|consider|be\s+aware)\b",
            r"\bthis\s+(?:analysis|report)\s+(?:does\s+not\s+constitute|is\s+not)\s+(?:financial|investment)\s+advice\b",
            r"\bpast\s+performance\s+(?:is\s+not|does\s+not)\s+(?:indicative|guarantee)\b",
        ],
    },
    "healthcare": {
        "name": "Healthcare & Clinical AI patterns",
        "patterns": [
            # Clinical note headers
            r"(?:^|\n)\s*(?:Assessment|Plan|Subjective|Objective|Chief\s+Complaint|History\s+of\s+Present|Review\s+of\s+Systems|Physical\s+(?:Exam|Examination)|Differential\s+Diagnosis|Impression)\s*[:\-]",
            # LLM clinical language
            r"\bthe\s+patient\s+(?:presents|presented)\s+with\s+(?:a\s+)?(?:history|complaint|symptoms?)\s+of\b",
            r"\b(?:it\s+is|would\s+be)\s+(?:advisable|recommended|prudent)\s+to\s+(?:monitor|follow[- ]up|consider|refer)\b",
            r"\bconsistent\s+with\s+(?:a\s+)?(?:diagnosis|presentation|clinical\s+picture)\s+of\b",
            # Disclaimer patterns
            r"\bthis\s+(?:note|assessment|summary)\s+(?:does\s+not|is\s+not\s+intended\s+to)\s+(?:replace|substitute)\b",
            r"\bclinical\s+(?:correlation|judgment)\s+(?:is|should\s+be)\s+(?:advised|recommended|used)\b",
            # Overly thorough differentials
            r"\bdifferential\s+(?:diagnosis|diagnoses)\s+(?:includes?|to\s+consider)\b",
        ],
    },
    "insurance": {
        "name": "Insurance & Claims AI patterns",
        "patterns": [
            # Claims assessment headers
            r"(?:^|\n)\s*(?:Claims?\s+(?:Summary|Assessment|Analysis|Determination)|Coverage\s+(?:Analysis|Determination)|Liability\s+(?:Assessment|Analysis)|Damages?\s+(?:Assessment|Summary)|Findings?|Recommendation)\s*[:\-]",
            # LLM claims language
            r"\bbased\s+on\s+(?:the\s+)?(?:investigation|review|inspection|evidence|documentation)\b",
            r"\bthe\s+(?:claimant|insured|policyholder)\s+(?:alleges|reports?|states?|indicates?)\b",
            r"\bcoverage\s+(?:applies|is\s+afforded|is\s+available|may\s+be\s+(?:limited|excluded))\b",
            # Formulaic adjustor conclusions
            r"\b(?:within|outside)\s+(?:the\s+)?(?:scope|terms|provisions?)\s+of\s+(?:the\s+)?(?:policy|coverage)\b",
            r"\breserves?\s+(?:should|are\s+recommended\s+to)\s+be\s+(?:set|established|adjusted)\b",
        ],
    },
    "customer_support": {
        "name": "Customer Support AI patterns",
        "patterns": [
            # Overly polished support language
            r"\bthank\s+you\s+(?:so\s+much\s+)?for\s+(?:your\s+)?(?:patience|understanding|reaching\s+out|contacting\s+us|bringing\s+this)\b",
            r"\bI\s+(?:completely|fully|totally)\s+understand\s+(?:your|how|the)\b",
            r"\bI\s+(?:sincerely|truly)\s+apologize\s+for\s+(?:any|the)\s+(?:inconvenience|frustration|confusion)\b",
            # Resolution templates
            r"\bplease\s+(?:don[''']?t\s+hesitate|feel\s+free)\s+to\s+(?:reach\s+out|contact\s+us|let\s+(?:me|us)\s+know)\b",
            r"\bIs\s+there\s+anything\s+else\s+I\s+can\s+(?:help|assist)\s+(?:you\s+)?with\b",
            r"\bI[''']?(?:m|ve)\s+(?:happy|glad|delighted)\s+to\s+(?:help|assist|look\s+into)\b",
            # Numbered step instructions
            r"(?:^|\n)\s*(?:Step\s+)?\d+[\.\)]\s+(?:Navigate|Click|Go\s+to|Open|Select|Visit|Log\s+in)\b",
        ],
    },
    "education": {
        "name": "Education & Academic AI patterns",
        "patterns": [
            # Academic assessment headers
            r"(?:^|\n)\s*(?:Learning\s+Objectives?|Assessment|Student\s+(?:Performance|Evaluation|Progress)|Areas?\s+(?:of|for)\s+(?:Growth|Development|Improvement)|Strengths?|Recommendations?)\s*[:\-]",
            # LLM academic language
            r"\bthe\s+student\s+(?:demonstrates?|exhibits?|shows?|displays?)\s+(?:a\s+)?(?:strong|solid|growing|developing|emerging)\b",
            r"\b(?:mastery|proficiency|competency)\s+(?:in|of|with)\b",
            r"\b(?:grade[- ]level|age[- ]appropriate|developmentally\s+appropriate)\b",
            # Formulaic progress language
            r"\bwith\s+(?:continued|additional|targeted)\s+(?:support|practice|instruction|intervention)\b",
            r"\b(?:differentiated|scaffolded)\s+(?:instruction|support|learning)\b",
        ],
    },
    "general": {
        "name": "General professional AI patterns",
        "patterns": [
            # Generic LLM structural patterns (universal)
            r"(?:^|\n)\s*(?:Summary|Overview|Background|Context|Analysis|Findings?|Recommendations?|Next\s+Steps?|Action\s+Items?|Conclusion)\s*[:\-]",
            # Numbered or bulleted points starting with action verbs
            r"(?:^|\n)\s*(?:\d+[\.\)]\s+|[-*]\s+)(?:Implement|Ensure|Consider|Review|Evaluate|Develop|Establish|Monitor|Assess)\s+",
            # Meta-commentary
            r"\bbased\s+on\s+(?:the\s+)?(?:above|foregoing|available|provided)\s+(?:information|data|analysis|evidence)\b",
            # Disclaimer patterns
            r"\bthis\s+(?:document|analysis|report|summary|overview)\s+(?:is\s+(?:not\s+)?intended|provides|offers)\b",
        ],
    },
}


# ============================================================
# Context-Aware Regulatory Mapping
# Maps each industry context to relevant regulations when
# AI-generated content is detected.
# ============================================================

REGULATORY_MAP = {
    "hiring": [
        {"law": "NYC Local Law 144", "risk": "AEDT use without bias audit", "status": "in_effect"},
        {"law": "Illinois HB 3773", "risk": "AI screening without disclosure", "status": "in_effect"},
        {"law": "California FEHA", "risk": "AI vendor liability, 4-year retention required", "status": "in_effect"},
        {"law": "Colorado CAIA", "risk": "Developer duty of care for AI hiring tools", "status": "effective_june_2026"},
        {"law": "EU AI Act Annex III", "risk": "High-risk AI in employment (Art. 6)", "status": "effective_august_2026"},
    ],
    "legal": [
        {"law": "ABA Model Rule 1.1", "risk": "Competence requires understanding AI tool limitations", "status": "in_effect"},
        {"law": "ABA Model Rule 5.3", "risk": "Supervision duty for AI-assisted legal work", "status": "in_effect"},
        {"law": "Court-specific AI orders", "risk": "Many courts require AI use disclosure in filings", "status": "in_effect"},
        {"law": "EU AI Act Art. 50", "risk": "Transparency obligation for AI-generated content", "status": "effective_august_2026"},
    ],
    "finance": [
        {"law": "SEC AI disclosure guidance", "risk": "Material AI use in research requires disclosure", "status": "in_effect"},
        {"law": "FINRA Notice 24-09", "risk": "Broker-dealer AI communication supervision", "status": "in_effect"},
        {"law": "EU AI Act Art. 50", "risk": "Transparency obligation for AI-generated content", "status": "effective_august_2026"},
        {"law": "Colorado CAIA", "risk": "AI in consequential financial decisions", "status": "effective_june_2026"},
    ],
    "healthcare": [
        {"law": "HIPAA", "risk": "PHI in unsanctioned AI tools lacks BAA coverage", "status": "in_effect"},
        {"law": "FDA AI/ML guidance", "risk": "Clinical decision support AI requires oversight", "status": "in_effect"},
        {"law": "State medical board rules", "risk": "AI-generated clinical notes without physician review", "status": "in_effect"},
        {"law": "EU AI Act Annex III", "risk": "High-risk AI in healthcare (Art. 6)", "status": "effective_august_2026"},
    ],
    "insurance": [
        {"law": "State insurance AI bulletins", "risk": "AI in underwriting/claims requires disclosure (CO, CT, NY)", "status": "in_effect"},
        {"law": "NAIC Model Bulletin", "risk": "Insurers must govern AI in consumer-impacting decisions", "status": "in_effect"},
        {"law": "Colorado CAIA", "risk": "AI in consequential insurance decisions", "status": "effective_june_2026"},
        {"law": "EU AI Act Annex III", "risk": "High-risk AI in insurance access (Art. 6)", "status": "effective_august_2026"},
    ],
    "customer_support": [
        {"law": "FTC AI guidelines", "risk": "Deceptive practices if AI impersonates human agent", "status": "in_effect"},
        {"law": "California Bot Disclosure Law", "risk": "Must disclose bot/AI use in consumer interactions", "status": "in_effect"},
        {"law": "EU AI Act Art. 50", "risk": "Users must be informed of AI interaction", "status": "effective_august_2026"},
    ],
    "education": [
        {"law": "FERPA", "risk": "Student data in unsanctioned AI tools lacks privacy controls", "status": "in_effect"},
        {"law": "State AI-in-education laws", "risk": "Several states require disclosure of AI in student assessment", "status": "in_effect"},
        {"law": "EU AI Act Annex III", "risk": "High-risk AI in education access/assessment (Art. 6)", "status": "effective_august_2026"},
    ],
    "general": [
        {"law": "EU AI Act Art. 50", "risk": "Transparency obligation for AI-generated content", "status": "effective_august_2026"},
        {"law": "FTC Act Section 5", "risk": "AI-generated content in commerce may be deceptive practice", "status": "in_effect"},
        {"law": "State consumer protection", "risk": "AI-generated professional work without disclosure", "status": "varies"},
    ],
}


# ============================================================
# Core Detection Functions (universal)
# ============================================================

def _count_pattern_matches(text: str, patterns: list) -> list:
    """Return list of (pattern_desc, count) for each matching pattern."""
    matches = []
    for p in patterns:
        found = re.findall(p, text, re.IGNORECASE | re.MULTILINE)
        if found:
            clean = p.replace(r"\b", "").replace(r"\s+", " ").replace(r"[''']?", "'")
            clean = re.sub(r'\(.*?\)', '...', clean)[:60]
            matches.append({"pattern": clean, "count": len(found)})
    return matches


def _sentence_uniformity(text: str) -> dict:
    """Measure how uniform sentence lengths are.

    CV < 0.3 = very uniform (AI signal)
    CV 0.3-0.5 = moderate (inconclusive)
    CV > 0.5 = high variance (human signal)
    """
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

    if len(sentences) < 3:
        return {"cv": 0.5, "mean_length": 0, "sentence_count": len(sentences), "signal": "insufficient_data"}

    lengths = [len(s.split()) for s in sentences]
    mean_len = sum(lengths) / len(lengths)
    if mean_len == 0:
        return {"cv": 0.5, "mean_length": 0, "sentence_count": len(sentences), "signal": "insufficient_data"}

    variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
    std_dev = math.sqrt(variance)
    cv = std_dev / mean_len

    if cv < 0.3:
        signal = "ai_likely"
    elif cv < 0.5:
        signal = "inconclusive"
    else:
        signal = "human_likely"

    return {
        "cv": round(cv, 3),
        "mean_length": round(mean_len, 1),
        "sentence_count": len(sentences),
        "signal": signal,
    }


def _paragraph_uniformity(text: str) -> dict:
    """Measure paragraph length uniformity."""
    paragraphs = [p.strip() for p in text.split("\n\n") if len(p.strip()) > 20]
    if len(paragraphs) < 2:
        paragraphs = [p.strip() for p in text.split("\n") if len(p.strip()) > 20]

    if len(paragraphs) < 2:
        return {"cv": 0.5, "paragraph_count": len(paragraphs), "signal": "insufficient_data"}

    lengths = [len(p.split()) for p in paragraphs]
    mean_len = sum(lengths) / len(lengths)
    if mean_len == 0:
        return {"cv": 0.5, "paragraph_count": len(paragraphs), "signal": "insufficient_data"}

    variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
    std_dev = math.sqrt(variance)
    cv = std_dev / mean_len

    if cv < 0.25:
        signal = "ai_likely"
    elif cv < 0.45:
        signal = "inconclusive"
    else:
        signal = "human_likely"

    return {
        "cv": round(cv, 3),
        "paragraph_count": len(paragraphs),
        "signal": signal,
    }


def _vocabulary_analysis(text: str) -> dict:
    """Analyze vocabulary sophistication and diversity."""
    words = re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())
    if len(words) < 20:
        return {"ttr": 0.5, "signal": "insufficient_data"}

    unique_words = set(words)
    total_words = len(words)
    ttr = len(unique_words) / total_words

    def _syllable_count(word):
        word = word.lower()
        count = 0
        vowels = "aeiouy"
        if word[0] in vowels:
            count += 1
        for i in range(1, len(word)):
            if word[i] in vowels and word[i - 1] not in vowels:
                count += 1
        if word.endswith("e"):
            count -= 1
        return max(count, 1)

    polysyllabic = sum(1 for w in words if _syllable_count(w) >= 4)
    poly_ratio = polysyllabic / total_words

    if ttr > 0.6 and poly_ratio > 0.10:
        signal = "ai_likely"
    elif ttr > 0.55 and poly_ratio > 0.08:
        signal = "inconclusive"
    else:
        signal = "human_likely"

    return {
        "type_token_ratio": round(ttr, 3),
        "unique_words": len(unique_words),
        "total_words": total_words,
        "polysyllabic_ratio": round(poly_ratio, 3),
        "signal": signal,
    }


def _cross_text_similarity(texts: list) -> dict:
    """Detect when multiple texts share suspiciously similar structure."""
    if len(texts) < 2:
        return {"similarity": 0, "signal": "single_text"}

    def _trigrams(text):
        words = re.findall(r'\b[a-z]{2,}\b', text.lower())
        return set(tuple(words[i:i+3]) for i in range(len(words) - 2))

    similarities = []
    for i in range(len(texts)):
        for j in range(i + 1, len(texts)):
            t1 = _trigrams(texts[i])
            t2 = _trigrams(texts[j])
            if not t1 or not t2:
                continue
            intersection = len(t1 & t2)
            union = len(t1 | t2)
            if union > 0:
                similarities.append(intersection / union)

    if not similarities:
        return {"similarity": 0, "signal": "insufficient_data"}

    avg_sim = sum(similarities) / len(similarities)

    if avg_sim > 0.4:
        signal = "ai_likely"
    elif avg_sim > 0.2:
        signal = "inconclusive"
    else:
        signal = "human_likely"

    return {
        "avg_similarity": round(avg_sim, 3),
        "comparisons": len(similarities),
        "signal": signal,
    }


# ============================================================
# Main Detection Function
# ============================================================

def detect_ai_text(text: str, context: str = "general", texts_batch: list = None) -> dict:
    """
    Analyze text for AI-generation signals.

    Args:
        text: The text to analyze.
        context: Industry context for pattern matching and regulatory
                 mapping. One of: hiring, legal, finance, healthcare,
                 insurance, customer_support, education, general.
        texts_batch: Optional list of texts for cross-similarity analysis.

    Returns a confidence score (0.0 to 1.0) and detailed signal breakdown.
    """
    # Resolve legacy context aliases
    context = CONTEXT_ALIASES.get(context, context)
    if context not in INDUSTRY_PATTERNS:
        context = "general"

    word_count = len(text.split())
    if word_count < 15:
        return {
            "score": 0.0,
            "verdict": "insufficient_text",
            "word_count": word_count,
            "context": context,
            "detail": "Need at least 15 words for analysis",
            "signals": [],
            "signal_summary": {},
            "regulatory_exposure": [],
        }

    signals = []
    weighted_scores = []

    # --- Hedging phrases (weight: 0.20) ---
    hedging_matches = _count_pattern_matches(text, HEDGING_PHRASES)
    hedging_count = sum(m["count"] for m in hedging_matches)
    hedging_density = hedging_count / (word_count / 100)
    if hedging_density > 3.0:
        hedging_score = 1.0
    elif hedging_density > 1.5:
        hedging_score = 0.7
    elif hedging_density > 0.5:
        hedging_score = 0.4
    else:
        hedging_score = 0.1
    weighted_scores.append(("hedging", hedging_score, 0.20))
    if hedging_matches:
        signals.append({
            "name": "Hedging language",
            "score": hedging_score,
            "detail": f"{hedging_count} hedging phrases detected ({hedging_density:.1f} per 100 words)",
            "matches": hedging_matches[:5],
        })

    # --- Formulaic structure (weight: 0.20) ---
    formulaic_matches = _count_pattern_matches(text, FORMULAIC_PATTERNS)
    formulaic_count = sum(m["count"] for m in formulaic_matches)
    formulaic_density = formulaic_count / (word_count / 100)
    if formulaic_density > 2.0:
        formulaic_score = 1.0
    elif formulaic_density > 1.0:
        formulaic_score = 0.7
    elif formulaic_density > 0.3:
        formulaic_score = 0.4
    else:
        formulaic_score = 0.1
    weighted_scores.append(("formulaic", formulaic_score, 0.20))
    if formulaic_matches:
        signals.append({
            "name": "Formulaic structure",
            "score": formulaic_score,
            "detail": f"{formulaic_count} formulaic patterns detected",
            "matches": formulaic_matches[:5],
        })

    # --- LLM filler phrases (weight: 0.15) ---
    filler_matches = _count_pattern_matches(text, LLM_FILLER_PHRASES)
    filler_count = sum(m["count"] for m in filler_matches)
    filler_density = filler_count / (word_count / 100)
    if filler_density > 2.0:
        filler_score = 1.0
    elif filler_density > 1.0:
        filler_score = 0.7
    elif filler_density > 0.3:
        filler_score = 0.4
    else:
        filler_score = 0.1
    weighted_scores.append(("filler", filler_score, 0.15))
    if filler_matches:
        signals.append({
            "name": "LLM filler phrases",
            "score": filler_score,
            "detail": f"{filler_count} LLM-typical phrases detected",
            "matches": filler_matches[:5],
        })

    # --- Industry-specific AI patterns (weight: 0.15) ---
    industry_config = INDUSTRY_PATTERNS[context]
    industry_matches = _count_pattern_matches(text, industry_config["patterns"])
    industry_count = sum(m["count"] for m in industry_matches)
    if industry_count >= 3:
        industry_score = 1.0
    elif industry_count >= 2:
        industry_score = 0.7
    elif industry_count >= 1:
        industry_score = 0.4
    else:
        industry_score = 0.1
    weighted_scores.append(("industry_patterns", industry_score, 0.15))
    if industry_matches:
        signals.append({
            "name": industry_config["name"],
            "score": industry_score,
            "detail": f"{industry_count} industry-specific AI patterns detected",
            "matches": industry_matches[:5],
        })

    # --- Sentence uniformity (weight: 0.10) ---
    sent_analysis = _sentence_uniformity(text)
    if sent_analysis["signal"] == "ai_likely":
        sent_score = 0.9
    elif sent_analysis["signal"] == "inconclusive":
        sent_score = 0.5
    else:
        sent_score = 0.15
    weighted_scores.append(("sentence_uniformity", sent_score, 0.10))
    signals.append({
        "name": "Sentence length uniformity",
        "score": sent_score,
        "detail": f"CV={sent_analysis['cv']}, mean={sent_analysis['mean_length']} words, {sent_analysis['sentence_count']} sentences",
        "analysis": sent_analysis,
    })

    # --- Vocabulary analysis (weight: 0.10) ---
    vocab_analysis = _vocabulary_analysis(text)
    if vocab_analysis["signal"] == "ai_likely":
        vocab_score = 0.85
    elif vocab_analysis["signal"] == "inconclusive":
        vocab_score = 0.5
    else:
        vocab_score = 0.15
    weighted_scores.append(("vocabulary", vocab_score, 0.10))
    signals.append({
        "name": "Vocabulary sophistication",
        "score": vocab_score,
        "detail": f"TTR={vocab_analysis.get('type_token_ratio', 0)}, polysyllabic={vocab_analysis.get('polysyllabic_ratio', 0)}",
        "analysis": vocab_analysis,
    })

    # --- Paragraph uniformity (weight: 0.10) ---
    para_analysis = _paragraph_uniformity(text)
    if para_analysis["signal"] == "ai_likely":
        para_score = 0.85
    elif para_analysis["signal"] == "inconclusive":
        para_score = 0.5
    else:
        para_score = 0.15
    weighted_scores.append(("paragraph_uniformity", para_score, 0.10))
    signals.append({
        "name": "Paragraph uniformity",
        "score": para_score,
        "detail": f"CV={para_analysis['cv']}, {para_analysis.get('paragraph_count', 0)} paragraphs",
        "analysis": para_analysis,
    })

    # --- Cross-text similarity (bonus signal) ---
    if texts_batch and len(texts_batch) > 1:
        cross_analysis = _cross_text_similarity(texts_batch)
        if cross_analysis["signal"] == "ai_likely":
            cross_score = 0.9
        elif cross_analysis["signal"] == "inconclusive":
            cross_score = 0.5
        else:
            cross_score = 0.15
        weighted_scores.append(("cross_similarity", cross_score, 0.10))
        signals.append({
            "name": "Cross-text similarity",
            "score": cross_score,
            "detail": f"Average similarity={cross_analysis.get('avg_similarity', 0)} across {cross_analysis.get('comparisons', 0)} pairs",
            "analysis": cross_analysis,
        })

    # --- Calculate weighted composite score ---
    total_weight = sum(w for _, _, w in weighted_scores)
    composite = sum(score * weight for _, score, weight in weighted_scores) / total_weight

    # Confidence adjustment for short texts
    if word_count < 50:
        composite = 0.5 + (composite - 0.5) * 0.6
    elif word_count < 100:
        composite = 0.5 + (composite - 0.5) * 0.8

    composite = round(min(max(composite, 0.0), 1.0), 3)

    # Verdict
    if composite >= 0.8:
        verdict = "very_likely_ai"
    elif composite >= 0.6:
        verdict = "likely_ai"
    elif composite >= 0.4:
        verdict = "inconclusive"
    elif composite >= 0.2:
        verdict = "likely_human"
    else:
        verdict = "very_likely_human"

    # Context-aware regulatory exposure
    regulations = []
    if composite >= 0.6:
        regulations = REGULATORY_MAP.get(context, REGULATORY_MAP["general"])

    return {
        "score": composite,
        "verdict": verdict,
        "word_count": word_count,
        "context": context,
        "signals": signals,
        "signal_summary": {name: round(score, 3) for name, score, _ in weighted_scores},
        "regulatory_exposure": regulations,
    }


# ============================================================
# HTTP Handler (Vercel serverless)
# ============================================================

class handler(BaseHTTPRequestHandler):
    """Vercel serverless function handler for /api/detect."""

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return self._error(400, "Request body is empty. Send JSON with a 'text' field.")
            if content_length > MAX_TEXT_SIZE:
                return self._error(413, f"Text too large. Maximum size is {MAX_TEXT_SIZE // 1024}KB.")

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._error(400, 'Invalid JSON. Send: {"text": "...", "context": "general"}')

            # Support single text or batch mode
            text = data.get("text", "")
            texts = data.get("texts", [])
            context = data.get("context", "general")

            if not text and not texts:
                return self._error(400, "No text provided. Send 'text' (single) or 'texts' (batch array).")

            if text and len(text) > MAX_TEXT_SIZE:
                return self._error(413, f"Text too large. Maximum size is {MAX_TEXT_SIZE // 1024}KB.")

            # ── Auth & Usage Tracking ──
            auth_header = self.headers.get("Authorization", "")
            api_key = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
            client_ip = self.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()

            auth_info = {}
            if api_key:
                validation = _validate_api_key(api_key)
                if not validation["valid"]:
                    return self._error(401, f"Invalid API key: {validation['reason']}. Get a key at POST /api/keys.")

                key_hash = validation["key_hash"]
                credits = _get_credit_balance(key_hash)

                if credits <= 0:
                    return self._error(402,
                        "No scan credits remaining. "
                        "Buy more at /api/checkout?pack=500&key=YOUR_KEY or /shadow-ai"
                    )

                remaining = _deduct_credit(key_hash)
                if remaining < 0:
                    return self._error(402, "No scan credits remaining.")

                scan_count = _track_usage(key_hash)
                auth_info = {
                    "authenticated": True,
                    "tier": validation["tier"],
                    "scans_this_month": scan_count,
                    "credits_remaining": remaining,
                    "email": validation["email"],
                }
            else:
                free_check = _check_free_tier(client_ip)
                if not free_check["allowed"]:
                    return self._error(429,
                        f"Free tier limit reached ({FREE_TIER_SCANS} scans/month). "
                        f"Get an API key and buy credits at airblackbox.ai/shadow-ai"
                    )
                _increment_free_tier(client_ip)
                auth_info = {
                    "authenticated": False,
                    "tier": "free",
                    "scans_this_month": free_check["used"] + 1,
                    "scans_remaining": FREE_TIER_SCANS - free_check["used"] - 1,
                }

            start = time.time()

            if texts and len(texts) > 1:
                # Batch mode
                results = []
                for t in texts[:20]:
                    result = detect_ai_text(t, context=context, texts_batch=texts)
                    results.append(result)

                scores = [r["score"] for r in results]
                avg_score = sum(scores) / len(scores)
                high_risk_count = sum(1 for s in scores if s >= 0.6)

                duration_ms = int((time.time() - start) * 1000)
                response = {
                    "mode": "batch",
                    "results": results,
                    "batch_summary": {
                        "total_texts": len(results),
                        "average_score": round(avg_score, 3),
                        "high_risk_count": high_risk_count,
                        "verdict": "shadow_ai_detected" if high_risk_count > 0 else "no_shadow_ai_detected",
                    },
                    "meta": {
                        "scan_duration_ms": duration_ms,
                        "context": context,
                        "engine": "air-blackbox-shadow-detect",
                        "version": "0.3.0",
                        "method": "statistical_heuristic",
                        "disclaimer": (
                            "Detection uses statistical heuristics (vocabulary, "
                            "sentence structure, hedging patterns), not a trained ML "
                            "model. Results are indicative, not definitive. "
                            "Sophisticated AI-generated text may evade detection."
                        ),
                    },
                    "auth": auth_info,
                }
            else:
                # Single text mode
                if not text and texts:
                    text = texts[0]
                result = detect_ai_text(text, context=context)
                duration_ms = int((time.time() - start) * 1000)
                response = {
                    "mode": "single",
                    **result,
                    "meta": {
                        "scan_duration_ms": duration_ms,
                        "context": context,
                        "engine": "air-blackbox-shadow-detect",
                        "version": "0.3.0",
                        "method": "statistical_heuristic",
                        "disclaimer": (
                            "Detection uses statistical heuristics (vocabulary, "
                            "sentence structure, hedging patterns), not a trained ML "
                            "model. Results are indicative, not definitive. "
                            "Sophisticated AI-generated text may evade detection."
                        ),
                    },
                    "auth": auth_info,
                }

            self._json_response(200, response)

        except Exception as e:
            self._error(500, f"Detection failed: {str(e)[:200]}")

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
