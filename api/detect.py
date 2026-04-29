"""
AIR Blackbox — Shadow AI Detection API

Vercel serverless function that analyzes text (recruiter notes,
screening feedback, candidate evaluations) and returns a confidence
score for whether it was AI-generated.

This is the infrastructure layer. HR tech vendors (ATS platforms,
recruiting tools) call this API to detect unsanctioned AI usage
in hiring workflows.

POST /api/detect
Body: { "text": "...", "context": "screening_note" }
Returns: { "score": 0.82, "verdict": "likely_ai", "signals": [...], ... }

Detection approach: statistical feature extraction (no external ML
dependencies). Catches LLM writing patterns through:
  1. Hedging phrase density (LLMs hedge constantly)
  2. Sentence length uniformity (humans vary, LLMs don't)
  3. Vocabulary sophistication consistency
  4. Formulaic structure detection
  5. Filler phrase patterns unique to LLMs
  6. Paragraph uniformity
  7. Recruiter-specific AI patterns
"""

import json
import math
import re
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler


# ============================================================
# Rate limiting
# ============================================================
_DETECT_LOG = {}
FREE_DETECTS_PER_MONTH = 25
RATE_WINDOW = 30 * 24 * 3600
MAX_TEXT_SIZE = 50_000  # 50KB — plenty for recruiter notes


# ============================================================
# Signal Detectors
# ============================================================

# --- Signal 1: Hedging Phrases ---
# LLMs use hedging language at 3-5x the rate of human writers.
# These are phrases that soften claims — humans in recruiting
# notes are typically direct ("strong candidate" not "it's
# worth noting that this candidate demonstrates potential").

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

# --- Signal 2: Formulaic Evaluation Language ---
# LLMs produce evaluation text with very specific structures
# that real recruiters almost never use in screening notes.

FORMULAIC_PATTERNS = [
    r"\bdemonstrates?\s+(?:strong|solid|excellent|good|clear)\s+(?:competenc|skill|abilit|understand|knowledge|experience)",
    r"\bexhibits?\s+(?:strong|solid|excellent|good|clear)\s+",
    r"\bshowcases?\s+(?:strong|solid|excellent|a deep|a clear)\s+",
    r"\bpossesses?\s+(?:strong|solid|excellent|good|the)\s+",
    r"\baligns?\s+(?:well|closely|strongly)\s+with\b",
    r"\bwell[- ]suited\s+for\b",
    r"\bwould\s+be\s+(?:a\s+)?(?:strong|great|good|excellent|ideal|valuable)\s+(?:addition|asset|fit|candidate)",
    r"\bbrings?\s+(?:a\s+)?(?:wealth|breadth|depth)\s+of\b",
    r"\bhas\s+a\s+(?:proven|strong|solid)\s+track\s+record\b",
    r"\bleverage[sd]?\s+(?:their|his|her)\s+(?:experience|expertise|skills|knowledge)\b",
    r"\b(?:strong|excellent|exceptional)\s+(?:communication|interpersonal|leadership|analytical)\s+skills\b",
    r"\bkey\s+(?:strengths?|takeaways?|highlights?)\s+include\b",
    r"\b(?:in\s+)?conclusion\b",
    r"\barea[s]?\s+(?:for|of)\s+(?:improvement|growth|development|concern)\b",
    r"\bpotential\s+(?:areas?\s+)?(?:for|of)\s+(?:growth|improvement|development)\b",
]

# --- Signal 3: LLM-Specific Filler ---
# Phrases that are signature LLM output. Real humans almost
# never write these in professional notes.

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
    r"\bspecifically\b.*\bspecifically\b",  # double use in one text
    r"\brobust\s+(?:experience|background|skill|understanding)\b",
    r"\bcomprehensive\s+(?:experience|background|skill|understanding|knowledge)\b",
    r"\bmeticulous(?:ly)?\b",
    r"\bseamless(?:ly)?\b",
    r"\bholistic(?:ally)?\b",
    r"\bsynerg(?:y|ies|istic)\b",
    r"\bthroughout\s+(?:their|his|her)\s+career\b",
]

# --- Signal 4: Recruiter-Specific AI Patterns ---
# When recruiters use ChatGPT for screening, the output has
# distinctive patterns that differ from genuine recruiter notes.

RECRUITER_AI_PATTERNS = [
    # Structured evaluation headers that LLMs love to add
    r"(?:^|\n)\s*(?:Strengths?|Weaknesses?|Areas?\s+(?:of|for)\s+(?:Improvement|Concern)|Summary|Assessment|Recommendation|Evaluation|Key\s+(?:Points?|Observations?|Findings?)|Pros?|Cons?)\s*[:\-]",
    # Numbered or bulleted points in screening notes (humans rarely do this)
    r"(?:^|\n)\s*(?:\d+[\.\)]\s+|[-*]\s+)(?:Strong|Demonstrates?|Has|Possesses?|Exhibits?|Shows?)\s+",
    # Rating scales that LLMs inject
    r"\b(?:rating|score)\s*:\s*\d+\s*/\s*\d+\b",
    r"\b\d+\s*/\s*(?:5|10)\b",
    # Comparison language (LLMs compare to ideal, humans compare to other candidates)
    r"\bcompared\s+to\s+(?:the\s+)?(?:ideal|typical|average|standard)\b",
    # Meta-commentary about the evaluation itself
    r"\bbased\s+on\s+(?:the\s+)?(?:resume|CV|application|materials?|information)\s+(?:provided|reviewed|submitted)\b",
]


def _count_pattern_matches(text: str, patterns: list) -> list:
    """Return list of (pattern_desc, count) for each matching pattern."""
    matches = []
    for p in patterns:
        found = re.findall(p, text, re.IGNORECASE | re.MULTILINE)
        if found:
            # Clean up the pattern for display
            clean = p.replace(r"\b", "").replace(r"\s+", " ").replace(r"[''']?", "'")
            clean = re.sub(r'\(.*?\)', '...', clean)[:60]
            matches.append({"pattern": clean, "count": len(found)})
    return matches


def _sentence_uniformity(text: str) -> dict:
    """Measure how uniform sentence lengths are.

    Humans write with high variance (short punchy sentences mixed
    with long complex ones). LLMs produce eerily uniform sentence
    lengths. We measure this with coefficient of variation (CV).

    CV < 0.3 = very uniform (AI signal)
    CV 0.3-0.5 = moderate (inconclusive)
    CV > 0.5 = high variance (human signal)
    """
    # Split on sentence-ending punctuation
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
    """Measure paragraph length uniformity.

    Same principle as sentence uniformity but at paragraph level.
    LLMs produce very uniform paragraph sizes.
    """
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
    """Analyze vocabulary sophistication and diversity.

    LLM-generated text tends to have:
    - Higher type-token ratio (more unique words per total words)
    - More polysyllabic words consistently throughout
    - Less colloquial/informal language
    """
    words = re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())
    if len(words) < 20:
        return {"ttr": 0.5, "signal": "insufficient_data"}

    unique_words = set(words)
    total_words = len(words)
    ttr = len(unique_words) / total_words

    # Polysyllabic ratio (words with 4+ syllables)
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

    # LLM text: higher TTR (0.55+) and higher polysyllabic ratio (0.08+)
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
    """Detect when multiple texts from the same source share
    suspiciously similar structure (same recruiter evaluating
    different candidates with near-identical language).

    Only used when multiple texts are submitted in batch mode.
    """
    if len(texts) < 2:
        return {"similarity": 0, "signal": "single_text"}

    # Simple Jaccard similarity on word trigrams
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


def detect_ai_text(text: str, texts_batch: list = None) -> dict:
    """
    Analyze text for AI-generation signals.

    Returns a confidence score (0.0 to 1.0) and detailed signal breakdown.
    Score interpretation:
      0.0 - 0.3: likely human-written
      0.3 - 0.6: inconclusive
      0.6 - 0.8: likely AI-generated
      0.8 - 1.0: very likely AI-generated
    """
    word_count = len(text.split())
    if word_count < 15:
        return {
            "score": 0.0,
            "verdict": "insufficient_text",
            "detail": "Need at least 15 words for analysis",
            "signals": [],
        }

    signals = []
    weighted_scores = []

    # --- Hedging phrases (weight: 0.20) ---
    hedging_matches = _count_pattern_matches(text, HEDGING_PHRASES)
    hedging_count = sum(m["count"] for m in hedging_matches)
    hedging_density = hedging_count / (word_count / 100)  # per 100 words
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

    # --- Formulaic evaluation language (weight: 0.25) ---
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
    weighted_scores.append(("formulaic", formulaic_score, 0.25))
    if formulaic_matches:
        signals.append({
            "name": "Formulaic evaluation language",
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

    # --- Recruiter-specific AI patterns (weight: 0.15) ---
    recruiter_matches = _count_pattern_matches(text, RECRUITER_AI_PATTERNS)
    recruiter_count = sum(m["count"] for m in recruiter_matches)
    if recruiter_count >= 3:
        recruiter_score = 1.0
    elif recruiter_count >= 2:
        recruiter_score = 0.7
    elif recruiter_count >= 1:
        recruiter_score = 0.4
    else:
        recruiter_score = 0.1
    weighted_scores.append(("recruiter_patterns", recruiter_score, 0.15))
    if recruiter_matches:
        signals.append({
            "name": "Recruiter-specific AI patterns",
            "score": recruiter_score,
            "detail": f"{recruiter_count} recruiter AI patterns detected",
            "matches": recruiter_matches[:5],
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

    # --- Paragraph uniformity (weight: 0.05) ---
    para_analysis = _paragraph_uniformity(text)
    if para_analysis["signal"] == "ai_likely":
        para_score = 0.85
    elif para_analysis["signal"] == "inconclusive":
        para_score = 0.5
    else:
        para_score = 0.15
    weighted_scores.append(("paragraph_uniformity", para_score, 0.05))
    signals.append({
        "name": "Paragraph uniformity",
        "score": para_score,
        "detail": f"CV={para_analysis['cv']}, {para_analysis.get('paragraph_count', 0)} paragraphs",
        "analysis": para_analysis,
    })

    # --- Cross-text similarity (bonus signal, not in base weight) ---
    if texts_batch and len(texts_batch) > 1:
        cross_analysis = _cross_text_similarity(texts_batch)
        if cross_analysis["signal"] == "ai_likely":
            cross_score = 0.9
        elif cross_analysis["signal"] == "inconclusive":
            cross_score = 0.5
        else:
            cross_score = 0.15
        # Add as bonus weight (0.10) that adjusts the final score
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

    # Apply confidence adjustment for very short texts
    if word_count < 50:
        # Pull score toward 0.5 (less confident) for short texts
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

    # Regulatory implications
    regulations = []
    if composite >= 0.6:
        regulations = [
            {"law": "NYC Local Law 144", "risk": "AEDT use without bias audit", "status": "in_effect"},
            {"law": "Illinois HB 3773", "risk": "AI screening without disclosure", "status": "in_effect"},
            {"law": "California FEHA", "risk": "AI vendor liability, 4-year retention required", "status": "in_effect"},
            {"law": "Colorado CAIA", "risk": "Developer duty of care for AI hiring tools", "status": "effective_june_2026"},
            {"law": "EU AI Act Annex III", "risk": "High-risk AI in employment (Art. 6)", "status": "effective_august_2026"},
        ]

    return {
        "score": composite,
        "verdict": verdict,
        "word_count": word_count,
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
                return self._error(400, 'Invalid JSON. Send: {"text": "...recruiter evaluation text..."}')

            # Support single text or batch mode
            text = data.get("text", "")
            texts = data.get("texts", [])
            context = data.get("context", "screening_note")

            if not text and not texts:
                return self._error(400, "No text provided. Send 'text' (single) or 'texts' (batch array).")

            if text and len(text) > MAX_TEXT_SIZE:
                return self._error(413, f"Text too large. Maximum size is {MAX_TEXT_SIZE // 1024}KB.")

            # Rate limiting
            client_ip = self.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()
            now = time.time()
            if client_ip in _DETECT_LOG:
                _DETECT_LOG[client_ip] = [t for t in _DETECT_LOG[client_ip] if now - t < RATE_WINDOW]
                if len(_DETECT_LOG[client_ip]) >= FREE_DETECTS_PER_MONTH:
                    return self._error(429, f"Free tier limit reached ({FREE_DETECTS_PER_MONTH} detections per month). Contact us for API access.")
            else:
                _DETECT_LOG[client_ip] = []
            _DETECT_LOG[client_ip].append(now)

            start = time.time()

            if texts and len(texts) > 1:
                # Batch mode: analyze multiple texts + cross-similarity
                results = []
                for t in texts[:20]:  # cap at 20 texts per batch
                    result = detect_ai_text(t, texts_batch=texts)
                    results.append(result)

                # Aggregate batch stats
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
                        "version": "0.1.0",
                    },
                }
            else:
                # Single text mode
                if not text and texts:
                    text = texts[0]
                result = detect_ai_text(text)
                duration_ms = int((time.time() - start) * 1000)
                response = {
                    "mode": "single",
                    **result,
                    "meta": {
                        "scan_duration_ms": duration_ms,
                        "context": context,
                        "engine": "air-blackbox-shadow-detect",
                        "version": "0.1.0",
                    },
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
