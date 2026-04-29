"""
AIR Blackbox — Policy Verification API

Vercel serverless function that checks whether an AI action
(tool call, model usage, provider) is allowed by a company's
policy. Returns approve/deny/flag with the matching rule.

POST /api/policy
Body: {
    "action": "send_email",
    "model": "gpt-4o",
    "provider": "openai",
    "framework": "langchain",
    "policy": { ... }  // or use a saved policy ID
}
Returns: {
    "decision": "deny",
    "reason": "Model gpt-4o is not in the approved list",
    "matched_rule": { ... },
    "risk_level": "high"
}

Uses same API key and credit system as /api/detect.
"""

import hashlib
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler

import redis as redis_lib


# ============================================================
# Config & Redis
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")
KEY_PREFIX = "airbb_sk_"
FREE_TIER_SCANS = 25
MAX_BODY_SIZE = 100_000  # 100KB

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
# Auth helpers (same as detect.py)
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
# Default Policy (used when no custom policy is provided)
# ============================================================

DEFAULT_POLICY = {
    "name": "AIR Blackbox Default Policy",
    "version": "1.0",
    "rules": [
        {
            "id": "approved-providers",
            "description": "Only allow approved AI providers",
            "type": "provider_allowlist",
            "allowed": ["openai", "anthropic", "google", "azure", "aws-bedrock"],
            "action": "deny",
            "risk_level": "high",
        },
        {
            "id": "approved-models",
            "description": "Block known deprecated or unsafe models",
            "type": "model_blocklist",
            "blocked": [
                "gpt-3.5-turbo-0301", "gpt-3.5-turbo-0613",
                "text-davinci-003", "text-davinci-002",
                "code-davinci-002",
            ],
            "action": "deny",
            "risk_level": "medium",
        },
        {
            "id": "high-risk-actions",
            "description": "Flag dangerous tool actions for human review",
            "type": "action_blocklist",
            "blocked": [
                "delete_user", "drop_table", "rm_rf",
                "send_payment", "transfer_funds", "execute_trade",
                "modify_permissions", "grant_access", "revoke_access",
                "deploy_production", "push_to_main",
            ],
            "action": "flag",
            "risk_level": "critical",
        },
        {
            "id": "pii-actions",
            "description": "Flag actions that may expose PII",
            "type": "action_pattern",
            "patterns": [
                "export.*user", "download.*customer", "send.*email.*bulk",
                "share.*data", "log.*personal", "store.*ssn",
                "collect.*biometric",
            ],
            "action": "flag",
            "risk_level": "high",
        },
        {
            "id": "framework-check",
            "description": "Flag unrecognized frameworks",
            "type": "framework_allowlist",
            "allowed": [
                "langchain", "crewai", "autogen", "openai-agents",
                "anthropic-sdk", "google-adk", "haystack", "dspy",
                "pydantic-ai", "llamaindex",
            ],
            "action": "flag",
            "risk_level": "low",
        },
    ],
}


# ============================================================
# Policy Engine
# ============================================================

def evaluate_policy(action_data: dict, policy: dict = None) -> dict:
    """
    Evaluate an AI action against a policy.

    Args:
        action_data: {
            "action": "send_email",       # tool/function name
            "model": "gpt-4o",            # model being used
            "provider": "openai",          # AI provider
            "framework": "langchain",      # agent framework
            "metadata": {}                 # optional extra context
        }
        policy: Custom policy dict, or None to use default.

    Returns:
        {
            "decision": "approve" | "deny" | "flag",
            "reason": "...",
            "matched_rules": [...],
            "risk_level": "critical" | "high" | "medium" | "low" | "none",
            "policy_name": "...",
            "policy_version": "...",
        }
    """
    if policy is None:
        policy = DEFAULT_POLICY

    action = (action_data.get("action") or "").lower().strip()
    model = (action_data.get("model") or "").lower().strip()
    provider = (action_data.get("provider") or "").lower().strip()
    framework = (action_data.get("framework") or "").lower().strip()

    matched_rules = []
    overall_decision = "approve"
    overall_risk = "none"

    risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

    for rule in policy.get("rules", []):
        rule_type = rule.get("type", "")
        rule_action = rule.get("action", "flag")
        rule_risk = rule.get("risk_level", "medium")
        match_reason = None

        # Provider allowlist
        if rule_type == "provider_allowlist" and provider:
            allowed = [p.lower() for p in rule.get("allowed", [])]
            if provider not in allowed:
                match_reason = f"Provider '{provider}' is not in the approved list: {', '.join(allowed)}"

        # Model blocklist
        elif rule_type == "model_blocklist" and model:
            blocked = [m.lower() for m in rule.get("blocked", [])]
            if model in blocked:
                match_reason = f"Model '{model}' is blocked by policy"

        # Model allowlist
        elif rule_type == "model_allowlist" and model:
            allowed = [m.lower() for m in rule.get("allowed", [])]
            if model not in allowed:
                match_reason = f"Model '{model}' is not in the approved list"

        # Action blocklist
        elif rule_type == "action_blocklist" and action:
            blocked = [a.lower() for a in rule.get("blocked", [])]
            if action in blocked:
                match_reason = f"Action '{action}' is blocked by policy"

        # Action pattern matching
        elif rule_type == "action_pattern" and action:
            for pattern in rule.get("patterns", []):
                if re.search(pattern, action, re.IGNORECASE):
                    match_reason = f"Action '{action}' matches restricted pattern '{pattern}'"
                    break

        # Framework allowlist
        elif rule_type == "framework_allowlist" and framework:
            allowed = [f.lower() for f in rule.get("allowed", [])]
            if framework not in allowed:
                match_reason = f"Framework '{framework}' is not in the approved list"

        # Custom rule with regex on any field
        elif rule_type == "custom":
            field = rule.get("field", "")
            pattern = rule.get("pattern", "")
            value = action_data.get(field, "")
            if value and pattern and re.search(pattern, str(value), re.IGNORECASE):
                match_reason = f"Custom rule matched: {rule.get('description', rule.get('id', 'unknown'))}"

        if match_reason:
            matched_rules.append({
                "rule_id": rule.get("id", "unknown"),
                "description": rule.get("description", ""),
                "decision": rule_action,
                "risk_level": rule_risk,
                "reason": match_reason,
            })

            # Escalate: deny > flag > approve
            if rule_action == "deny" and overall_decision != "deny":
                overall_decision = "deny"
            elif rule_action == "flag" and overall_decision == "approve":
                overall_decision = "flag"

            # Track highest risk
            if risk_order.get(rule_risk, 0) > risk_order.get(overall_risk, 0):
                overall_risk = rule_risk

    if not matched_rules:
        reason = "All checks passed. Action is approved by policy."
    elif overall_decision == "deny":
        reasons = [r["reason"] for r in matched_rules if r["decision"] == "deny"]
        reason = reasons[0] if reasons else "Denied by policy rule"
    elif overall_decision == "flag":
        reasons = [r["reason"] for r in matched_rules if r["decision"] == "flag"]
        reason = reasons[0] if reasons else "Flagged for human review"
    else:
        reason = "Approved with notes"

    return {
        "decision": overall_decision,
        "reason": reason,
        "matched_rules": matched_rules,
        "risk_level": overall_risk,
        "policy_name": policy.get("name", "Unknown"),
        "policy_version": policy.get("version", "unknown"),
    }


# ============================================================
# HTTP Handler
# ============================================================

class handler(BaseHTTPRequestHandler):

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return self._error(400, "Request body is empty.")
            if content_length > MAX_BODY_SIZE:
                return self._error(413, "Request too large.")

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._error(400, 'Invalid JSON. Send: {"action": "...", "model": "...", "provider": "..."}')

            # Need at least one field to check
            action = data.get("action", "")
            model = data.get("model", "")
            provider = data.get("provider", "")
            framework = data.get("framework", "")

            if not any([action, model, provider, framework]):
                return self._error(400,
                    "Provide at least one of: action, model, provider, framework")

            # Auth & credits (same pattern as detect.py)
            auth_header = self.headers.get("Authorization", "")
            api_key = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
            client_ip = self.headers.get("X-Forwarded-For", "unknown").split(",")[0].strip()

            auth_info = {}
            if api_key:
                validation = _validate_api_key(api_key)
                if not validation["valid"]:
                    return self._error(401, f"Invalid API key: {validation['reason']}")

                key_hash = validation["key_hash"]
                credits = _get_credit_balance(key_hash)
                if credits <= 0:
                    return self._error(402, "No scan credits remaining. Buy more at /shadow-ai")

                remaining = _deduct_credit(key_hash)
                if remaining < 0:
                    return self._error(402, "No scan credits remaining.")

                scan_count = _track_usage(key_hash)
                auth_info = {
                    "authenticated": True,
                    "tier": validation["tier"],
                    "credits_remaining": remaining,
                }
            else:
                free_check = _check_free_tier(client_ip)
                if not free_check["allowed"]:
                    return self._error(429,
                        f"Free tier limit reached ({FREE_TIER_SCANS}/month). Get an API key at /shadow-ai")
                _increment_free_tier(client_ip)
                auth_info = {
                    "authenticated": False,
                    "tier": "free",
                    "scans_remaining": FREE_TIER_SCANS - free_check["used"] - 1,
                }

            # Run policy evaluation
            start = time.time()
            custom_policy = data.get("policy", None)
            action_data = {
                "action": action,
                "model": model,
                "provider": provider,
                "framework": framework,
                "metadata": data.get("metadata", {}),
            }
            result = evaluate_policy(action_data, custom_policy)
            duration_ms = int((time.time() - start) * 1000)

            response = {
                **result,
                "action_checked": action_data,
                "meta": {
                    "scan_duration_ms": duration_ms,
                    "engine": "air-blackbox-policy",
                    "version": "1.0.0",
                },
                "auth": auth_info,
            }

            self._json_response(200, response)

        except Exception as e:
            self._error(500, f"Policy check failed: {str(e)[:200]}")

    def do_OPTIONS(self):
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
