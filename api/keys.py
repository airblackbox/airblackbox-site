"""
AIR Blackbox - API Key Management

Vercel serverless function for generating and managing API keys
for the Shadow AI Detection API.

POST /api/keys   - Generate a new API key (requires email)
GET  /api/keys   - Check key status (requires Authorization header)
DELETE /api/keys - Revoke a key (requires Authorization header)

Storage: Standard Redis via REDIS_URL environment variable.
"""

import hashlib
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler

import redis as redis_lib

# ============================================================
# Config
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")

KEY_PREFIX = "airbb_sk_"
FREE_TIER_SCANS = 25  # per month, no key needed
STARTER_TIER_SCANS = 5_000  # per month

# Pricing tiers (per scan above free tier)
PRICING = {
    "free": {"monthly_limit": 25, "per_scan": 0.0},
    "starter": {"monthly_limit": 5_000, "per_scan": 0.03},
    "growth": {"monthly_limit": 100_000, "per_scan": 0.02},
    "enterprise": {"monthly_limit": None, "per_scan": 0.01},  # unlimited
}


# ============================================================
# Redis Connection
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


def _kv_set(key: str, value: str, ex: int = None) -> bool:
    """Set a key in Redis. Optional expiry in seconds."""
    r = _get_redis()
    if not r:
        return False
    try:
        if ex:
            r.set(key, value, ex=ex)
        else:
            r.set(key, value)
        return True
    except Exception:
        return False


def _kv_get(key: str) -> str:
    """Get a value from Redis. Returns None if not found."""
    r = _get_redis()
    if not r:
        return None
    try:
        return r.get(key)
    except Exception:
        return None


def _kv_incr(key: str) -> int:
    """Increment a counter in Redis. Returns new value."""
    r = _get_redis()
    if not r:
        return 0
    try:
        return r.incr(key)
    except Exception:
        return 0


def _kv_expire(key: str, seconds: int) -> bool:
    """Set expiry on a key."""
    r = _get_redis()
    if not r:
        return False
    try:
        return r.expire(key, seconds)
    except Exception:
        return False


def _kv_del(key: str) -> bool:
    """Delete a key."""
    r = _get_redis()
    if not r:
        return False
    try:
        return r.delete(key) >= 1
    except Exception:
        return False


def _kv_ttl(key: str) -> int:
    """Get TTL of a key in seconds. -1 = no expiry, -2 = key doesn't exist."""
    r = _get_redis()
    if not r:
        return -2
    try:
        return r.ttl(key)
    except Exception:
        return -2


# ============================================================
# API Key Helpers
# ============================================================

def generate_api_key() -> str:
    """Generate a new API key.

    Format: airbb_sk_ + 32 random hex chars
    Example: airbb_sk_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4
    """
    random_part = secrets.token_hex(16)
    return f"{KEY_PREFIX}{random_part}"


def hash_key(api_key: str) -> str:
    """Hash an API key for storage (never store raw keys).

    We store SHA-256 hash of the key. When a user sends their key,
    we hash it and look up the hash. This way even if KV is
    compromised, the actual keys are not exposed.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _current_month() -> str:
    """Return current year-month string like '2026-04'."""
    return time.strftime("%Y-%m", time.gmtime())


def store_api_key(api_key: str, email: str, tier: str = "starter") -> bool:
    """Store a new API key in KV.

    Stored data structure (as JSON string):
    {
        "email": "user@example.com",
        "tier": "starter",
        "created": 1714300000,
        "active": true
    }

    Keys stored:
    - apikey:{hash} -> key metadata (JSON)
    - email:{email} -> key hash (for lookup by email)
    """
    key_hash = hash_key(api_key)
    metadata = json.dumps({
        "email": email,
        "tier": tier,
        "created": int(time.time()),
        "active": True,
    })

    # Store key metadata
    ok1 = _kv_set(f"apikey:{key_hash}", metadata)
    # Store email -> hash mapping (for "I lost my key" lookup)
    ok2 = _kv_set(f"email:{email.lower().strip()}", key_hash)

    return ok1 and ok2


def validate_api_key(api_key: str) -> dict:
    """Validate an API key and return its metadata.

    Returns:
        {"valid": True, "email": "...", "tier": "...", ...} on success
        {"valid": False, "reason": "..."} on failure
    """
    if not api_key or not api_key.startswith(KEY_PREFIX):
        return {"valid": False, "reason": "Invalid key format"}

    key_hash = hash_key(api_key)
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
        "created": metadata.get("created", 0),
        "key_hash": key_hash,
    }


def track_usage(key_hash: str) -> int:
    """Increment usage counter for a key and return new count.

    Counter key: usage:{key_hash}:{YYYY-MM}
    Expires after 90 days (keeps 3 months of history).
    """
    month = _current_month()
    counter_key = f"usage:{key_hash}:{month}"
    count = _kv_incr(counter_key)

    # Set expiry on first use (90 days)
    if count == 1:
        _kv_expire(counter_key, 90 * 24 * 3600)

    return count


def get_usage(key_hash: str) -> dict:
    """Get usage stats for a key."""
    month = _current_month()
    counter_key = f"usage:{key_hash}:{month}"
    raw = _kv_get(counter_key)
    current_usage = int(raw) if raw else 0

    return {
        "month": month,
        "scans_used": current_usage,
    }


def get_credit_balance(key_hash: str) -> int:
    """Get remaining prepaid scan credits."""
    r = _get_redis()
    if not r:
        return 0
    try:
        val = r.get(f"credits:{key_hash}")
        return int(val) if val else 0
    except Exception:
        return 0


def track_free_tier(client_ip: str) -> dict:
    """Track free tier usage by IP address.

    Returns:
        {"allowed": True/False, "used": N, "limit": 25}
    """
    month = _current_month()
    counter_key = f"free:{client_ip}:{month}"
    raw = _kv_get(counter_key)
    current = int(raw) if raw else 0

    return {
        "allowed": current < FREE_TIER_SCANS,
        "used": current,
        "limit": FREE_TIER_SCANS,
    }


def increment_free_tier(client_ip: str) -> int:
    """Increment free tier counter. Returns new count."""
    month = _current_month()
    counter_key = f"free:{client_ip}:{month}"
    count = _kv_incr(counter_key)
    if count == 1:
        _kv_expire(counter_key, 45 * 24 * 3600)  # expire after 45 days
    return count


def _log_signup(email: str, key_hash: str):
    """Log a new API key signup to a Redis list for admin tracking."""
    r = _get_redis()
    if not r:
        return
    try:
        entry = json.dumps({
            "email": email,
            "key_hash": key_hash[:12] + "...",
            "timestamp": int(time.time()),
            "date": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        })
        r.lpush("signups", entry)
        # Keep last 500 signups
        r.ltrim("signups", 0, 499)
    except Exception:
        pass


def _get_signups(limit: int = 50) -> list:
    """Get recent signups from Redis."""
    r = _get_redis()
    if not r:
        return []
    try:
        raw_list = r.lrange("signups", 0, limit - 1)
        return [json.loads(item) for item in raw_list]
    except Exception:
        return []


def _get_total_keys() -> int:
    """Count total API keys ever created (approximate via signups list length)."""
    r = _get_redis()
    if not r:
        return 0
    try:
        return r.llen("signups")
    except Exception:
        return 0


# ============================================================
# HTTP Handler
# ============================================================

class handler(BaseHTTPRequestHandler):
    """Vercel serverless function handler for /api/keys."""

    def do_POST(self):
        """Generate a new API key."""
        try:
            # Check KV is configured
            if not REDIS_URL:
                return self._error(503, "API key service is not yet configured. Coming soon.")

            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return self._error(400, 'Send JSON with an "email" field.')

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                return self._error(400, 'Invalid JSON. Send: {"email": "you@example.com"}')

            email = data.get("email", "").strip().lower()
            if not email or "@" not in email or "." not in email:
                return self._error(400, "A valid email address is required.")

            # Check if email already has a key
            existing_hash = _kv_get(f"email:{email}")
            if existing_hash:
                existing_meta = _kv_get(f"apikey:{existing_hash}")
                if existing_meta:
                    meta = json.loads(existing_meta)
                    if meta.get("active"):
                        return self._error(409,
                            "This email already has an active API key. "
                            "Use GET /api/keys with your key to check status, "
                            "or DELETE /api/keys to revoke and generate a new one."
                        )

            # Generate and store the key
            api_key = generate_api_key()
            stored = store_api_key(api_key, email, tier="starter")

            if not stored:
                return self._error(500, "Failed to store API key. Please try again.")

            # Log the signup for admin tracking
            _log_signup(email, hash_key(api_key))

            self._json_response(201, {
                "api_key": api_key,
                "email": email,
                "tier": "starter",
                "monthly_limit": STARTER_TIER_SCANS,
                "free_scans_no_key": FREE_TIER_SCANS,
                "pricing": {
                    "per_scan": "$0.03",
                    "volume_discounts": {
                        "0-5000": "$0.03/scan",
                        "5001-100000": "$0.02/scan",
                        "100001+": "$0.01/scan",
                    },
                },
                "usage": {
                    "endpoint": "GET /api/keys",
                    "header": f"Authorization: Bearer {api_key}",
                },
                "important": "Save this key now. It will not be shown again.",
            })

        except Exception as e:
            self._error(500, f"Key generation failed: {str(e)[:200]}")

    def do_GET(self):
        """Check API key status and usage."""
        try:
            if not REDIS_URL:
                return self._error(503, "API key service is not yet configured. Coming soon.")

            api_key = self._get_bearer_token()
            if not api_key:
                return self._error(401, "Missing Authorization header. Send: Authorization: Bearer airbb_sk_...")

            validation = validate_api_key(api_key)
            if not validation["valid"]:
                return self._error(401, f"Invalid API key: {validation['reason']}")

            # Get usage stats and credit balance
            usage = get_usage(validation["key_hash"])
            credits = get_credit_balance(validation["key_hash"])
            tier = validation["tier"]
            tier_info = PRICING.get(tier, PRICING["starter"])

            self._json_response(200, {
                "status": "active",
                "email": validation["email"],
                "tier": tier,
                "created": validation["created"],
                "credits_remaining": credits,
                "usage": {
                    "month": usage["month"],
                    "scans_used": usage["scans_used"],
                },
                "pricing": {
                    "per_scan": f"${tier_info['per_scan']:.2f}",
                    "estimated_bill": f"${usage['scans_used'] * tier_info['per_scan']:.2f}",
                },
            })

        except Exception as e:
            self._error(500, f"Status check failed: {str(e)[:200]}")

    def do_DELETE(self):
        """Revoke an API key."""
        try:
            if not REDIS_URL:
                return self._error(503, "API key service is not yet configured. Coming soon.")

            api_key = self._get_bearer_token()
            if not api_key:
                return self._error(401, "Missing Authorization header.")

            validation = validate_api_key(api_key)
            if not validation["valid"]:
                return self._error(401, f"Invalid API key: {validation['reason']}")

            # Mark key as inactive (don't delete, keep for audit trail)
            key_hash = validation["key_hash"]
            raw = _kv_get(f"apikey:{key_hash}")
            if raw:
                metadata = json.loads(raw)
                metadata["active"] = False
                metadata["revoked_at"] = int(time.time())
                _kv_set(f"apikey:{key_hash}", json.dumps(metadata))

            # Remove email mapping so they can generate a new key
            email = validation["email"]
            if email:
                _kv_del(f"email:{email}")

            self._json_response(200, {
                "status": "revoked",
                "message": "API key has been revoked. You can generate a new one with POST /api/keys.",
            })

        except Exception as e:
            self._error(500, f"Key revocation failed: {str(e)[:200]}")

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    # ── Helpers ──────────────────────────────────────────

    def _get_bearer_token(self) -> str:
        """Extract Bearer token from Authorization header."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
