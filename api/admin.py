"""
AIR Blackbox — Admin Dashboard API

Simple admin endpoint to view API key signups, usage stats,
and credit purchases. Protected by ADMIN_SECRET env var.

GET /api/admin?secret=YOUR_SECRET           — recent signups + stats
GET /api/admin?secret=YOUR_SECRET&limit=100 — more signups
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler
import urllib.parse

import redis as redis_lib


# ============================================================
# Config & Redis
# ============================================================

REDIS_URL = os.environ.get("REDIS_URL", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")

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
# Data helpers
# ============================================================

def _get_signups(limit=50):
    """Get recent signups from the signups list."""
    r = _get_redis()
    if not r:
        return []
    try:
        raw_list = r.lrange("signups", 0, limit - 1)
        return [json.loads(item) for item in raw_list]
    except Exception:
        return []


def _get_total_signups():
    """Get total number of signups tracked."""
    r = _get_redis()
    if not r:
        return 0
    try:
        return r.llen("signups")
    except Exception:
        return 0


def _get_recent_purchases(limit=50):
    """Get recent credit purchases across all keys."""
    r = _get_redis()
    if not r:
        return []
    try:
        # Scan for purchase log keys
        purchases = []
        cursor = 0
        checked = 0
        while checked < 200:  # limit scan iterations
            cursor, keys = r.scan(cursor, match="purchases:*", count=50)
            for key in keys:
                items = r.lrange(key, 0, 4)  # last 5 per key
                for item in items:
                    try:
                        purchases.append(json.loads(item))
                    except (json.JSONDecodeError, TypeError):
                        pass
            checked += 50
            if cursor == 0:
                break
        # Sort by timestamp descending
        purchases.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return purchases[:limit]
    except Exception:
        return []


def _get_active_key_count():
    """Count active API keys (approximate via scan)."""
    r = _get_redis()
    if not r:
        return 0
    try:
        count = 0
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="apikey:*", count=100)
            for key in keys:
                raw = r.get(key)
                if raw:
                    try:
                        meta = json.loads(raw)
                        if meta.get("active", False):
                            count += 1
                    except (json.JSONDecodeError, TypeError):
                        pass
            if cursor == 0:
                break
        return count
    except Exception:
        return 0


def _get_month_usage_stats():
    """Get total API usage across all keys this month."""
    r = _get_redis()
    if not r:
        return {"month": "", "total_calls": 0}
    try:
        month = time.strftime("%Y-%m", time.gmtime())
        total = 0
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match=f"usage:*:{month}", count=100)
            for key in keys:
                val = r.get(key)
                if val:
                    total += int(val)
            if cursor == 0:
                break
        return {"month": month, "total_calls": total}
    except Exception:
        return {"month": "", "total_calls": 0}


# ============================================================
# HTTP Handler
# ============================================================

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Check admin secret
        if not ADMIN_SECRET:
            return self._error(503, "ADMIN_SECRET not configured. Add it as a Vercel env var.")

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        secret = qs.get("secret", [None])[0]

        if secret != ADMIN_SECRET:
            return self._error(401, "Invalid admin secret.")

        limit = int(qs.get("limit", ["50"])[0])
        if limit > 500:
            limit = 500

        # Gather all stats
        signups = _get_signups(limit)
        total_signups = _get_total_signups()
        active_keys = _get_active_key_count()
        usage = _get_month_usage_stats()
        purchases = _get_recent_purchases(limit)

        response = {
            "summary": {
                "total_signups_tracked": total_signups,
                "active_api_keys": active_keys,
                "api_calls_this_month": usage["total_calls"],
                "month": usage["month"],
                "checked_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
            },
            "recent_signups": signups,
            "recent_purchases": purchases,
        }

        self._json_response(200, response)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def _json_response(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def _error(self, status, message):
        self._json_response(status, {"error": message})

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
