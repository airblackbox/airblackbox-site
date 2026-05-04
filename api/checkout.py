"""
AIR Blackbox - Stripe Checkout

Supports two products:
  1. Pro plan subscription ($49/month) - GET /api/checkout
  2. Scan credit packs (one-time) - GET /api/checkout?pack=500|2000|10000&key=airbb_sk_...

Uses stdlib only (no stripe package) for maximum compatibility.
"""

import hashlib
import json
import os
import ssl
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
BASE_URL = "https://airblackbox.ai"

# API credit packs: pack_size -> (price_cents, display_name, per_call_price)
SCAN_PACKS = {
    "500":   (1500,  "500 API Credits",    "$0.030"),
    "2000":  (5000,  "2,000 API Credits",  "$0.025"),
    "10000": (15000, "10,000 API Credits", "$0.015"),
}


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if not STRIPE_SECRET_KEY:
            self._json(500, {"error": "STRIPE_SECRET_KEY not set in environment"})
            return

        # Parse query string
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        pack = qs.get("pack", [None])[0]
        api_key = qs.get("key", [None])[0]

        if pack:
            self._handle_scan_pack(pack, api_key)
        else:
            self._handle_pro_subscription()

    def _handle_scan_pack(self, pack, api_key):
        """Create Stripe Checkout for a scan credit pack."""
        if pack not in SCAN_PACKS:
            self._json(400, {
                "error": f"Invalid pack size. Choose: {', '.join(SCAN_PACKS.keys())}",
            })
            return

        if not api_key or not api_key.startswith("airbb_sk_"):
            self._json(400, {
                "error": "API key required. Pass ?key=airbb_sk_... to link credits to your account.",
            })
            return

        price_cents, display_name, per_scan = SCAN_PACKS[pack]
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        try:
            params = {
                "mode": "payment",
                "line_items[0][price_data][currency]": "usd",
                "line_items[0][price_data][unit_amount]": str(price_cents),
                "line_items[0][price_data][product_data][name]": f"AIR Blackbox - {display_name}",
                "line_items[0][price_data][product_data][description]": f"API credits for Detect, Policy, and Scan ({per_scan}/call)",
                "line_items[0][quantity]": "1",
                "metadata[product]": "scan_credits",
                "metadata[pack_size]": pack,
                "metadata[key_hash]": key_hash,
                "success_url": BASE_URL + "/shadow-ai?purchased=" + pack,
                "cancel_url": BASE_URL + "/shadow-ai",
            }
            data = urllib.parse.urlencode(params).encode("utf-8")
            ctx = ssl.create_default_context()

            req = urllib.request.Request(
                "https://api.stripe.com/v1/checkout/sessions",
                data=data,
                method="POST",
            )
            req.add_header("Authorization", "Bearer " + STRIPE_SECRET_KEY)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                session = json.loads(resp.read().decode("utf-8"))

            checkout_url = session.get("url", "")
            if not checkout_url:
                self._json(500, {"error": "Stripe returned no checkout URL"})
                return

            self.send_response(303)
            self.send_header("Location", checkout_url)
            self.end_headers()

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
            self._json(400, {"error": "Stripe error: " + error_body[:200]})
        except Exception as e:
            self._json(500, {"error": "Checkout failed: " + str(e)[:200]})

    def _handle_pro_subscription(self):
        """Create Stripe Checkout for the Pro plan subscription."""
        if not STRIPE_PRICE_ID:
            self._json(500, {"error": "STRIPE_PRICE_ID not set"})
            return

        try:
            params = {
                "mode": "subscription",
                "line_items[0][price]": STRIPE_PRICE_ID,
                "line_items[0][quantity]": "1",
                "success_url": BASE_URL + "/console/success?session_id={CHECKOUT_SESSION_ID}",
                "cancel_url": BASE_URL + "/console/scan",
            }
            data = urllib.parse.urlencode(params).encode("utf-8")
            ctx = ssl.create_default_context()

            req = urllib.request.Request(
                "https://api.stripe.com/v1/checkout/sessions",
                data=data,
                method="POST",
            )
            req.add_header("Authorization", "Bearer " + STRIPE_SECRET_KEY)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                session = json.loads(resp.read().decode("utf-8"))

            checkout_url = session.get("url", "")
            if not checkout_url:
                self._json(500, {"error": "Stripe returned no checkout URL"})
                return

            self.send_response(303)
            self.send_header("Location", checkout_url)
            self.end_headers()

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
            self._json(400, {"error": "Stripe API returned " + str(e.code), "detail": error_body})
        except Exception as e:
            self._json(500, {"error": "Checkout failed: " + str(e)[:300]})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://airblackbox.ai")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def _json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))
