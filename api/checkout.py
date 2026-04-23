"""
AIR Blackbox Console — Stripe Checkout

Creates a Stripe Checkout Session for the Pro plan ($49/month).
Redirects the user to Stripe's hosted checkout page.

GET /api/checkout  → redirects to Stripe Checkout
GET /api/checkout?annual=true  → redirects to annual plan (if configured)

Environment variables (set in Vercel):
  STRIPE_SECRET_KEY   — sk_test_... or sk_live_...
  STRIPE_PRICE_ID     — price_... for the $49/mo Pro plan
"""

import json
import os
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
BASE_URL = os.environ.get("BASE_URL", "https://airblackbox.ai")


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Stripe not configured"}).encode())
            return

        # Build Stripe Checkout Session via API
        # Using urllib (stdlib) instead of stripe package to avoid dependencies
        data = urllib.parse.urlencode({
            "mode": "subscription",
            "line_items[0][price]": STRIPE_PRICE_ID,
            "line_items[0][quantity]": "1",
            "success_url": BASE_URL + "/console/success?session_id={CHECKOUT_SESSION_ID}",
            "cancel_url": BASE_URL + "/console/scan",
            "allow_promotion_codes": "true",
            "billing_address_collection": "auto",
            "tax_id_collection[enabled]": "true",
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.stripe.com/v1/checkout/sessions",
            data=data,
            method="POST",
        )
        req.add_header("Authorization", f"Bearer {STRIPE_SECRET_KEY}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                session = json.loads(resp.read().decode("utf-8"))

            checkout_url = session.get("url")
            if not checkout_url:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "No checkout URL returned"}).encode())
                return

            # Redirect to Stripe Checkout
            self.send_response(303)
            self.send_header("Location", checkout_url)
            self.end_headers()

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")[:500]
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": f"Stripe API error: {e.code}",
                "detail": error_body,
            }).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)[:200]}).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "https://airblackbox.ai")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()
