"""
AIR Blackbox Console — Stripe Checkout

Creates a Stripe Checkout Session for the Pro plan ($49/month).
Uses stdlib only (no stripe package) for maximum compatibility.
"""

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


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Debug: check if env vars are loaded
        if not STRIPE_SECRET_KEY:
            self._json(500, {"error": "STRIPE_SECRET_KEY not set in environment"})
            return
        if not STRIPE_PRICE_ID:
            self._json(500, {"error": "STRIPE_PRICE_ID not set in environment"})
            return

        try:
            # Build form data for Stripe API
            params = {
                "mode": "subscription",
                "line_items[0][price]": STRIPE_PRICE_ID,
                "line_items[0][quantity]": "1",
                "success_url": BASE_URL + "/console/success?session_id={CHECKOUT_SESSION_ID}",
                "cancel_url": BASE_URL + "/console/scan",
            }
            data = urllib.parse.urlencode(params).encode("utf-8")

            # Create SSL context
            ctx = ssl.create_default_context()

            req = urllib.request.Request(
                "https://api.stripe.com/v1/checkout/sessions",
                data=data,
                method="POST",
            )
            req.add_header("Authorization", "Bearer " + STRIPE_SECRET_KEY)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                body = resp.read().decode("utf-8")
                session = json.loads(body)

            checkout_url = session.get("url", "")
            if not checkout_url:
                self._json(500, {
                    "error": "Stripe returned no checkout URL",
                    "session_id": session.get("id", "unknown"),
                })
                return

            # Redirect to Stripe
            self.send_response(303)
            self.send_header("Location", checkout_url)
            self.end_headers()

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")[:500]
            self._json(400, {
                "error": "Stripe API returned " + str(e.code),
                "detail": error_body,
            })

        except Exception as e:
            self._json(500, {
                "error": "Checkout failed: " + type(e).__name__,
                "detail": str(e)[:300],
            })

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
