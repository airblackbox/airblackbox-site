"""
AIR Blackbox Console — Stripe Checkout

Creates a Stripe Checkout Session for the Pro plan ($49/month).
Redirects the user to Stripe's hosted checkout page.

GET /api/checkout  → redirects to Stripe Checkout
"""

import json
import os
from http.server import BaseHTTPRequestHandler

import stripe

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")
BASE_URL = os.environ.get("BASE_URL", "https://airblackbox.ai")


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if not stripe.api_key or not STRIPE_PRICE_ID:
            self._json(500, {
                "error": "Stripe not configured",
                "detail": "STRIPE_SECRET_KEY or STRIPE_PRICE_ID env var missing"
            })
            return

        try:
            session = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
                success_url=BASE_URL + "/console/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=BASE_URL + "/console/scan",
                allow_promotion_codes=True,
                billing_address_collection="auto",
            )

            # Redirect to Stripe Checkout
            self.send_response(303)
            self.send_header("Location", session.url)
            self.end_headers()

        except stripe.error.AuthenticationError as e:
            self._json(401, {"error": "Stripe authentication failed. Check API key.", "detail": str(e)[:200]})

        except stripe.error.InvalidRequestError as e:
            self._json(400, {"error": "Stripe invalid request. Check price ID.", "detail": str(e)[:200]})

        except Exception as e:
            self._json(500, {"error": "Checkout failed", "detail": str(e)[:200]})

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
