"""
AIR Blackbox Pro - Stripe Webhook Handler
Handles: checkout.session.completed -> provision VPS
         customer.subscription.deleted -> tear down VPS

Deployed as a Vercel serverless function at /api/webhook
"""

from http.server import BaseHTTPRequestHandler
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import urllib.error

import redis as redis_lib

# ── Environment variables (set in Vercel dashboard) ──────────────
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
REDIS_URL = os.environ.get("REDIS_URL", "")
DO_API_TOKEN = os.environ.get("DO_API_TOKEN", "")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "")
CLOUDFLARE_ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

# ── Config ───────────────────────────────────────────────────────
DO_REGION = "nyc1"
DO_SIZE = "s-2vcpu-4gb"  # 4GB RAM - enough for Ollama + gateway stack
DO_IMAGE = "ubuntu-22-04-x64"
DOMAIN = "airblackbox.ai"


# ── Redis connection (for scan credit fulfillment) ──────────────

_redis_client = None

def _get_redis():
    """Get a Redis client, reusing the connection."""
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


def handle_scan_credit_purchase(session):
    """Credit scan credits to a customer's API key in Redis.

    Reads metadata set by checkout.py:
      - product: "scan_credits"
      - pack_size: "500" | "2000" | "10000"
      - key_hash: SHA-256 hash of the customer's API key
    """
    metadata = session.get("metadata", {})
    pack_size = int(metadata.get("pack_size", "0"))
    key_hash = metadata.get("key_hash", "")

    if not pack_size or not key_hash:
        print(f"[WEBHOOK] Missing scan credit metadata: pack={pack_size}, hash={key_hash[:12]}...")
        return {"status": "error", "message": "Missing metadata"}

    r = _get_redis()
    if not r:
        print("[WEBHOOK] REDIS_URL not configured, cannot credit scans")
        return {"status": "error", "message": "Redis not configured"}

    # Credit key: credits:{key_hash} -- running total, no expiry
    credit_key = f"credits:{key_hash}"
    try:
        new_balance = r.incrby(credit_key, pack_size)
        # Log the purchase
        purchase_log = json.dumps({
            "pack_size": pack_size,
            "amount_cents": session.get("amount_total", 0),
            "stripe_session": session.get("id", ""),
            "customer_email": session.get("customer_details", {}).get("email", ""),
            "timestamp": int(time.time()),
        })
        r.rpush(f"purchases:{key_hash}", purchase_log)

        print(f"[WEBHOOK] Credited {pack_size} scans to {key_hash[:12]}... New balance: {new_balance}")
        return {"status": "credited", "scans_added": pack_size, "new_balance": new_balance}

    except Exception as e:
        print(f"[WEBHOOK] Redis error crediting scans: {e}")
        return {"status": "error", "message": str(e)[:200]}


class handler(BaseHTTPRequestHandler):
    """Vercel serverless function entry point."""

    def do_POST(self):
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Verify Stripe signature
        sig_header = self.headers.get("stripe-signature", "")
        if not verify_stripe_signature(body, sig_header, STRIPE_WEBHOOK_SECRET):
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Invalid signature"}).encode())
            return

        # Parse event
        event = json.loads(body)
        event_type = event.get("type", "")

        # Route events
        if event_type == "checkout.session.completed":
            session = event["data"]["object"]
            product = session.get("metadata", {}).get("product", "")
            if product == "scan_credits":
                result = handle_scan_credit_purchase(session)
            else:
                result = handle_checkout(event)
        elif event_type == "customer.subscription.deleted":
            result = handle_cancellation(event)
        else:
            result = {"status": "ignored", "event": event_type}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def do_GET(self):
        """Health check endpoint."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "ok", "service": "air-blackbox-webhook"}).encode())


def handle_checkout(event):
    """New Pro subscriber - provision their VPS."""
    session = event["data"]["object"]
    customer_id = session.get("customer", "")
    customer_email = session.get("customer_details", {}).get("email", "")
    subscription_id = session.get("subscription", "")

    # Idempotency: check if already provisioned by reading Stripe customer metadata
    if customer_id and STRIPE_SECRET_KEY:
        try:
            existing = get_stripe_customer(customer_id)
            existing_meta = existing.get("metadata", {})
            if existing_meta.get("provision_status") in ("provisioning", "active"):
                print(f"[WEBHOOK] Already provisioned for {customer_id}, re-sending email only")
                send_welcome_email(
                    customer_email,
                    existing_meta.get("company_slug", ""),
                    existing_meta.get("subdomain", ""),
                    existing_meta.get("gateway_key", ""),
                    existing_meta.get("vps_ip", ""),
                )
                return {"status": "already_provisioned", "subdomain": existing_meta.get("subdomain")}
        except Exception as e:
            print(f"[WEBHOOK] Idempotency check failed: {e}")

    # Get company name from custom fields
    custom_fields = session.get("custom_fields", [])
    company_name = ""
    for field in custom_fields:
        if field.get("key") == "company_name" or "company" in str(field.get("label", {})).lower():
            company_name = field.get("text", {}).get("value", "")
            break

    # Generate slug from company name
    slug = slugify(company_name) if company_name else f"pro-{customer_id[-8:]}"
    subdomain = f"{slug}.{DOMAIN}"
    gateway_key = f"gw_{secrets.token_hex(16)}"

    droplet_id = None
    droplet_ip = None

    try:
        # Step 0: Mark as provisioning BEFORE creating resources (prevents duplicates on retry)
        if customer_id and STRIPE_SECRET_KEY:
            update_stripe_customer(customer_id, {
                "provision_status": "provisioning",
                "company_slug": slug,
                "provisioned_at": str(int(time.time())),
            })

        # Step 1: Create DigitalOcean droplet
        print(f"[WEBHOOK] Creating droplet for {slug}")
        droplet_id, droplet_ip = create_droplet(slug, gateway_key)
        print(f"[WEBHOOK] Droplet created: {droplet_id} at {droplet_ip}")

        # Step 2: Create DNS record (slug.airblackbox.ai)
        print(f"[WEBHOOK] Creating DNS record: {slug}.{DOMAIN}")
        create_dns_record(slug, droplet_ip)

        # Step 3: Update Stripe customer metadata (NO secrets stored here).
        # gateway_key and vps_ip are sent via email only, not stored in Stripe.
        update_stripe_customer(customer_id, {
            "company_slug": slug,
            "subdomain": subdomain,
            "droplet_id": str(droplet_id),
            "provision_status": "active",
        })

        # Step 4: Update Stripe subscription metadata
        if subscription_id:
            update_stripe_subscription(subscription_id, {
                "tier": "pro",
                "vps_region": DO_REGION,
            })

        # Step 5: Send welcome email
        print(f"[WEBHOOK] Sending welcome email to: {customer_email}")
        print(f"[WEBHOOK] RESEND_API_KEY set: {bool(RESEND_API_KEY)}")
        send_welcome_email(customer_email, slug, subdomain, gateway_key, droplet_ip)

        return {
            "status": "provisioning",
            "subdomain": subdomain,
            "droplet_id": droplet_id,
        }

    except Exception as e:
        # Cleanup on partial failure: destroy orphaned resources
        error_msg = str(e)[:200]
        print(f"[WEBHOOK] Provisioning failed: {error_msg}")

        # Try to clean up the droplet if it was created
        try:
            if droplet_id:
                print(f"[WEBHOOK] Cleaning up orphaned droplet {droplet_id}")
                destroy_droplet(droplet_id)
        except Exception as cleanup_err:
            print(f"[WEBHOOK] Droplet cleanup failed: {cleanup_err}")

        # Try to clean up DNS if it was created
        try:
            if slug:
                print(f"[WEBHOOK] Cleaning up orphaned DNS for {slug}")
                delete_dns_record(slug)
        except Exception as cleanup_err:
            print(f"[WEBHOOK] DNS cleanup failed: {cleanup_err}")

        # Update Stripe metadata to show failure
        if customer_id:
            try:
                update_stripe_customer(customer_id, {
                    "provision_status": f"failed: {error_msg[:100]}",
                })
            except Exception:
                pass
        return {"status": "error", "message": error_msg}


def handle_cancellation(event):
    """Subscription cancelled - tear down VPS."""
    subscription = event["data"]["object"]
    customer_id = subscription.get("customer", "")

    try:
        # Get customer metadata to find droplet
        customer = get_stripe_customer(customer_id)
        metadata = customer.get("metadata", {})
        droplet_id = metadata.get("droplet_id", "")
        slug = metadata.get("company_slug", "")

        if droplet_id:
            # Destroy the VPS
            destroy_droplet(droplet_id)

            # Remove DNS record
            if slug:
                delete_dns_record(slug)

            # Update metadata
            update_stripe_customer(customer_id, {
                "provision_status": "terminated",
                "terminated_at": str(int(time.time())),
            })

        return {"status": "terminated", "droplet_id": droplet_id}

    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Stripe helpers ───────────────────────────────────────────────

def verify_stripe_signature(payload, sig_header, secret):
    """Verify Stripe webhook signature (v1 scheme)."""
    if not sig_header or not secret:
        return False

    # Parse signature header
    pairs = {}
    for item in sig_header.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            pairs[k.strip()] = v.strip()

    timestamp = pairs.get("t", "")
    signature = pairs.get("v1", "")

    if not timestamp or not signature:
        return False

    # Check timestamp isn't too old (5 min tolerance)
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except ValueError:
        return False

    # Compute expected signature
    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(
        secret.encode(), signed_payload, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def stripe_request(method, path, data=None):
    """Make authenticated request to Stripe API."""
    url = f"https://api.stripe.com/v1/{path}"
    headers = {
        "Authorization": f"Bearer {STRIPE_SECRET_KEY}",
    }

    body = None
    if data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode_nested(data).encode()

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def urlencode_nested(data, prefix=""):
    """URL-encode nested dict for Stripe API (metadata[key]=value format)."""
    parts = []
    for key, value in data.items():
        full_key = f"{prefix}[{key}]" if prefix else key
        if isinstance(value, dict):
            parts.append(urlencode_nested(value, full_key))
        else:
            parts.append(f"{urllib.parse.quote(str(full_key), safe='')}={urllib.parse.quote(str(value), safe='')}")
    return "&".join(parts)


def get_stripe_customer(customer_id):
    return stripe_request("GET", f"customers/{customer_id}")


def update_stripe_customer(customer_id, metadata):
    return stripe_request("POST", f"customers/{customer_id}", {"metadata": metadata})


def update_stripe_subscription(subscription_id, metadata):
    return stripe_request("POST", f"subscriptions/{subscription_id}", {"metadata": metadata})


# ── DigitalOcean helpers ─────────────────────────────────────────

def do_request(method, path, data=None):
    """Make authenticated request to DigitalOcean API."""
    url = f"https://api.digitalocean.com/v2/{path}"
    headers = {
        "Authorization": f"Bearer {DO_API_TOKEN}",
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 204:
                return {}
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        raise Exception(f"DO API {method} {path}: {e.code} {error_body}")


def create_droplet(slug, gateway_key):
    """Create a DigitalOcean droplet with the Pro deploy script."""
    # Generate secrets in Python so they are interpolated correctly.
    # SECURITY: Never use quoted heredocs ('EOF') with shell variables -
    # the quotes suppress interpolation and write literal $VAR strings.
    trust_key = secrets.token_hex(32)
    minio_password = secrets.token_hex(16)

    user_data = f"""#!/bin/bash
set -e

# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone the gateway repo
git clone https://github.com/airblackbox/airblackbox.git /opt/airblackbox
cd /opt/airblackbox

# Write .env file with restrictive permissions (root-only read)
umask 077
cat > .env <<ENVEOF
TRUST_SIGNING_KEY={trust_key}
MINIO_ROOT_USER=airblackbox
MINIO_ROOT_PASSWORD={minio_password}
GATEWAY_KEY={gateway_key}
ENVEOF
chmod 600 .env

# Start the Pro stack
docker compose up -d

# Post-boot cleanup: scrub secrets from disk after Docker has read them.
# Docker Compose reads .env at startup and injects vars into containers.
# Wait for containers to be running, then delete the plaintext .env.
sleep 10
if docker compose ps --status running | grep -q "gateway"; then
    rm -f /opt/airblackbox/.env
    echo "[AIR] .env scrubbed after successful container start"
else
    echo "[AIR] WARNING: containers not running, keeping .env for debug"
fi

# Scrub cloud-init log which may contain the user-data script
sed -i '/TRUST_SIGNING_KEY\\|MINIO_ROOT_PASSWORD\\|GATEWAY_KEY/d' /var/log/cloud-init-output.log 2>/dev/null || true
"""

    result = do_request("POST", "droplets", {
        "name": f"air-pro-{slug}",
        "region": DO_REGION,
        "size": DO_SIZE,
        "image": DO_IMAGE,
        "user_data": user_data,
        "tags": ["airblackbox-pro"],
        "monitoring": True,
    })

    droplet = result.get("droplet", {})
    droplet_id = droplet.get("id", "")

    # Wait for IP assignment (poll up to 60s)
    droplet_ip = ""
    for _ in range(12):
        time.sleep(5)
        info = do_request("GET", f"droplets/{droplet_id}")
        networks = info.get("droplet", {}).get("networks", {}).get("v4", [])
        for net in networks:
            if net.get("type") == "public":
                droplet_ip = net.get("ip_address", "")
                break
        if droplet_ip:
            break

    if not droplet_ip:
        raise Exception(f"Droplet {droplet_id} created but no IP assigned after 60s")

    return droplet_id, droplet_ip


def destroy_droplet(droplet_id):
    """Destroy a DigitalOcean droplet."""
    do_request("DELETE", f"droplets/{droplet_id}")


# ── Cloudflare DNS helpers ───────────────────────────────────────

def cf_request(method, path, data=None):
    """Make authenticated request to Cloudflare API."""
    url = f"https://api.cloudflare.com/client/v4/{path}"
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def create_dns_record(slug, ip):
    """Create A record: slug.airblackbox.ai -> IP."""
    cf_request("POST", f"zones/{CLOUDFLARE_ZONE_ID}/dns_records", {
        "type": "A",
        "name": f"{slug}.{DOMAIN}",
        "content": ip,
        "ttl": 300,
        "proxied": False,
    })


def delete_dns_record(slug):
    """Delete DNS record for slug.airblackbox.ai."""
    result = cf_request("GET",
        f"zones/{CLOUDFLARE_ZONE_ID}/dns_records?name={slug}.{DOMAIN}&type=A")
    records = result.get("result", [])
    for record in records:
        cf_request("DELETE",
            f"zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record['id']}")


# ── Email helper ─────────────────────────────────────────────────

def send_welcome_email(to_email, slug, subdomain, gateway_key, ip):
    """Send welcome email with Pro credentials via Resend."""
    if not RESEND_API_KEY or not to_email:
        return

    html_body = f"""
    <div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto; color: #e6edf3; background: #0d1117; padding: 2rem; border-radius: 12px;">
        <h1 style="color: #58a6ff;">Your AIR Blackbox Pro is ready</h1>
        <p style="color: #8b949e;">Your dedicated VPS has been provisioned. Here's everything you need to start scanning.</p>

        <div style="background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1.5rem; margin: 1.5rem 0;">
            <h3 style="color: #e6edf3; margin-top: 0;">Your Credentials</h3>
            <p style="color: #8b949e; margin: 0.5rem 0;"><strong style="color: #e6edf3;">Gateway URL:</strong> <code style="color: #3fb950;">https://{subdomain}/v1</code></p>
            <p style="color: #8b949e; margin: 0.5rem 0;"><strong style="color: #e6edf3;">Gateway Key:</strong> <code style="color: #3fb950;">{gateway_key}</code></p>
            <p style="color: #8b949e; margin: 0.5rem 0;"><strong style="color: #e6edf3;">Jaeger Dashboard:</strong> <code style="color: #3fb950;">https://{subdomain}:16686</code></p>
            <p style="color: #8b949e; margin: 0.5rem 0;"><strong style="color: #e6edf3;">Server IP:</strong> <code style="color: #3fb950;">{ip}</code></p>
        </div>

        <div style="background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1.5rem; margin: 1.5rem 0;">
            <h3 style="color: #e6edf3; margin-top: 0;">Quick Start</h3>
            <pre style="color: #3fb950; background: #0d1117; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 14px;">pip install air-blackbox
export AIR_GATEWAY=https://{subdomain}
air-blackbox comply --scan . -v</pre>
        </div>

        <p style="color: #8b949e;">Your VPS includes the fine-tuned gap analysis model, Jaeger trace dashboard, and private telemetry. No data leaves your server.</p>
        <p style="color: #8b949e;">Questions? Reply to this email or reach us at <a href="mailto:jason.j.shotwell@gmail.com" style="color: #58a6ff;">jason.j.shotwell@gmail.com</a></p>

        <hr style="border: 1px solid #21262d; margin: 2rem 0;">
        <p style="color: #484f58; font-size: 12px;">AIR Blackbox - EU AI Act gap analysis scanner. Identifies gaps. Does not certify compliance.<br><a href="https://airblackbox.ai/terms.html" style="color: #484f58;">Terms of Service</a></p>
    </div>
    """

    data = json.dumps({
        "from": "AIR Blackbox <noreply@airblackbox.ai>",
        "to": [to_email],
        "subject": f"Your AIR Blackbox Pro is ready - {subdomain}",
        "html": html_body,
    }).encode()

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"[RESEND] Email sent to {to_email}: {result}")
            return result
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else "no body"
        print(f"[RESEND] ERROR {e.code}: {error_body}")
    except Exception as e:
        print(f"[RESEND] ERROR: {e}")


# ── Utilities ────────────────────────────────────────────────────

def slugify(text):
    """Convert company name to URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text[:30].strip('-')
