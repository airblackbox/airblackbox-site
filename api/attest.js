// Vercel Serverless Function: /api/attest
// POST: Publish an attestation record to the public registry
// GET:  Verify/retrieve an attestation by ID (?id=air-att-...)
//
// Storage: Redis (via REDIS_URL env var)
// Key format: att:<attestation_id> -> JSON string

import Redis from 'ioredis';

let redis;
function getRedis() {
  if (!redis) {
    redis = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 1,
      connectTimeout: 5000,
      lazyConnect: true,
    });
  }
  return redis;
}

// Attestation ID format: air-att-YYYY-MM-DD-<hex>
const ATT_ID_REGEX = /^air-att-\d{4}-\d{2}-\d{2}-[0-9a-f]{8}$/;

// Maximum attestation record size (100KB -- generous for JSON)
const MAX_BODY_SIZE = 100_000;

function validateRecord(record) {
  const issues = [];

  if (!record.attestation_id || !ATT_ID_REGEX.test(record.attestation_id)) {
    issues.push('Invalid or missing attestation_id');
  }
  if (!record.schema_version) {
    issues.push('Missing schema_version');
  }
  if (!record.created_at) {
    issues.push('Missing created_at');
  }

  // Subject
  if (!record.subject || !record.subject.system_hash) {
    issues.push('Missing subject.system_hash');
  }

  // Scan
  if (!record.scan) {
    issues.push('Missing scan object');
  } else {
    if (!record.scan.scanner_version) {
      issues.push('Missing scan.scanner_version');
    }
    if (!Array.isArray(record.scan.frameworks) || record.scan.frameworks.length === 0) {
      issues.push('Missing or empty scan.frameworks');
    }
    const p = record.scan.checks_passed || 0;
    const w = record.scan.checks_warned || 0;
    const f = record.scan.checks_failed || 0;
    const t = record.scan.checks_total || 0;
    if (p + w + f !== t) {
      issues.push(`Check counts do not add up: ${p}+${w}+${f} != ${t}`);
    }
  }

  // Crypto -- signature is required for public registry
  if (!record.crypto || !record.crypto.signature) {
    issues.push('Missing crypto.signature (attestation must be signed)');
  }
  if (record.crypto && !record.crypto.public_key_fingerprint) {
    issues.push('Missing crypto.public_key_fingerprint');
  }

  return issues;
}

export default async function handler(req, res) {
  // CORS headers for CLI access
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // ------- GET: Retrieve/verify an attestation -------
  if (req.method === 'GET') {
    const id = req.query.id;
    if (!id) {
      return res.status(400).json({ error: 'Missing ?id= parameter' });
    }
    if (!ATT_ID_REGEX.test(id)) {
      return res.status(400).json({ error: 'Invalid attestation ID format' });
    }

    try {
      const db = getRedis();
      const raw = await db.get(`att:${id}`);
      if (!raw) {
        return res.status(404).json({ error: 'Attestation not found', id });
      }

      const record = JSON.parse(raw);
      return res.status(200).json({
        ok: true,
        attestation: record,
        verified: true,
        message: 'Attestation found in public registry',
      });
    } catch (err) {
      console.error('GET /api/attest error:', err.message);
      return res.status(500).json({ error: 'Registry lookup failed' });
    }
  }

  // ------- POST: Publish a new attestation -------
  if (req.method === 'POST') {
    const record = req.body;

    if (!record || typeof record !== 'object') {
      return res.status(400).json({ error: 'Request body must be a JSON object' });
    }

    // Size check
    const bodySize = JSON.stringify(record).length;
    if (bodySize > MAX_BODY_SIZE) {
      return res.status(413).json({
        error: `Attestation too large: ${bodySize} bytes (max ${MAX_BODY_SIZE})`,
      });
    }

    // Validate
    const issues = validateRecord(record);
    if (issues.length > 0) {
      return res.status(400).json({ error: 'Validation failed', issues });
    }

    try {
      const db = getRedis();
      const key = `att:${record.attestation_id}`;

      // Check for duplicate
      const existing = await db.get(key);
      if (existing) {
        return res.status(409).json({
          error: 'Attestation already exists',
          id: record.attestation_id,
          message: 'Each attestation ID can only be published once',
        });
      }

      // Add server-side metadata
      record._registry = {
        published_at: new Date().toISOString(),
        registry_version: '1.0',
        source_ip_hash: '', // We intentionally do not log IPs
      };

      // Store with 2-year TTL (attestations expire after the EU AI Act cycle)
      const ttl = 2 * 365 * 24 * 60 * 60; // 2 years in seconds
      await db.set(key, JSON.stringify(record), 'EX', ttl);

      // Also add to the attestation index (sorted set by timestamp)
      const timestamp = new Date(record.created_at).getTime() || Date.now();
      await db.zadd('att:index', timestamp, record.attestation_id);

      return res.status(201).json({
        ok: true,
        id: record.attestation_id,
        verify_url: `https://airblackbox.ai/verify/${record.attestation_id}`,
        badge_url: `https://airblackbox.ai/badge/${record.attestation_id}.svg`,
        message: 'Attestation published to public registry',
      });
    } catch (err) {
      console.error('POST /api/attest error:', err.message);
      return res.status(500).json({ error: 'Failed to publish attestation' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
