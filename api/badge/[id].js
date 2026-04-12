// Vercel Serverless Function: /api/badge/:id
// Returns an SVG badge for a given attestation ID
// Cached for 5 minutes to reduce Redis lookups
//
// Usage: https://airblackbox.ai/api/badge/air-att-2026-04-12-a7f3c2e1

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

const COLOR_GREEN = '#4c1';
const COLOR_YELLOW = '#dfb317';
const COLOR_RED = '#e05d44';
const COLOR_BLUE = '#007ec6';
const COLOR_GRAY = '#555';
const COLOR_DARK_GRAY = '#9f9f9f';

function escapeXml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function textWidth(text) {
  return Math.round(text.length * 6.5) + 10;
}

function generateBadge(label, message, color, link) {
  const labelW = textWidth(label);
  const messageW = textWidth(message);
  const totalW = labelW + messageW;
  const labelX = labelW / 2;
  const messageX = labelW + messageW / 2;

  const labelEsc = escapeXml(label);
  const messageEsc = escapeXml(message);

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="20" role="img" aria-label="${labelEsc}: ${messageEsc}">
  <title>${labelEsc}: ${messageEsc}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalW}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelW}" height="20" fill="${COLOR_GRAY}"/>
    <rect x="${labelW}" width="${messageW}" height="20" fill="${color}"/>
    <rect width="${totalW}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${labelX}" y="15" fill="#010101" fill-opacity=".3">${labelEsc}</text>
    <text x="${labelX}" y="14" fill="#fff">${labelEsc}</text>
    <text aria-hidden="true" x="${messageX}" y="15" fill="#010101" fill-opacity=".3">${messageEsc}</text>
    <text x="${messageX}" y="14" fill="#fff">${messageEsc}</text>
  </g>
</svg>`;

  return svg;
}

function notFoundBadge() {
  return generateBadge('AIR Blackbox', 'not found', COLOR_DARK_GRAY, '');
}

function frameworkShort(frameworks) {
  const nameMap = {
    eu: 'EU', eu_ai_act: 'EU',
    iso42001: 'ISO', iso_42001: 'ISO',
    nist: 'NIST', nist_rmf: 'NIST',
    colorado: 'CO', colorado_sb205: 'CO',
  };
  const shorts = [];
  for (const fw of frameworks) {
    const short = nameMap[fw.toLowerCase()] || fw.toUpperCase().slice(0, 4);
    if (!shorts.includes(short)) shorts.push(short);
  }
  return shorts.slice(0, 4).join('+');
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }

  const { id } = req.query;
  if (!id) {
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=60');
    return res.status(404).send(notFoundBadge());
  }

  try {
    const db = getRedis();
    const raw = await db.get(`att:${id}`);

    if (!raw) {
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Cache-Control', 'public, max-age=60');
      return res.status(404).send(notFoundBadge());
    }

    const record = JSON.parse(raw);
    const scan = record.scan || {};
    const passed = scan.checks_passed || 0;
    const total = scan.checks_total || 0;
    const failed = scan.checks_failed || 0;
    const frameworks = scan.frameworks || [];

    let label, color;
    if (failed > 0) {
      label = 'AIR Scanned';
      color = COLOR_YELLOW;
    } else if (frameworks.length >= 2) {
      label = 'AIR Attested';
      color = COLOR_BLUE;
    } else {
      label = 'AIR Attested';
      color = COLOR_GREEN;
    }

    const fwShort = frameworkShort(frameworks);
    const message = total > 0 ? `${fwShort} | ${passed}/${total}` : 'scanned';

    const svg = generateBadge(label, message, color, '');

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=300'); // 5 min cache
    return res.status(200).send(svg);
  } catch (err) {
    console.error('Badge error:', err.message);
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.status(500).send(notFoundBadge());
  }
}
