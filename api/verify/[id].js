// Vercel Serverless Function: /verify/:id
// Renders an HTML verification page for a given attestation ID
// This is what people see when they click a badge

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

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function frameworkName(fw) {
  const names = {
    eu_ai_act: 'EU AI Act', eu: 'EU AI Act',
    iso_42001: 'ISO/IEC 42001', iso42001: 'ISO/IEC 42001',
    nist_rmf: 'NIST AI RMF', nist: 'NIST AI RMF',
    colorado_sb205: 'Colorado SB 24-205', colorado: 'Colorado SB 24-205',
  };
  return names[fw.toLowerCase()] || fw;
}

function renderPage(record, id) {
  const scan = record.scan || {};
  const subject = record.subject || {};
  const crypto = record.crypto || {};
  const evidence = record.evidence || {};
  const passed = scan.checks_passed || 0;
  const warned = scan.checks_warned || 0;
  const failed = scan.checks_failed || 0;
  const total = scan.checks_total || 0;
  const frameworks = (scan.frameworks || []).map(frameworkName).join(', ');
  const allPassed = failed === 0;
  const statusColor = allPassed ? '#3fb950' : '#d29922';
  const statusText = allPassed ? 'ALL CHECKS PASSED' : 'NEEDS ATTENTION';
  const statusIcon = allPassed ? '&#x2705;' : '&#x26A0;&#xFE0F;';
  const created = record.created_at ? new Date(record.created_at).toUTCString() : 'Unknown';
  const algo = escapeHtml(crypto.algorithm || 'Unknown');
  const keyFp = escapeHtml(crypto.public_key_fingerprint || 'Not available');
  const hasSig = crypto.signature ? true : false;
  const sigPreview = hasSig ? escapeHtml(crypto.signature.slice(0, 40) + '...') : 'Not signed';
  const bundleHash = escapeHtml(evidence.bundle_hash || 'Not linked');
  const chainHash = escapeHtml(evidence.audit_chain_hash || 'Not linked');
  const sysName = escapeHtml(subject.system_name || 'Unnamed System');
  const sysHash = escapeHtml(subject.system_hash || '');
  const sysVersion = escapeHtml(subject.system_version || '');
  const scannerVersion = escapeHtml(scan.scanner_version || '');
  const risk = escapeHtml(scan.risk_classification || 'Not classified');
  const badgeUrl = `https://airblackbox.ai/api/badge/${escapeHtml(id)}`;
  const attId = escapeHtml(id);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Attestation | AIR Blackbox</title>
  <meta name="description" content="Verify AIR Blackbox compliance attestation ${attId}. Independent proof that an AI system was scanned for EU AI Act compliance.">
  <meta property="og:title" content="AIR Blackbox Attestation Verification">
  <meta property="og:description" content="Compliance attestation ${attId}: ${passed}/${total} checks passed across ${frameworks}.">
  <meta property="og:type" content="website">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    :root{--bg:#080b14;--card:#0d1117;--border:#21262d;--text:#e6edf3;--dim:#8b949e;--accent:#fbbf24;--green:#3fb950;--red:#f85149;--yellow:#d29922;--mono:'Courier New',monospace;--sans:-apple-system,sans-serif}
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.7;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2rem 1rem}
    .container{max-width:700px;width:100%}
    .logo{font-family:var(--mono);font-weight:700;font-size:1.1rem;text-align:center;margin-bottom:2rem;color:var(--text)}
    .logo span{color:var(--accent)}
    .status-card{background:var(--card);border:2px solid ${statusColor};border-radius:12px;padding:2rem;text-align:center;margin-bottom:2rem}
    .status-icon{font-size:2.5rem;margin-bottom:0.5rem}
    .status-text{font-size:1.2rem;font-weight:700;color:${statusColor};margin-bottom:0.3rem}
    .att-id{font-family:var(--mono);font-size:0.85rem;color:var(--dim);word-break:break-all}
    .score{font-size:3rem;font-weight:800;color:var(--text);margin:1rem 0 0.3rem}
    .score-label{font-size:0.85rem;color:var(--dim)}
    .detail-section{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1rem}
    .detail-section h3{font-size:0.75rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--accent);margin-bottom:1rem}
    .detail-row{display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--border);font-size:0.88rem}
    .detail-row:last-child{border-bottom:none}
    .detail-label{color:var(--dim)}
    .detail-value{font-family:var(--mono);font-size:0.82rem;text-align:right;max-width:60%;word-break:break-all}
    .badge-section{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1rem;text-align:center}
    .badge-section h3{font-size:0.75rem;text-transform:uppercase;letter-spacing:1.5px;color:var(--accent);margin-bottom:1rem}
    .badge-preview{margin:1rem 0}
    .badge-code{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:0.8rem;font-family:var(--mono);font-size:0.75rem;color:var(--dim);word-break:break-all;text-align:left;cursor:pointer}
    .badge-code:hover{border-color:var(--accent)}
    .disclaimer{font-size:0.72rem;color:var(--dim);text-align:center;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)}
    .verified-badge{display:inline-block;background:rgba(63,185,80,0.1);border:1px solid rgba(63,185,80,0.3);color:var(--green);padding:0.3rem 0.8rem;border-radius:6px;font-size:0.75rem;font-weight:600;margin-top:0.5rem}
    a{color:#58a6ff;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">AIR <span>Blackbox</span> &mdash; Attestation Verification</div>

    <div class="status-card">
      <div class="status-icon">${statusIcon}</div>
      <div class="status-text">${statusText}</div>
      <div class="att-id">${attId}</div>
      <div class="score">${passed}/${total}</div>
      <div class="score-label">compliance checks passed</div>
      <div class="verified-badge">&#x1F512; Found in public registry</div>
    </div>

    <div class="detail-section">
      <h3>Scan Summary</h3>
      <div class="detail-row"><span class="detail-label">Frameworks</span><span class="detail-value">${frameworks}</span></div>
      <div class="detail-row"><span class="detail-label">Passed</span><span class="detail-value" style="color:var(--green)">${passed}</span></div>
      <div class="detail-row"><span class="detail-label">Warnings</span><span class="detail-value" style="color:var(--yellow)">${warned}</span></div>
      <div class="detail-row"><span class="detail-label">Failed</span><span class="detail-value" style="color:var(--red)">${failed}</span></div>
      <div class="detail-row"><span class="detail-label">Risk Classification</span><span class="detail-value">${risk}</span></div>
      <div class="detail-row"><span class="detail-label">Scanner</span><span class="detail-value">${scannerVersion}</span></div>
      <div class="detail-row"><span class="detail-label">Scan Date</span><span class="detail-value">${created}</span></div>
    </div>

    <div class="detail-section">
      <h3>System</h3>
      <div class="detail-row"><span class="detail-label">Name</span><span class="detail-value">${sysName}</span></div>
      ${sysVersion ? `<div class="detail-row"><span class="detail-label">Version</span><span class="detail-value">${sysVersion}</span></div>` : ''}
      <div class="detail-row"><span class="detail-label">System Hash</span><span class="detail-value">${sysHash.slice(0, 16)}...</span></div>
    </div>

    <div class="detail-section">
      <h3>Cryptographic Proof</h3>
      <div class="detail-row"><span class="detail-label">Algorithm</span><span class="detail-value">${algo}</span></div>
      <div class="detail-row"><span class="detail-label">Key Fingerprint</span><span class="detail-value">${keyFp.slice(0, 16)}...</span></div>
      <div class="detail-row"><span class="detail-label">Signature</span><span class="detail-value">${sigPreview}</span></div>
      <div class="detail-row"><span class="detail-label">Evidence Bundle</span><span class="detail-value">${bundleHash.slice(0, 16)}${bundleHash.length > 16 ? '...' : ''}</span></div>
      <div class="detail-row"><span class="detail-label">Audit Chain</span><span class="detail-value">${chainHash.slice(0, 16)}${chainHash.length > 16 ? '...' : ''}</span></div>
    </div>

    <div class="badge-section">
      <h3>Embed This Badge</h3>
      <div class="badge-preview"><img src="${badgeUrl}" alt="AIR Attested"></div>
      <div class="badge-code" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{this.style.borderColor='#3fb950'})">[![AIR Attested](${badgeUrl})](https://airblackbox.ai/verify/${attId})</div>
      <div style="font-size:0.72rem;color:var(--dim);margin-top:0.5rem">Click to copy markdown</div>
    </div>

    <div class="disclaimer">
      AIR Blackbox attestations verify that a compliance scan was performed and signed.
      They do not certify or guarantee regulatory compliance. Consult a qualified attorney
      for binding legal guidance.<br><br>
      <a href="https://airblackbox.ai">airblackbox.ai</a> &middot;
      <a href="https://github.com/airblackbox/gateway">GitHub</a> &middot;
      <a href="https://pypi.org/project/air-blackbox/">PyPI</a>
    </div>
  </div>
</body>
</html>`;
}

function notFoundPage(id) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Attestation Not Found | AIR Blackbox</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>
    body{font-family:-apple-system,sans-serif;background:#080b14;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh;text-align:center}
    .box{max-width:500px;padding:2rem}
    h1{font-size:1.5rem;margin-bottom:1rem}
    p{color:#8b949e;margin-bottom:1rem}
    code{background:#0d1117;padding:0.2rem 0.5rem;border-radius:4px;font-size:0.85rem}
    a{color:#58a6ff}
  </style>
</head>
<body>
  <div class="box">
    <h1>Attestation Not Found</h1>
    <p>No attestation with ID <code>${escapeHtml(id || 'unknown')}</code> exists in the public registry.</p>
    <p>If you just published this attestation, it may take a few seconds to appear.</p>
    <p><a href="https://airblackbox.ai">Back to airblackbox.ai</a></p>
  </div>
</body>
</html>`;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).end();
  }

  const { id } = req.query;
  if (!id) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(400).send(notFoundPage(''));
  }

  try {
    const db = getRedis();
    const raw = await db.get(`att:${id}`);

    if (!raw) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(notFoundPage(id));
    }

    const record = JSON.parse(raw);
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'public, max-age=60');
    return res.status(200).send(renderPage(record, id));
  } catch (err) {
    console.error('Verify page error:', err.message);
    res.setHeader('Content-Type', 'text/html');
    return res.status(500).send(notFoundPage(id));
  }
}
