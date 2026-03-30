// Vercel Serverless Function: /api/dashboard
// Returns aggregated telemetry stats for the dashboard
// Protected by a simple API key (set DASHBOARD_KEY env var)

import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  // Simple auth — check for dashboard key in query params or header
  const key = req.query.key || req.headers['x-dashboard-key'];
  const envKey = process.env.DASHBOARD_KEY;
  console.log(`Dashboard auth: key_len=${key ? key.length : 'none'}, env_len=${envKey ? envKey.length : 'none'}, match=${key === envKey}`);
  if (!envKey || key !== envKey) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (!process.env.KV_REST_API_URL) {
    return res.status(500).json({ error: 'KV not configured' });
  }

  // Gather stats
  const today = new Date().toISOString().slice(0, 10);
  const uniqueUsersAllTime = await kv.pfcount('unique_users');
  const uniqueUsersToday = await kv.pfcount(`unique_users:${today}`);

  // Get daily counts for last 30 days
  const dailyCounts = {};
  for (let i = 0; i < 30; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const count = await kv.get(`daily:${dateStr}`);
    dailyCounts[dateStr] = parseInt(count) || 0;
  }

  // Command distribution
  const commands = {};
  for (const cmd of ['comply', 'discover', 'replay', 'export', 'demo', 'setup', 'validate', 'test', 'init']) {
    const count = await kv.get(`cmd:${cmd}`);
    if (count) commands[cmd] = parseInt(count);
  }

  // OS distribution
  const osDist = {};
  for (const os of ['Linux', 'Darwin', 'Windows']) {
    const count = await kv.get(`os:${os}`);
    if (count) osDist[os] = parseInt(count);
  }

  // Python version distribution
  const pyDist = {};
  for (const v of ['3.8', '3.9', '3.10', '3.11', '3.12', '3.13']) {
    const count = await kv.get(`py:${v}`);
    if (count) pyDist[v] = parseInt(count);
  }

  // Get recent events (last 20)
  const keys = await kv.keys('evt:*');
  const recentKeys = keys.sort().reverse().slice(0, 20);
  const recentEvents = [];
  for (const k of recentKeys) {
    const evt = await kv.get(k);
    if (evt) recentEvents.push(typeof evt === 'string' ? JSON.parse(evt) : evt);
  }

  const stats = {
    unique_users_all_time: uniqueUsersAllTime,
    unique_users_today: uniqueUsersToday,
    daily_scans: dailyCounts,
    commands,
    os_distribution: osDist,
    python_versions: pyDist,
    recent_events: recentEvents,
    generated_at: new Date().toISOString(),
  };

  res.setHeader('Cache-Control', 'max-age=60');
  return res.status(200).json(stats);
}
