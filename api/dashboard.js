// Vercel Serverless Function: /api/dashboard
// Returns aggregated telemetry stats for the dashboard
// Protected by DASHBOARD_KEY env var, uses Redis via REDIS_URL

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

export default async function handler(req, res) {
  // Simple auth — check for dashboard key in query params or header
  const key = req.query.key || req.headers['x-dashboard-key'];
  const envKey = process.env.DASHBOARD_KEY;

  if (!envKey || key !== envKey) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (!process.env.REDIS_URL) {
    return res.status(500).json({ error: 'Redis not configured' });
  }

  try {
    const r = getRedis();
    await r.connect().catch(() => {});

    // Gather stats
    const today = new Date().toISOString().slice(0, 10);
    const uniqueUsersAllTime = await r.pfcount('unique_users');
    const uniqueUsersToday = await r.pfcount(`unique_users:${today}`);

    // Get daily counts for last 30 days
    const dailyCounts = {};
    for (let i = 0; i < 30; i++) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().slice(0, 10);
      const count = await r.get(`daily:${dateStr}`);
      dailyCounts[dateStr] = parseInt(count) || 0;
    }

    // Command distribution
    const commands = {};
    for (const cmd of ['comply', 'discover', 'replay', 'export', 'demo', 'setup', 'validate', 'test', 'init']) {
      const count = await r.get(`cmd:${cmd}`);
      if (count) commands[cmd] = parseInt(count);
    }

    // OS distribution
    const osDist = {};
    for (const os of ['Linux', 'Darwin', 'Windows']) {
      const count = await r.get(`os:${os}`);
      if (count) osDist[os] = parseInt(count);
    }

    // Python version distribution
    const pyDist = {};
    for (const v of ['3.8', '3.9', '3.10', '3.11', '3.12', '3.13']) {
      const count = await r.get(`py:${v}`);
      if (count) pyDist[v] = parseInt(count);
    }

    // Get recent events (last 20)
    const keys = await r.keys('evt:*');
    const recentKeys = keys.sort().reverse().slice(0, 20);
    const recentEvents = [];
    for (const k of recentKeys) {
      const evt = await r.get(k);
      if (evt) {
        try {
          recentEvents.push(JSON.parse(evt));
        } catch {
          recentEvents.push(evt);
        }
      }
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
  } catch (err) {
    console.error('Dashboard error:', err.message);
    return res.status(500).json({ error: 'internal error' });
  }
}
