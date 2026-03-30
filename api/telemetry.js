// Vercel Serverless Function: /api/telemetry
// Receives anonymous usage events from AIR Blackbox CLI
// Stores them in Vercel KV (Redis) for the dashboard

import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  // Only accept POST
  if (req.method !== 'POST') {
    return res.status(200).json({ ok: true });
  }

  try {
    const event = req.body;

    // Validate required fields
    if (!event.anonymous_id || !event.command) {
      return res.status(400).json({ error: 'missing fields' });
    }

    // Add server-side timestamp (don't trust client time)
    event.server_timestamp = new Date().toISOString();

    // Strip any accidentally included sensitive data
    delete event.file_paths;
    delete event.code;
    delete event.project_name;

    // Store in Vercel KV if available, otherwise log to stdout
    if (process.env.KV_REST_API_URL) {

      // Store individual event with TTL of 90 days
      const eventKey = `evt:${Date.now()}:${event.anonymous_id.slice(0, 8)}`;
      await kv.set(eventKey, JSON.stringify(event), { ex: 90 * 86400 });

      // Increment daily counter
      const today = new Date().toISOString().slice(0, 10);
      await kv.incr(`daily:${today}`);

      // Increment command counter
      await kv.incr(`cmd:${event.command}`);

      // Track unique users (HyperLogLog)
      await kv.pfadd('unique_users', event.anonymous_id);
      await kv.pfadd(`unique_users:${today}`, event.anonymous_id);

      // Track OS distribution
      if (event.os) {
        await kv.incr(`os:${event.os}`);
      }

      // Track Python version distribution
      if (event.python_version) {
        const pyMajorMinor = event.python_version.split('.').slice(0, 2).join('.');
        await kv.incr(`py:${pyMajorMinor}`);
      }
    } else {
      // Fallback: log to Vercel's stdout (visible in runtime logs)
      console.log(JSON.stringify({ telemetry_event: event }));
    }

    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(200).json({ ok: true });
  } catch (err) {
    // Never return errors to the client — telemetry should be invisible
    return res.status(200).json({ ok: true });
  }
}
