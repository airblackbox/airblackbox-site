// Temporary diagnostic — lists env var names (NOT values) to debug DASHBOARD_KEY issue
// DELETE THIS FILE after fixing the env var

export default function handler(req, res) {
  const envNames = Object.keys(process.env).sort();
  
  // Check for specific vars we care about
  const check = {
    DASHBOARD_KEY_exists: 'DASHBOARD_KEY' in process.env,
    KV_REST_API_URL_exists: 'KV_REST_API_URL' in process.env,
    KV_REST_API_TOKEN_exists: 'KV_REST_API_TOKEN' in process.env,
    VERCEL_ENV: process.env.VERCEL_ENV || null,
    NODE_ENV: process.env.NODE_ENV || null,
    // Show all env var NAMES that contain "KEY" or "DASHBOARD" (no values!)
    key_related: envNames.filter(n => /key|dashboard/i.test(n)),
    // Show all env var NAMES that contain "KV" (no values!)
    kv_related: envNames.filter(n => /kv/i.test(n)),
    total_env_vars: envNames.length,
  };

  return res.status(200).json(check);
}
