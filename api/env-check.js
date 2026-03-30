// Temporary diagnostic — lists env var names related to Redis/KV
// DELETE THIS FILE after fixing

export default function handler(req, res) {
  const envNames = Object.keys(process.env).sort();
  
  const check = {
    // Check all possible KV/Redis env var names
    kv_related: envNames.filter(n => /kv|redis|upstash/i.test(n)),
    DASHBOARD_KEY_exists: 'DASHBOARD_KEY' in process.env,
    KV_REST_API_URL_exists: 'KV_REST_API_URL' in process.env,
    KV_REST_API_TOKEN_exists: 'KV_REST_API_TOKEN' in process.env,
    total_env_vars: envNames.length,
  };

  return res.status(200).json(check);
}
