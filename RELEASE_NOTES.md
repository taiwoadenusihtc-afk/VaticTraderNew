# VaticTrader update: Fast mode, Portfolio Builder, own-keys notice

Files (same folder layout as your repo):
  public/index.html        front end (Fast-mode toggle, stream status, Portfolio Builder page, Alpaca keys notice)
  server/server.js         engine changes (per-deployment lock, streaming hook, fast_mode, /api/fast/status, bar request fix)
  server/fast_stream.js    NEW: one Alpaca data WebSocket per user, using that user's own keys
  server/schema.sql        adds live_deployments.fast_mode (idempotent, applied on boot)

Do this once
  1. Add the "ws" package to package.json dependencies ("ws": "^8"). If it is missing, Fast mode falls back to Node's built-in
     WebSocket (Node 22+); with neither, Fast mode shows a clear error and the normal once-a-minute engine keeps working.
  2. Redeploy. No new env vars are required. Optional: FAST_MODE_ENABLED=0 (kill switch), ALPACA_STREAM_FEED=sip (only if your
     users have a paid Alpaca data plan), FAST_MIN_EVAL_MS (1000), FAST_CONFIRM_EVALS (2), FAST_BARS_TTL_MS (15000), FAST_POS_CHECK_MS (5000).

Also fixed
  The live engine asked Alpaca for bars with no start date or sort order. It now asks for the newest bars explicitly
  (start + sort=desc + feed=iex). I could not check this against the real Alpaca API from here: watch the first live logs.

Not verified
  Nothing here has been run against a real Alpaca account or real market data. Tests used a local mock Alpaca (REST + WebSocket)
  and synthetic prices. Single server instance assumed (the lock is in memory).
