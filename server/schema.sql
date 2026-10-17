-- VaticTrader backend schema
-- Mirrors the existing window.storage key-value shape used throughout the
-- frontend, so the app's data model doesn't need to be redesigned to gain
-- real persistence — just the transport underneath it changes.

CREATE TABLE IF NOT EXISTS users (
  username      TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  plan_tier     TEXT NOT NULL DEFAULT 'free', -- 'free' | 'starter' | 'pro'
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  subscription_status TEXT, -- 'active' | 'past_due' | 'canceled' | null
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Safe on databases where the table already existed before these columns
-- were added; CREATE TABLE IF NOT EXISTS above is a no-op in that case.
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_tier TEXT NOT NULL DEFAULT 'free';
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT;
-- Running total of what a strategy creator has earned from other traders
-- copying their published strategies (in cents). Tracked here independent
-- of whether it's ever actually applied to Stripe, a free-tier creator
-- still accumulates it, it just can't be redeemed as real invoice credit
-- until they have a Stripe customer record (i.e. have been through
-- checkout at least once).
ALTER TABLE users ADD COLUMN IF NOT EXISTS creator_credit_cents INTEGER NOT NULL DEFAULT 0;
-- Every account gets one real, server-enforced 30-day Pro-equivalent
-- trial from signup, set once at registration and never reset. While
-- active, it's treated as equivalent to a paid tier by every limit
-- check below, not just shown as a badge with no backing.
ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;
-- Granted automatically to whichever account redeems the permanent
-- single-use TAIWOADENUSI founder code (see the redeem endpoint), since
-- successfully redeeming that specific code is itself proof of being the
-- founder account. Not settable through any user-facing action otherwise.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;

-- Redemption codes: a comp-access mechanism separate from real Stripe
-- billing entirely, for granting a tier for free (beta testers, the app
-- owner's own account, promotional access), not a discount on a real
-- subscription. A code can be capped to a number of uses and/or an
-- expiry date; each username may redeem a given code at most once,
-- enforced by the unique constraint below, not just application logic.
CREATE TABLE IF NOT EXISTS redemption_codes (
  code        TEXT PRIMARY KEY,
  tier        TEXT NOT NULL DEFAULT 'pro',
  max_uses    INTEGER NOT NULL DEFAULT 1,
  uses_count  INTEGER NOT NULL DEFAULT 0,
  expires_at  TIMESTAMPTZ,
  note        TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS redemption_code_uses (
  id           SERIAL PRIMARY KEY,
  code         TEXT NOT NULL REFERENCES redemption_codes(code) ON DELETE CASCADE,
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  redeemed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (code, username)
);
-- Seeded once (ON CONFLICT DO NOTHING means a later server restart never
-- resets or re-extends these): a permanent single-use founder code, and a
-- broader one-month promotional code for wider giveaway.
INSERT INTO redemption_codes (code, tier, max_uses, expires_at, note) VALUES
  ('TAIWOADENUSI', 'pro', 1, NULL, 'Founder account, permanent, single use'),
  ('VATICTRADER', 'pro', 100000, now() + INTERVAL '1 month', 'Public one-month promo code')
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Shared key-value store: readable/writable by any authenticated user.
-- Used for: user:<username> profile blobs, community-index, follows-index,
-- waitlist-index (matching the exact keys the frontend already uses).
CREATE TABLE IF NOT EXISTS kv_shared (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Personal key-value store: scoped to the owning user only (e.g. "session").
CREATE TABLE IF NOT EXISTS kv_personal (
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  key         TEXT NOT NULL,
  value       TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, key)
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

-- Real broker API credentials (currently: Alpaca paper trading only).
-- api_secret is stored encrypted (AES-256-GCM) — see encryptSecret() in
-- server.js — never returned to the client after the initial connect.
CREATE TABLE IF NOT EXISTS broker_credentials (
  username        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  broker          TEXT NOT NULL DEFAULT 'alpaca',
  api_key_id      TEXT NOT NULL,
  api_secret_enc  TEXT NOT NULL,
  base_url        TEXT NOT NULL DEFAULT 'https://paper-api.alpaca.markets',
  connected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, broker)
);

-- Tracks strategies actually deployed for real, automated execution against
-- a connected broker. Deliberately a real table, not a field inside the
-- user's JSON profile blob — a background scheduler reads and writes this
-- independently of any client session, so it needs proper row-level
-- locking (see /api/live/tick in server.js), which a shared JSON blob
-- can't safely provide without reintroducing the exact lost-update race
-- the kv-atomic endpoint exists to prevent elsewhere in this schema.
CREATE TABLE IF NOT EXISTS live_deployments (
  id              SERIAL PRIMARY KEY,
  username        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  strategy_id     TEXT NOT NULL,
  strategy_name   TEXT NOT NULL DEFAULT '',
  broker          TEXT NOT NULL DEFAULT 'alpaca',
  symbol          TEXT NOT NULL,
  timeframe       TEXT NOT NULL DEFAULT '15m',
  direction       TEXT NOT NULL,
  entry_conditions JSONB NOT NULL,
  take_profit_pct NUMERIC NOT NULL,
  stop_loss_pct   NUMERIC NOT NULL,
  position_size_pct NUMERIC NOT NULL,
  status          TEXT NOT NULL DEFAULT 'watching', -- watching | open | closed | error
  entry_order_id  TEXT,
  entry_price     NUMERIC,
  qty             NUMERIC,
  opened_at       TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  last_error      TEXT,
  last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (username, strategy_id)
);
CREATE INDEX IF NOT EXISTS idx_live_deployments_status ON live_deployments(status);

-- A real-time snapshot of what the execution engine actually evaluated on
-- its most recent check, one row of history per deployment (not a growing
-- log like live_trade_log, this is intentionally "what does the engine see
-- right now"): the current computed value of each condition, whether each
-- passed, and the combined signal result, so a user can see WHY a strategy
-- hasn't fired yet, not just that it hasn't. Separate columns rather than
-- adding directly to live_deployments so the two concerns (execution state
-- vs. diagnostic detail) stay independently readable/updatable.
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS audit_conditions JSONB;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS audit_signal BOOLEAN;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS audit_price NUMERIC;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS audit_at TIMESTAMPTZ;

-- A genuine per-strategy trade history, distinct from live_deployments
-- (which only ever holds ONE row per strategy, overwritten on each new
-- deploy cycle). Every time the execution engine places a real entry order,
-- it INSERTs a new row here; when that position closes, the SAME row is
-- UPDATEd with the exit details. This is what lets a strategy that's been
-- live for weeks show its full real trade-by-trade history, entries, exits,
-- sizing, timestamps, rather than only ever showing its current position
-- (or relying on the global activity feed, which mixes trades in with
-- every other kind of account event and isn't scoped per strategy).
CREATE TABLE IF NOT EXISTS live_trade_log (
  id              SERIAL PRIMARY KEY,
  username        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  strategy_id     TEXT NOT NULL,
  strategy_name   TEXT NOT NULL DEFAULT '',
  broker          TEXT NOT NULL DEFAULT 'alpaca',
  symbol          TEXT NOT NULL,
  side            TEXT NOT NULL, -- buy | sell
  qty             NUMERIC NOT NULL,
  entry_order_id  TEXT,
  entry_price     NUMERIC NOT NULL,
  opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  exit_price      NUMERIC,
  closed_at       TIMESTAMPTZ,
  status          TEXT NOT NULL DEFAULT 'open' -- open | closed
);
CREATE INDEX IF NOT EXISTS idx_live_trade_log_lookup ON live_trade_log(username, strategy_id);


-- Per-user risk limits, enforced by the live execution engine on every new entry.
CREATE TABLE IF NOT EXISTS risk_limits (
  username                     TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  enabled                      BOOLEAN NOT NULL DEFAULT TRUE,
  max_daily_loss_pct           NUMERIC,
  max_capital_per_strategy_usd NUMERIC,
  max_open_positions           INTEGER,
  max_deployed_pct             NUMERIC,
  tripped_on                   TEXT,
  tripped_reason               TEXT,
  updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Settings, notifications, trials, alerts, 2FA, sessions, trade journal
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_settings (
  username              TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  require_paper_first   BOOLEAN NOT NULL DEFAULT TRUE,
  paper_min_days        INTEGER NOT NULL DEFAULT 3,
  disclosure_ack_at     TIMESTAMPTZ,
  disclosure_version    TEXT,
  notify_email          TEXT,
  notify_email_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  notify_telegram_chat  TEXT,
  notify_events         JSONB NOT NULL DEFAULT '{}'::jsonb,
  daily_hour_utc        INTEGER NOT NULL DEFAULT 17,
  last_daily_sent_on    TEXT,
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  id          SERIAL PRIMARY KEY,
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  kind        TEXT NOT NULL,
  title       TEXT NOT NULL,
  body        TEXT NOT NULL DEFAULT '',
  link        TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(username, created_at DESC);

CREATE TABLE IF NOT EXISTS telegram_link_codes (
  code        TEXT PRIMARY KEY,
  username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- First time a strategy ran in a no-real-money environment (demo simulation or
-- a paper broker account). Going live with real money is gated on this.
CREATE TABLE IF NOT EXISTS strategy_trials (
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  strategy_id  TEXT NOT NULL,
  mode         TEXT NOT NULL, -- demo | paper
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (username, strategy_id, mode)
);

CREATE TABLE IF NOT EXISTS alerts (
  id             SERIAL PRIMARY KEY,
  username       TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  name           TEXT NOT NULL DEFAULT '',
  symbol         TEXT NOT NULL,
  timeframe      TEXT NOT NULL DEFAULT '15m',
  conditions     JSONB NOT NULL,
  repeat         BOOLEAN NOT NULL DEFAULT FALSE,
  status         TEXT NOT NULL DEFAULT 'active', -- active | paused | fired
  last_signal    BOOLEAN,
  last_checked_at TIMESTAMPTZ,
  last_fired_at  TIMESTAMPTZ,
  fire_count     INTEGER NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(username);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS user_2fa (
  username         TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  secret_enc       TEXT NOT NULL,
  enabled          BOOLEAN NOT NULL DEFAULT FALSE,
  recovery_hashes  JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT;

-- Why the engine entered: the indicator readings and the last bars at the moment of the fill.
ALTER TABLE live_trade_log ADD COLUMN IF NOT EXISTS entry_snapshot JSONB;

-- Keep trading after each trade, and auto-pause after N losses in a row.
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS repeat BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS max_consecutive_losses INTEGER;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS needs_reset BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS streak_from TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS pause_reason TEXT;

-- One calendar warning per user, event and day.
CREATE TABLE IF NOT EXISTS calendar_notices (
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  notice_key TEXT NOT NULL,
  day        DATE NOT NULL,
  PRIMARY KEY (username, notice_key, day)
);

-- Settings an admin can change in the app (Stripe keys and prices). Values are encrypted.
CREATE TABLE IF NOT EXISTS app_settings (
  key        TEXT PRIMARY KEY,
  value_enc  TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT
);

-- A customer's own AI provider key (encrypted). Used instead of the platform's key.
CREATE TABLE IF NOT EXISTS user_ai_config (
  username    TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  provider    TEXT NOT NULL,
  model       TEXT NOT NULL,
  base_url    TEXT,
  api_key_enc TEXT NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Trailing stop, leverage and close confirmations for live trading.
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS trail_pct NUMERIC;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS trail_peak NUMERIC;
ALTER TABLE live_deployments ADD COLUMN IF NOT EXISTS leverage NUMERIC NOT NULL DEFAULT 1;
ALTER TABLE live_trade_log ADD COLUMN IF NOT EXISTS close_reason TEXT;
ALTER TABLE live_trade_log ADD COLUMN IF NOT EXISTS closed_ack BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE live_trade_log ADD COLUMN IF NOT EXISTS leverage NUMERIC NOT NULL DEFAULT 1;

-- Notification channels: email is verified by a code before any alert is sent to it.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='user_settings' AND column_name='notify_email_verified') THEN
    ALTER TABLE user_settings ADD COLUMN notify_email_verified BOOLEAN NOT NULL DEFAULT FALSE;
    -- Addresses that were already switched on before verification existed keep working.
    UPDATE user_settings SET notify_email_verified = TRUE WHERE notify_email_enabled AND notify_email IS NOT NULL;
  END IF;
END $$;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS email_code_hash TEXT;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS email_code_expires TIMESTAMPTZ;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS email_code_sent_at TIMESTAMPTZ;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS email_code_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS notify_email_last_error TEXT;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS notify_telegram_last_error TEXT;
ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS notify_telegram_linked_at TIMESTAMPTZ;
