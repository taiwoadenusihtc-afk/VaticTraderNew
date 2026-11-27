# Release: close fix, real-data Following, aligned pages

Deploy: replace public/index.html, server/server.js, server/fast_stream.js, server/schema.sql;
add public/vatictrader-overview.mp4 and public/overview-poster.jpg (the old ad files are no longer used and can be deleted); add "ws": "^8" to package.json; hard-refresh.

- Close position: cancels open bracket orders and retries when Alpaca refuses (held qty). Tested on a mock only.
- Simulated activity removed (S3-S6). S1, S2, S7 still pending a decision.
- Following: all four tabs have real-data empty states and a starter view.
- Landing: new "Why rules, not guesses" section, 60-second video, honest "is / is not" copy, alerts and journal tile.
- Auth page: fake crowd-sentiment panel removed; copy aligned.
- Settings plans, FAQ and Learn guides aligned with the above.
- Video adds about 5 MB to the repo.

## Clips re-recorded (this build)
- Re-recorded from the current app: Home, Build, Backtest, Live, Manage, Portfolio, Code, Markets, Journal.
- New clips and Learn guides: Following, Portfolio Builder (clip added to its existing guide), Alerts (clip added to its guide).
- Community clip is not used (left out on request); the Community guide is text only.
- Journal clip shows example trades from a sample account, labelled on screen; the old one presented made-up trades as real.
- Portfolio Builder clip uses trending sample data that gives a mixed result (higher return, lower Sharpe, deeper drawdown than equal weight); both sides are shown.
- All clips use sample market data and a mock broker account; footer note on each says so.
- Learn text fixed: demo strategies use live prices with simulated fills.

## Landing video
- The top video in the landing page's video section is now a product overview (about 1:40) recorded from the real app: intro, home, build, backtest, demo and go-live checks, positions and risk limits, portfolio builder, alerts, code export, straight-talk card, end card.
- Section heading changed to "See VaticTrader in action". The AI-agent comparison ad is kept as a separate file and is not on the site.

## v7 reverted
- The email and Telegram removal was reverted on request. Email and Telegram alerts, the event toggles and the daily summary work as in v6.

## Brokers tab redesign (v9)
- New status header (connected / ready / coming soon) with a "Connect Alpaca" call to action when nothing is linked.
- Connected accounts come first as wide cards with cash, buying power and status tiles plus Test order, Refresh and Disconnect.
- Available brokers: uniform cards with type, a single capability label, and filter chips (All, Stocks, Crypto, CFDs, Automated trading).
- Coming soon is a compact chip row. The fictional "Sahm" prototype broker is no longer shown there.
- "How this works" is a collapsed note. The 24-node orbit diagram is removed. No server change.

## v10: practice-mode controls
- Stop strategy button on the demo panel (strategy page) and Stop all demo on the Portfolio panel.
- Close trade button on every open simulated trade (closes at the latest price; the strategy keeps running and waits for a fresh signal).
- Panels can be hidden/shown (remembered per browser).
- Clear practice history (all, or per strategy) with confirmation. Open trades are never deleted.
- Stopped strategies show a clear "Stopped" badge and keep their history visible.
- New endpoints: POST /api/sim/close/:strategyId, POST /api/sim/clear. No schema change.

## v11: opt-in safety guard screen + "Only trade if…" and event pause
- Settings are now reachable: Portfolio > "Safety and reliability" (Turn on / Edit settings / Resume entries). Off by default. The server side already existed; the app had no screen for it.
  Enforces on the server: daily loss cap, max open trades, losing-streak pause; unique order IDs + restart reconciliation; scheduler/order-failure/position-mismatch monitoring with alerts.
- Builder: new "Only trade if…" block (up to 5 AND-ed state filters such as Price vs SMA, ADX, RSI) and "Pause around big events" (Fed/ECB/BoE decision days; earnings when FINNHUB_API_KEY is set). Both optional and per strategy.
  Filters are included in backtests. Event pauses are not.
- Server enforcement: new table strategy_gates (auto-created), GET/PUT /api/gate/:strategyId. The gate runs only when the entry rule fires, blocks new entries only, and logs "entry skipped" with the reason (visible in Safety and reliability > Recent).
- Needs on the server: FINNHUB_API_KEY for earnings. The built-in rate-decision list ends 2026-12-31; add 2027 dates with MACRO_EVENTS_JSON='[{"date":"YYYY-MM-DD","bank":"FOMC|ECB|BoE","title":"..."}]'.
- Not built: news/sentiment (no data source configured). If added it should be a filter only.

## v12: trust and first-run
- **Robustness score** (0 to 100, one number) on every backtest: trade count 20%, recent out-of-sample result 30%, parameter-stability heatmap 25%, cost sensitivity 25%. Caps: under 20 trades max 40; losing recent 30% max 45; unprofitable max 20. Bands: Solid 70+, Mixed 45+, Weak below. It is a guide to how fragile a result looks, not a forecast.
- **Tune many** now warns that picking the best of many variants overfits. After a run it shows how many variants were tested, a multiple-testing check (Bonferroni at 5%, normal approximation) and a walk-forward check (4 forward blocks) per row. "Use this" is highlighted only when a row passes both. Single Tune also has a walk-forward button.
- **Realistic default costs** per asset class (fee + slippage per side, e.g. US stocks 0.03% + 0.02%, crypto 0.10% + 0.05%, GCC 0.12% + 0.05%, Nigeria 0.30% + 0.10%). Shown on the results screen with "Use typical costs" reset. Your own settings override them. These are typical retail estimates, not broker quotes.
- **Describe-first first run (about five minutes):** a new account's Home is a "Describe a strategy in plain English" box with example chips. Flow: describe, review, "Save and backtest on real data", then "Practise with pretend money". Practice no longer requires a connected broker (live still does). Setup checklist reordered: describe, backtest, practise, then broker.
- **Curated Ready-made list:** opens with 8 starter picks; "Browse all 830" or any search/filter shows the full library.
- No server or schema change in v12 (server.js and schema.sql are as in v11).
