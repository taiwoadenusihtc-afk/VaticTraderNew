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
