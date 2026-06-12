"""
sources — TorShield-IR bridge collection source modules.

Available modules:
  torproject      Async scraper for bridges.torproject.org (rotating UA, polite delay)
  moat            MOAT API client (country=IR, no CAPTCHA)
  github_bridges  GitHub public bridge repo scraper
  bridgedb_api    BridgeDB API client
  static_bridges  Hard-coded reliable static bridges (snowflake, meek-lite)
  telegram_bridges Telegram channel bridge extractor
  direct_scraper  Direct scraper with connectivity testing (integrated from legacy scraper)
"""
