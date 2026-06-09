"""fetch_market_data tool — simulated external market data feed.

Fully deterministic — no real external API calls.
Represents LLM03 (supply chain) risk: agents relying on external data
whose provenance and integrity are unverified.
"""

from __future__ import annotations

import math
import random
import time

from langchain_core.tools import tool

# Deterministic price simulation (seeded, reproducible)
_PRICES: dict[str, float] = {
    "AAPL": 185.42,
    "MSFT": 412.10,
    "GOOGL": 175.88,
    "AMZN": 198.25,
    "TSLA": 248.70,
    "SPY": 512.30,
    "QQQ": 440.15,
    "BTC": 67_542.00,
    "ETH": 3_201.50,
    "GOLD": 2_315.00,
}

_rng = random.Random(2024)


def _simulated_price(symbol: str) -> float:
    base = _PRICES.get(symbol.upper(), 100.0)
    # Deterministic jitter based on current hour (stable within a demo session)
    hour_seed = int(time.time()) // 3600
    r = random.Random(hour_seed + hash(symbol))
    jitter = r.uniform(-0.02, 0.02)
    return round(base * (1 + jitter), 2)


@tool
def fetch_market_data_tool(symbol: str) -> str:
    """Fetch simulated market data for a financial symbol.

    Args:
        symbol: Ticker symbol (e.g. AAPL, MSFT, BTC).

    Returns:
        Simulated price quote and basic market data.

    OWASP: LLM03 (Supply Chain — unverified external data)
    Reversibility: reversible
    Risk tier: LOW
    """
    symbol = symbol.upper().strip()
    price = _simulated_price(symbol)
    prev_close = _PRICES.get(symbol, 100.0)
    change = price - prev_close
    change_pct = (change / prev_close) * 100 if prev_close else 0

    sign = "+" if change >= 0 else ""
    return (
        f"MARKET DATA: {symbol}\n"
        f"Price:      ${price:,.2f}\n"
        f"Change:     {sign}{change:.2f} ({sign}{change_pct:.2f}%)\n"
        f"Prev close: ${prev_close:,.2f}\n"
        f"Source:     SimulatedFeed/v1 (demo — not real market data)\n"
        f"Timestamp:  {__import__('datetime').datetime.utcnow().isoformat()}Z"
    )
