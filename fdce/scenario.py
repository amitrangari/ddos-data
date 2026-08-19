"""
FDCE scenario simulator: generates bot (declined-card) and organic merchant
traffic and runs it through FDCEDetector, producing a REAL detection latency
and block rate rather than the hardcoded constants v1 used.

Card-damage mix (matches main_v1.md's Section VI.I prose):
  expired_only: 100% decline code 54
  mixed:        ~60% code 54, ~25% code 82, ~15% code 14

Organic merchants: ~85% completion rate (matches the paper's legitimate
transaction-mix assumption); declines, when they occur, spread close to
uniformly across a wider code set (grounded in calibrate_fdce_from_real_data.py
against 3.0M real ng-card-auth records: organic single-code share p99=0.712).
"""

import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .fdce import FDCEDetector

BOT_BIN_POOL_SIZE = 4          # BINs the bot cluster concentrates on (R-11 needs volume per BIN)
ORGANIC_BIN_POOL_SIZE = 30
N_ORGANIC_MERCHANTS = 20
ORGANIC_COMPLETION_RATE = 0.85
ORGANIC_DECLINE_CODES = ["14", "54", "57", "82", "05", "51", "61"]  # broader, near-uniform

CARD_MIX = {
    "expired_only": {"54": 1.00},
    "mixed": {"54": 0.60, "82": 0.25, "14": 0.15},
}


def _weighted_choice(rng: random.Random, weights: dict) -> str:
    r = rng.random()
    acc = 0.0
    for k, w in weights.items():
        acc += w
        if r <= acc:
            return k
    return list(weights.keys())[-1]


@dataclass
class FDCEScenarioResult:
    detection_latency_s: Optional[float]
    triggered_rule: Optional[str]   # "R-11", "R-12", or both
    block_rate: float               # fraction of bot-attack transactions blocked
    n_bot_txn: int
    n_bot_blocked: int
    n_organic_r12_false_positives: int = 0


def simulate_fdce_scenario(cluster_size: int, card_type: str, intensity: float,
                           seed: int, duration_s: float = 120.0) -> FDCEScenarioResult:
    rng = random.Random(seed)
    detector = FDCEDetector(window_s=60.0)

    # Scale the bot BIN pool with cluster size so per-BIN aggregate rate stays
    # in a realistic range regardless of cluster size (a fixed small pool would
    # make R-11 trigger near-instantly for large clusters purely from volume,
    # not from genuine decline-code concentration).
    n_bot_bins = max(BOT_BIN_POOL_SIZE, cluster_size // 8)
    bot_bins = [f"BOT{i:03d}" for i in range(n_bot_bins)]
    organic_bins = [f"ORG{i:03d}" for i in range(ORGANIC_BIN_POOL_SIZE)]
    bot_merchants = [f"bot_merchant_{i:04d}" for i in range(cluster_size)]
    organic_merchants = [f"org_merchant_{i:03d}" for i in range(N_ORGANIC_MERCHANTS)]
    card_mix = CARD_MIX[card_type]

    # Per-bot-merchant rate: 5-15 TPS scaled by intensity (well below the 100 TPS
    # per-merchant R-12 threshold individually, per main_v1.md's threat model).
    per_bot_rate = 5.0 + intensity * 10.0
    per_organic_rate = 3.0

    # Build an event schedule: list of (ts, kind, merchant_id, bin_prefix)
    events: List[Tuple[float, str, str, str]] = []
    for m in bot_merchants:
        bin_p = rng.choice(bot_bins)
        t = 0.0
        while t < duration_s:
            t += rng.expovariate(per_bot_rate)
            if t < duration_s:
                events.append((t, "bot", m, bin_p))
    for m in organic_merchants:
        bin_p = rng.choice(organic_bins)
        t = 0.0
        while t < duration_s:
            t += rng.expovariate(per_organic_rate)
            if t < duration_s:
                events.append((t, "organic", m, bin_p))
    events.sort(key=lambda e: e[0])

    n_bot_txn = 0
    n_bot_blocked = 0
    detection_ts: Optional[float] = None
    triggered_rule: Optional[str] = None
    organic_r12_false_positives: set = set()

    for ts, kind, merchant, bin_p in events:
        if kind == "bot":
            n_bot_txn += 1
            if detector.is_blocked(bin_p, merchant):
                n_bot_blocked += 1
                continue  # blocked before it can pollute the window further
            code = _weighted_choice(rng, card_mix)
            detector.observe_auth_request(merchant, ts)
            detector.observe_auth_response(bin_p, ts, code)
            # bot transactions never complete (declined by construction)
        else:
            detector.observe_auth_request(merchant, ts)
            if rng.random() < ORGANIC_COMPLETION_RATE:
                detector.observe_completion(merchant, ts + 1.0)
                detector.observe_auth_response(bin_p, ts, None)
            else:
                code = rng.choice(ORGANIC_DECLINE_CODES)
                detector.observe_auth_response(bin_p, ts, code)

        # Check every event (not just until first detection) so the block rate
        # reflects the detector continuing to flag additional bins/merchants as
        # the attack proceeds -- not just the single bin/merchant that tripped
        # first.
        r11 = detector.check_r11(bin_p, ts)
        r12 = detector.check_r12(merchant, ts)
        if kind == "organic" and r12.triggered:
            organic_r12_false_positives.add(merchant)
        if detection_ts is None and (r11.triggered or r12.triggered):
            detection_ts = ts
            triggered_rule = "R-11" if r11.triggered else "R-12"
            if r11.triggered and r12.triggered:
                triggered_rule = "R-11+R-12"

    block_rate = n_bot_blocked / n_bot_txn if n_bot_txn > 0 else 0.0
    return FDCEScenarioResult(
        detection_latency_s=detection_ts, triggered_rule=triggered_rule,
        block_rate=block_rate, n_bot_txn=n_bot_txn, n_bot_blocked=n_bot_blocked,
        n_organic_r12_false_positives=len(organic_r12_false_positives),
    )


def simulate_fdce_adversarial_spread(cluster_size: int, intensity: float, seed: int,
                                     duration_s: float = 120.0,
                                     spread: Tuple[float, float, float, float] = (0.24, 0.24, 0.24, 0.28)
                                     ) -> FDCEScenarioResult:
    """Security-review-requested robustness check: an adversary who deliberately
    spreads decline codes to sit just under the R-11 0.80 concentration
    threshold (default 24/24/24/28%, vs. real organic p99 single-code share of
    0.712). Tests whether R-12 (completion-rate floor) alone still catches the
    attack once R-11 is evaded by construction."""
    rng = random.Random(seed)
    detector = FDCEDetector(window_s=60.0)
    codes = ["14", "54", "57", "82"]
    card_mix = dict(zip(codes, spread))

    n_bot_bins = max(BOT_BIN_POOL_SIZE, cluster_size // 8)
    bot_bins = [f"BOT{i:03d}" for i in range(n_bot_bins)]
    organic_bins = [f"ORG{i:03d}" for i in range(ORGANIC_BIN_POOL_SIZE)]
    bot_merchants = [f"bot_merchant_{i:04d}" for i in range(cluster_size)]
    organic_merchants = [f"org_merchant_{i:03d}" for i in range(N_ORGANIC_MERCHANTS)]
    per_bot_rate = 5.0 + intensity * 10.0
    per_organic_rate = 3.0

    events: List[Tuple[float, str, str, str]] = []
    for m in bot_merchants:
        bin_p = rng.choice(bot_bins)
        t = 0.0
        while t < duration_s:
            t += rng.expovariate(per_bot_rate)
            if t < duration_s:
                events.append((t, "bot", m, bin_p))
    for m in organic_merchants:
        bin_p = rng.choice(organic_bins)
        t = 0.0
        while t < duration_s:
            t += rng.expovariate(per_organic_rate)
            if t < duration_s:
                events.append((t, "organic", m, bin_p))
    events.sort(key=lambda e: e[0])

    n_bot_txn = 0
    n_bot_blocked = 0
    detection_ts: Optional[float] = None
    triggered_rule: Optional[str] = None
    r11_ever_triggered = False

    for ts, kind, merchant, bin_p in events:
        if kind == "bot":
            n_bot_txn += 1
            if detector.is_blocked(bin_p, merchant):
                n_bot_blocked += 1
                continue
            code = _weighted_choice(rng, card_mix)
            detector.observe_auth_request(merchant, ts)
            detector.observe_auth_response(bin_p, ts, code)
        else:
            detector.observe_auth_request(merchant, ts)
            if rng.random() < ORGANIC_COMPLETION_RATE:
                detector.observe_completion(merchant, ts + 1.0)
                detector.observe_auth_response(bin_p, ts, None)
            else:
                code = rng.choice(ORGANIC_DECLINE_CODES)
                detector.observe_auth_response(bin_p, ts, code)

        r11 = detector.check_r11(bin_p, ts)
        if r11.triggered:
            r11_ever_triggered = True
        if detection_ts is None:
            r12 = detector.check_r12(merchant, ts)
            if r11.triggered or r12.triggered:
                detection_ts = ts
                triggered_rule = "R-11" if r11.triggered else "R-12"

    block_rate = n_bot_blocked / n_bot_txn if n_bot_txn > 0 else 0.0
    return FDCEScenarioResult(
        detection_latency_s=detection_ts, triggered_rule=triggered_rule,
        block_rate=block_rate, n_bot_txn=n_bot_txn, n_bot_blocked=n_bot_blocked,
    ), r11_ever_triggered
