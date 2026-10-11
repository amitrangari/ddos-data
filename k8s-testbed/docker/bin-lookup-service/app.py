#!/usr/bin/env python3
"""
BIN Lookup Service with BIN-WATCH Entropy Monitoring
=====================================================
Validates BIN prefixes and computes the BIN Entropy Score (BES) over a
60-second sliding window to detect enumeration attacks.

BIN-WATCH detection zones (from paper Section VIII.C):
  Zone 1 (Normal):   BES < theta_low  -> action: allow
  Zone 2 (Warning):  theta_low <= BES < theta_high -> action: throttle
  Zone 3 (Attack):   BES >= theta_high -> action: block

Composite signal = BES + sequential_run_penalty + velocity_anomaly_score

Paper: Section VIII -- BIN-WATCH Entropy-Based Enumeration Detection
"""

import math
import os
import random
import time
from collections import deque, defaultdict
from typing import Dict, List, Tuple

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="BIN Lookup Service", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BIN_WATCH_ENABLED = os.getenv("BIN_WATCH_ENABLED", "true").lower() == "true"
BIN_WATCH_THETA_HIGH = float(os.getenv("BIN_WATCH_THETA_HIGH", "7.0"))
BIN_WATCH_THETA_LOW = float(os.getenv("BIN_WATCH_THETA_LOW", "4.5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
NUM_LEGITIMATE_BINS = int(os.getenv("NUM_LEGITIMATE_BINS", "10000"))
ZIPF_ALPHA = 1.5

# ---------------------------------------------------------------------------
# BIN table (synthetic: Zipf-distributed over NUM_LEGITIMATE_BINS prefixes)
# ---------------------------------------------------------------------------
_rng = random.Random(42)
_LEGIT_BINS: set = set()

def _build_bin_table():
    bins = set()
    # Generate BINs in 4xxxxx, 5xxxxx, 6xxxxx ranges (Visa, Mastercard, Discover)
    prefixes = ["4", "5", "6"]
    for _ in range(NUM_LEGITIMATE_BINS):
        prefix = _rng.choice(prefixes)
        suffix = "".join([str(_rng.randint(0, 9)) for _ in range(5)])
        bins.add(prefix + suffix)
    return bins

_LEGIT_BINS = _build_bin_table()

# ---------------------------------------------------------------------------
# Sliding window state for BIN-WATCH
# ---------------------------------------------------------------------------
_bin_window: deque = deque()         # (timestamp, bin_prefix)
_total_lookups = 0
_total_attacks_detected = 0
_false_positives = 0   # Legitimate requests flagged (tracked via is_legitimate hint)
_true_positives = 0
_false_negatives = 0
_true_negatives = 0


def _prune_window():
    cutoff = time.time() - WINDOW_SECONDS
    while _bin_window and _bin_window[0][0] < cutoff:
        _bin_window.popleft()


def _shannon_entropy(bins: List[str]) -> float:
    """Shannon entropy of BIN prefix distribution in current window."""
    if not bins:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for b in bins:
        counts[b] += 1
    n = len(bins)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _sequential_run_penalty(bins: List[str]) -> float:
    """
    Detect sequential BIN scanning: counts longest run of numerically
    consecutive BIN prefixes. Returns a score in [0, 3].
    """
    if len(bins) < 5:
        return 0.0
    try:
        sorted_bins = sorted(int(b) for b in bins if b.isdigit())
    except ValueError:
        return 0.0
    if not sorted_bins:
        return 0.0
    max_run = 1
    current_run = 1
    for i in range(1, len(sorted_bins)):
        if sorted_bins[i] == sorted_bins[i - 1] + 1:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    # Penalty: 0 for runs < 5; scales up to 3.0 for runs >= 50
    penalty = min(3.0, max(0.0, (max_run - 5) / 15.0))
    return penalty


def _velocity_anomaly_score(bins: List[str]) -> float:
    """
    Measure velocity: ratio of unique BINs to total lookups.
    High ratio (many unique BINs) suggests enumeration. Score in [0, 2].
    """
    if not bins:
        return 0.0
    unique_ratio = len(set(bins)) / len(bins)
    # Normal traffic (Zipf): unique_ratio ~ 0.3-0.5
    # Attack traffic: unique_ratio ~ 0.9-1.0
    score = max(0.0, (unique_ratio - 0.5) / 0.25)
    return min(score, 2.0)


def _compute_bes(bins: List[str]) -> Tuple[float, float, float, float]:
    """
    Compute composite BIN Entropy Score.
    BES = entropy + sequential_penalty + velocity_score

    Returns: (bes, entropy, seq_penalty, velocity_score)
    """
    entropy = _shannon_entropy(bins)
    seq_penalty = _sequential_run_penalty(bins)
    vel_score = _velocity_anomaly_score(bins)
    bes = entropy + seq_penalty + vel_score
    return bes, entropy, seq_penalty, vel_score


def _classify(bes: float) -> Tuple[str, bool]:
    """Map BES to action and attack flag."""
    if bes >= BIN_WATCH_THETA_HIGH:
        return "block", True
    elif bes >= BIN_WATCH_THETA_LOW:
        return "throttle", True
    else:
        return "allow", False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    _prune_window()
    return {
        "status": "ok",
        "service": "bin-lookup-service",
        "bin_watch_enabled": BIN_WATCH_ENABLED,
        "window_size": len(_bin_window),
    }


@app.get("/metrics")
async def metrics():
    _prune_window()
    bins_in_window = [b for _, b in _bin_window]
    bes, entropy, seq_p, vel_s = _compute_bes(bins_in_window)
    action, is_attack = _classify(bes) if BIN_WATCH_ENABLED else ("allow", False)

    tp = _true_positives
    fp = _false_positives
    fn = _false_negatives
    tn = _true_negatives
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    fpr = fp / max(1, fp + tn)

    return {
        "bin_watch_enabled": BIN_WATCH_ENABLED,
        "window_bins": len(bins_in_window),
        "bes_score": round(bes, 4),
        "entropy": round(entropy, 4),
        "sequential_penalty": round(seq_p, 4),
        "velocity_score": round(vel_s, 4),
        "current_action": action,
        "attack_detected": is_attack,
        "total_lookups": _total_lookups,
        "attacks_detected": _total_attacks_detected,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "theta_high": BIN_WATCH_THETA_HIGH,
        "theta_low": BIN_WATCH_THETA_LOW,
    }


@app.post("/lookup")
async def lookup(body: dict = None):
    global _total_lookups, _total_attacks_detected
    global _false_positives, _true_positives, _false_negatives, _true_negatives

    body = body or {}
    bin_prefix = str(body.get("bin", "400000"))[:6]
    is_legitimate = body.get("is_legitimate", True)
    _total_lookups += 1

    now = time.time()
    _bin_window.append((now, bin_prefix))
    _prune_window()

    # BIN validation
    is_valid_bin = bin_prefix in _LEGIT_BINS

    if not BIN_WATCH_ENABLED:
        return JSONResponse(
            {
                "valid": is_valid_bin,
                "bin": bin_prefix,
                "action": "allow",
                "bes_score": 0.0,
                "is_attack": False,
            }
        )

    # BIN-WATCH computation
    bins_in_window = [b for _, b in _bin_window]
    bes, entropy, seq_p, vel_s = _compute_bes(bins_in_window)
    action, is_attack = _classify(bes)

    # Update confusion matrix counters
    if is_attack and not is_legitimate:
        _true_positives += 1
        _total_attacks_detected += 1
    elif is_attack and is_legitimate:
        _false_positives += 1
    elif not is_attack and not is_legitimate:
        _false_negatives += 1
    else:
        _true_negatives += 1

    return JSONResponse(
        {
            "valid": is_valid_bin,
            "bin": bin_prefix,
            "action": action,
            "bes_score": round(bes, 4),
            "entropy": round(entropy, 4),
            "sequential_penalty": round(seq_p, 4),
            "velocity_score": round(vel_s, 4),
            "is_attack": is_attack,
            "window_size": len(bins_in_window),
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
