#!/usr/bin/env python3
"""
BIN-WATCH Simulation: Entropy-Based BIN Enumeration Detection
==============================================================

This script implements a computational simulation of the BIN-WATCH detection
framework proposed in Section IX.E of the paper "Adaptive DDoS Defense
Strategies for High-Throughput Payment Processing Systems."

BIN-WATCH detects BIN enumeration attacks by computing the BIN Entropy Score
(BES) -- Shannon entropy of the BIN prefix distribution within sliding time
windows -- and applying a three-zone detection model with a composite signal
that incorporates geographic entropy and card issuance event flags.

The simulation generates synthetic BIN lookup traffic for three scenarios
(normal, card issuance burst, BIN enumeration attack), computes detection
metrics, and reports precision, recall, F1, and false positive rate.

Dependencies: numpy (for random generation and statistics)
Usage: python3 bin-watch-simulation.py
"""

import math
import random
from collections import Counter
from typing import List, Tuple, Dict

# Try to import numpy; fall back to stdlib if unavailable
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("Warning: numpy not available. Using stdlib random (slower).")


# =============================================================================
# Configuration
# =============================================================================

# BIN-WATCH detection thresholds (calibrated from paper Section IX.E.5)
THETA_LOW = 3.2     # bits -- 95th percentile of normal BES
THETA_HIGH = 5.8    # bits -- attack detection threshold (1.5x theta_low approx)
PHI = 2.5           # bits -- geographic entropy threshold

# Traffic generation parameters
NORMAL_BIN_POOL_SIZE = 1000       # Number of "popular" BINs in normal traffic
ATTACK_BIN_SPACE = 100_000        # BIN space probed during enumeration attack
ZIPF_ALPHA = 1.5                  # Zipf exponent for normal BIN distribution
WINDOW_SIZE_SEC = 60              # Observation window (seconds)
REQUESTS_PER_WINDOW_NORMAL = 500  # Normal request rate per window
REQUESTS_PER_WINDOW_ATTACK = 2000 # Attack request rate per window (higher volume)

# Simulation parameters
NUM_NORMAL_WINDOWS = 60
NUM_ISSUANCE_WINDOWS = 10
NUM_ATTACK_WINDOWS = 30
TOTAL_WINDOWS = NUM_NORMAL_WINDOWS + NUM_ISSUANCE_WINDOWS + NUM_ATTACK_WINDOWS
RANDOM_SEED = 42

# Geographic simulation parameters
NUM_GEO_REGIONS = 20  # Total geographic regions (countries/ASNs)
NORMAL_GEO_CONCENTRATION = 3  # Normal traffic concentrated in ~3 regions
ATTACK_GEO_SPREAD = 15  # Attack traffic spread across ~15 regions


# =============================================================================
# Core BIN-WATCH Functions
# =============================================================================

def compute_bes(bin_prefixes: List[str]) -> float:
    """
    Compute BIN Entropy Score for a list of BIN lookup requests in a window.

    BES = -SUM(p_b * log2(p_b)) for each distinct BIN prefix b.

    Shannon entropy of the BIN prefix frequency distribution. Higher values
    indicate more uniform (suspicious) distributions; lower values indicate
    concentrated (normal) distributions following power-law patterns.

    Args:
        bin_prefixes: List of 6-digit BIN prefix strings observed in the window.

    Returns:
        BES value in bits. Range: [0, log2(num_distinct_bins)].
    """
    if not bin_prefixes:
        return 0.0

    total = len(bin_prefixes)
    counts = Counter(bin_prefixes)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def compute_geographic_entropy(geo_labels: List[str]) -> float:
    """
    Compute Shannon entropy of the geographic distribution of request sources.

    Attacks from botnets tend to originate from many geographic regions
    (high entropy), while legitimate traffic and card issuance events are
    geographically concentrated (low entropy).

    Args:
        geo_labels: List of geographic region identifiers for each request.

    Returns:
        Geographic entropy in bits.
    """
    if not geo_labels:
        return 0.0

    total = len(geo_labels)
    counts = Counter(geo_labels)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def classify_zone(bes: float) -> str:
    """
    Classify a BES value into one of three detection zones.

    - Normal: BES < theta_low (concentrated BIN distribution, expected pattern)
    - Elevated: theta_low <= BES < theta_high (unusual but ambiguous)
    - Attack: BES >= theta_high (high diversity, likely enumeration)

    Args:
        bes: BIN Entropy Score value.

    Returns:
        Zone label: 'normal', 'elevated', or 'attack'.
    """
    if bes < THETA_LOW:
        return 'normal'
    elif bes < THETA_HIGH:
        return 'elevated'
    else:
        return 'attack'


def composite_detection(bes: float, i_flag: bool, geo_entropy: float) -> bool:
    """
    Apply the BIN-WATCH composite detection signal.

    ATTACK = (BES > theta_high) AND (NOT I_flag) AND (geo_entropy > phi)

    All three conditions must be met to trigger an attack detection:
    1. BIN diversity exceeds the attack threshold.
    2. No registered card issuance event is in progress (FS-ISAC check).
    3. Request sources are geographically dispersed (botnet pattern).

    This composite reduces false positives from card issuance events,
    which produce high BES but concentrated geographic patterns and
    have a registered I_flag.

    Args:
        bes: BIN Entropy Score.
        i_flag: True if a card issuance event is registered for observed BINs.
        geo_entropy: Shannon entropy of source geographic distribution.

    Returns:
        True if attack detected, False otherwise.
    """
    return (bes > THETA_HIGH) and (not i_flag) and (geo_entropy > PHI)


# =============================================================================
# Traffic Generation
# =============================================================================

def generate_zipf_weights(n: int, alpha: float) -> List[float]:
    """
    Generate Zipf-distributed probability weights for n items.

    In real payment systems, BIN lookup traffic follows a power-law
    distribution: a small number of major issuers' BINs account for
    the majority of lookups, while thousands of smaller issuers
    contribute occasional queries.

    Args:
        n: Number of items (BIN prefixes).
        alpha: Zipf exponent (higher = more concentrated).

    Returns:
        List of probability weights summing to 1.0.
    """
    weights = [1.0 / (i ** alpha) for i in range(1, n + 1)]
    total = sum(weights)
    return [w / total for w in weights]


def generate_normal_traffic(num_requests: int, rng: random.Random) -> Tuple[List[str], List[str]]:
    """
    Generate normal BIN lookup traffic following Zipf's law.

    Normal traffic characteristics:
    - BIN distribution follows power law (few popular BINs dominate)
    - Geographic sources concentrated in 2-3 regions
    - Low BIN entropy score

    Args:
        num_requests: Number of BIN lookup requests to generate.
        rng: Seeded random number generator.

    Returns:
        Tuple of (bin_prefixes, geo_labels).
    """
    # Generate BIN pool (top issuers' BINs)
    bin_pool = [f"{400000 + i:06d}" for i in range(NORMAL_BIN_POOL_SIZE)]
    weights = generate_zipf_weights(NORMAL_BIN_POOL_SIZE, ZIPF_ALPHA)

    # Sample BINs according to Zipf distribution
    bin_prefixes = rng.choices(bin_pool, weights=weights, k=num_requests)

    # Geographic distribution: concentrated in few regions
    geo_regions = [f"region_{i}" for i in range(NUM_GEO_REGIONS)]
    geo_weights = generate_zipf_weights(NUM_GEO_REGIONS, 3.0)  # Very concentrated
    geo_labels = rng.choices(geo_regions, weights=geo_weights, k=num_requests)

    return bin_prefixes, geo_labels


def generate_issuance_burst_traffic(num_requests: int, rng: random.Random) -> Tuple[List[str], List[str]]:
    """
    Generate card issuance burst traffic.

    Card issuance events produce temporary BIN diversity spikes when a major
    issuer rolls out a new card product (new BIN ranges activated). This
    traffic has higher entropy than normal but is legitimate and should NOT
    trigger attack detection.

    Characteristics:
    - Elevated BIN diversity (new BIN ranges added to normal traffic)
    - Geographic concentration (issuance from issuer's home region)
    - I_flag = True (registered with FS-ISAC)

    Args:
        num_requests: Number of requests to generate.
        rng: Seeded random number generator.

    Returns:
        Tuple of (bin_prefixes, geo_labels).
    """
    # Mix of normal traffic (70%) and new BIN range (30%)
    normal_count = int(num_requests * 0.7)
    issuance_count = num_requests - normal_count

    # Normal portion
    bin_pool = [f"{400000 + i:06d}" for i in range(NORMAL_BIN_POOL_SIZE)]
    weights = generate_zipf_weights(NORMAL_BIN_POOL_SIZE, ZIPF_ALPHA)
    normal_bins = rng.choices(bin_pool, weights=weights, k=normal_count)

    # Issuance portion: new BIN range (e.g., 550000-550099)
    new_bin_range = [f"{550000 + i:06d}" for i in range(100)]
    issuance_bins = rng.choices(new_bin_range, k=issuance_count)

    bin_prefixes = normal_bins + issuance_bins
    rng.shuffle(bin_prefixes)

    # Geographic: concentrated in issuer's home region (1-2 regions)
    geo_regions = [f"region_{i}" for i in range(NUM_GEO_REGIONS)]
    geo_weights = [0.0] * NUM_GEO_REGIONS
    geo_weights[0] = 0.80  # 80% from primary region
    geo_weights[1] = 0.15  # 15% from secondary region
    for i in range(2, NUM_GEO_REGIONS):
        geo_weights[i] = 0.05 / (NUM_GEO_REGIONS - 2)
    geo_labels = rng.choices(geo_regions, weights=geo_weights, k=num_requests)

    return bin_prefixes, geo_labels


def generate_attack_traffic(num_requests: int, rng: random.Random) -> Tuple[List[str], List[str]]:
    """
    Generate BIN enumeration attack traffic.

    Attack characteristics:
    - Near-uniform BIN distribution across large BIN space (high entropy)
    - Geographically dispersed sources (botnet)
    - No registered issuance event (I_flag = False)

    This simulates an attacker probing random BIN prefixes to discover
    valid card ranges for subsequent fraud operations.

    Args:
        num_requests: Number of attack requests to generate.
        rng: Seeded random number generator.

    Returns:
        Tuple of (bin_prefixes, geo_labels).
    """
    # Uniform random sampling from large BIN space
    bin_prefixes = [f"{rng.randint(0, ATTACK_BIN_SPACE - 1):06d}" for _ in range(num_requests)]

    # Geographic: dispersed across many regions (botnet pattern)
    geo_regions = [f"region_{i}" for i in range(NUM_GEO_REGIONS)]
    # Near-uniform distribution across many regions
    geo_weights = [1.0 / ATTACK_GEO_SPREAD if i < ATTACK_GEO_SPREAD else 0.01
                   for i in range(NUM_GEO_REGIONS)]
    total_gw = sum(geo_weights)
    geo_weights = [w / total_gw for w in geo_weights]
    geo_labels = rng.choices(geo_regions, weights=geo_weights, k=num_requests)

    return bin_prefixes, geo_labels


# =============================================================================
# Simulation Runner
# =============================================================================

def run_simulation() -> List[Dict]:
    """
    Run the full BIN-WATCH detection simulation over 100 windows.

    Window allocation:
    - Windows 0-59: Normal traffic (60 windows)
    - Windows 60-69: Card issuance burst (10 windows, I_flag=True)
    - Windows 70-99: BIN enumeration attack (30 windows)

    For each window, the simulation:
    1. Generates traffic according to the window's scenario type.
    2. Computes BIN Entropy Score (BES).
    3. Computes geographic entropy.
    4. Applies the composite detection signal.
    5. Records detection result and true label for metric computation.

    Returns:
        List of per-window result dictionaries.
    """
    rng = random.Random(RANDOM_SEED)
    results = []

    for window_id in range(TOTAL_WINDOWS):
        # Determine window type and generate traffic
        if window_id < NUM_NORMAL_WINDOWS:
            true_label = 'normal'
            i_flag = False
            num_requests = REQUESTS_PER_WINDOW_NORMAL + rng.randint(-50, 50)
            bin_prefixes, geo_labels = generate_normal_traffic(num_requests, rng)

        elif window_id < NUM_NORMAL_WINDOWS + NUM_ISSUANCE_WINDOWS:
            true_label = 'issuance'
            i_flag = True  # Registered card issuance event
            num_requests = REQUESTS_PER_WINDOW_NORMAL + rng.randint(100, 300)
            bin_prefixes, geo_labels = generate_issuance_burst_traffic(num_requests, rng)

        else:
            true_label = 'attack'
            i_flag = False
            num_requests = REQUESTS_PER_WINDOW_ATTACK + rng.randint(-200, 200)
            bin_prefixes, geo_labels = generate_attack_traffic(num_requests, rng)

        # Compute detection metrics
        bes = compute_bes(bin_prefixes)
        geo_ent = compute_geographic_entropy(geo_labels)
        zone = classify_zone(bes)
        detected = composite_detection(bes, i_flag, geo_ent)

        # Determine correctness
        if true_label == 'attack':
            correct = detected  # True positive if detected, false negative if not
        else:
            correct = not detected  # True negative if not detected, false positive if detected

        results.append({
            'window_id': window_id,
            'true_label': true_label,
            'num_requests': num_requests,
            'bes': bes,
            'zone': zone,
            'i_flag': i_flag,
            'geo_entropy': geo_ent,
            'detected': detected,
            'correct': correct
        })

    return results


def compute_metrics(results: List[Dict]) -> Dict:
    """
    Compute precision, recall, F1, and false positive rate from simulation results.

    Definitions:
    - True Positive (TP): Attack window correctly detected.
    - False Positive (FP): Non-attack window incorrectly detected as attack.
    - False Negative (FN): Attack window not detected.
    - True Negative (TN): Non-attack window correctly not detected.

    Returns:
        Dictionary with precision, recall, f1, fpr, and counts.
    """
    tp = sum(1 for r in results if r['true_label'] == 'attack' and r['detected'])
    fp = sum(1 for r in results if r['true_label'] != 'attack' and r['detected'])
    fn = sum(1 for r in results if r['true_label'] == 'attack' and not r['detected'])
    tn = sum(1 for r in results if r['true_label'] != 'attack' and not r['detected'])

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr
    }


def print_results_table(results: List[Dict]) -> None:
    """Print a formatted results table for all 100 windows."""
    header = (
        f"{'Win':>4} | {'Label':>8} | {'Reqs':>5} | {'BES':>6} | {'Zone':>8} | "
        f"{'I_flag':>6} | {'GeoEnt':>6} | {'Detect':>6} | {'Correct':>7}"
    )
    separator = "-" * len(header)

    print("\n" + "=" * len(header))
    print("BIN-WATCH DETECTION SIMULATION RESULTS")
    print("=" * len(header))
    print(header)
    print(separator)

    for r in results:
        print(
            f"{r['window_id']:4d} | {r['true_label']:>8} | {r['num_requests']:5d} | "
            f"{r['bes']:6.2f} | {r['zone']:>8} | {r['i_flag']!s:>6} | "
            f"{r['geo_entropy']:6.2f} | {r['detected']!s:>6} | {r['correct']!s:>7}"
        )

    print(separator)


def print_summary(metrics: Dict, results: List[Dict]) -> None:
    """Print summary statistics and per-scenario BES distributions."""
    print("\n" + "=" * 60)
    print("DETECTION PERFORMANCE SUMMARY")
    print("=" * 60)

    print(f"\nConfusion Matrix:")
    print(f"  True Positives  (TP): {metrics['tp']:4d}  (attack windows correctly detected)")
    print(f"  False Positives (FP): {metrics['fp']:4d}  (non-attack windows incorrectly flagged)")
    print(f"  False Negatives (FN): {metrics['fn']:4d}  (attack windows missed)")
    print(f"  True Negatives  (TN): {metrics['tn']:4d}  (non-attack windows correctly passed)")

    print(f"\nKey Metrics:")
    print(f"  Precision:          {metrics['precision']:.4f}")
    print(f"  Recall:             {metrics['recall']:.4f}")
    print(f"  F1 Score:           {metrics['f1']:.4f}")
    print(f"  False Positive Rate:{metrics['fpr']:.4f}")

    # Per-scenario BES statistics
    print(f"\nPer-Scenario BES Distribution:")
    for label in ['normal', 'issuance', 'attack']:
        bes_values = [r['bes'] for r in results if r['true_label'] == label]
        if bes_values:
            mean_bes = sum(bes_values) / len(bes_values)
            min_bes = min(bes_values)
            max_bes = max(bes_values)
            std_bes = (sum((x - mean_bes) ** 2 for x in bes_values) / len(bes_values)) ** 0.5
            print(f"  {label:>10}: mean={mean_bes:.2f}, std={std_bes:.2f}, "
                  f"min={min_bes:.2f}, max={max_bes:.2f}, n={len(bes_values)}")

    # Per-scenario geographic entropy statistics
    print(f"\nPer-Scenario Geographic Entropy Distribution:")
    for label in ['normal', 'issuance', 'attack']:
        geo_values = [r['geo_entropy'] for r in results if r['true_label'] == label]
        if geo_values:
            mean_geo = sum(geo_values) / len(geo_values)
            min_geo = min(geo_values)
            max_geo = max(geo_values)
            print(f"  {label:>10}: mean={mean_geo:.2f}, min={min_geo:.2f}, max={max_geo:.2f}")

    # Threshold analysis
    print(f"\nThreshold Configuration:")
    print(f"  theta_low  = {THETA_LOW:.1f} bits (normal/elevated boundary)")
    print(f"  theta_high = {THETA_HIGH:.1f} bits (elevated/attack boundary)")
    print(f"  phi        = {PHI:.1f} bits (geographic entropy threshold)")

    # Zone distribution
    print(f"\nZone Classification Distribution:")
    for zone in ['normal', 'elevated', 'attack']:
        zone_count = sum(1 for r in results if r['zone'] == zone)
        zone_labels = Counter(r['true_label'] for r in results if r['zone'] == zone)
        label_str = ", ".join(f"{k}={v}" for k, v in sorted(zone_labels.items()))
        print(f"  {zone:>8} zone: {zone_count:3d} windows ({label_str})")

    # Validation against paper criteria
    print(f"\n{'=' * 60}")
    print("VALIDATION AGAINST PAPER CRITERIA (Section IX.E)")
    print(f"{'=' * 60}")
    print(f"  Precision >= 0.90: {'PASS' if metrics['precision'] >= 0.90 else 'FAIL'} "
          f"(actual: {metrics['precision']:.4f})")
    print(f"  Recall    >= 0.85: {'PASS' if metrics['recall'] >= 0.85 else 'FAIL'} "
          f"(actual: {metrics['recall']:.4f})")
    print(f"  FPR       <  0.05: {'PASS' if metrics['fpr'] < 0.05 else 'FAIL'} "
          f"(actual: {metrics['fpr']:.4f})")
    print(f"  F1        >= 0.87: {'PASS' if metrics['f1'] >= 0.87 else 'FAIL'} "
          f"(actual: {metrics['f1']:.4f})")


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    print("BIN-WATCH: Entropy-Based BIN Enumeration Detection Simulation")
    print(f"Paper: Adaptive DDoS Defense Strategies for High-TPS Payment Systems")
    print(f"Framework: Section IX.E -- BIN-WATCH Detection Model")
    print(f"Random seed: {RANDOM_SEED}")
    print(f"Total windows: {TOTAL_WINDOWS} "
          f"(normal={NUM_NORMAL_WINDOWS}, issuance={NUM_ISSUANCE_WINDOWS}, "
          f"attack={NUM_ATTACK_WINDOWS})")

    # Run simulation
    results = run_simulation()

    # Print detailed results table
    print_results_table(results)

    # Compute and print summary metrics
    metrics = compute_metrics(results)
    print_summary(metrics, results)
