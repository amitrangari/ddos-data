#!/usr/bin/env python3
"""
LBMD Meta-Analysis: Latency-Bounded ML Detection Framework
===========================================================

This script implements a meta-analysis computing Detection Efficiency Ratio
(DER) values from published benchmark data, as proposed in Section IX.F of
the paper "Adaptive DDoS Defense Strategies for High-Throughput Payment
Processing Systems."

The LBMD framework defines DER = F1 * max(0, 1 - t_inference / t_budget),
a joint metric capturing both detection accuracy (F1) and latency fitness
for payment processing deployment. This script:

1. Aggregates F1 and t_inference estimates from multiple published sources.
2. Computes confidence intervals using t-distribution statistics.
3. Computes DER for each algorithm x TPS tier combination.
4. Identifies deployment modes and the Pareto-optimal latency-accuracy frontier.

Dependencies: None required (math, statistics from stdlib)
Optional: scipy.stats for t-distribution CIs (falls back to z-approximation)
Usage: python3 lbmd-meta-analysis.py
"""

import math
from typing import Dict, List, Tuple, Optional


# =============================================================================
# Statistical Helper Functions
# =============================================================================

def mean(values: List[float]) -> float:
    """Compute arithmetic mean."""
    return sum(values) / len(values) if values else 0.0


def std_dev(values: List[float]) -> float:
    """Compute sample standard deviation."""
    if len(values) < 2:
        return 0.0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def confidence_interval_95(values: List[float]) -> Tuple[float, float]:
    """
    Compute 95% confidence interval for the mean.

    Uses t-distribution critical values for small samples (n < 30).
    Falls back to z = 1.96 for larger samples.

    Args:
        values: List of observed values.

    Returns:
        Tuple of (lower_bound, upper_bound) for the 95% CI.
    """
    n = len(values)
    if n < 2:
        m = mean(values)
        return (m, m)

    m = mean(values)
    se = std_dev(values) / math.sqrt(n)

    # t critical values for 95% CI (two-tailed)
    # Pre-computed for common df values
    t_critical = {
        1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
        6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
        15: 2.131, 20: 2.086, 25: 2.060, 30: 2.042,
    }

    df = n - 1
    # Find closest t value
    if df in t_critical:
        t_val = t_critical[df]
    elif df > 30:
        t_val = 1.96  # z-approximation
    else:
        # Interpolate between known values
        known_dfs = sorted(t_critical.keys())
        lower_df = max(d for d in known_dfs if d <= df)
        upper_df = min(d for d in known_dfs if d >= df)
        if lower_df == upper_df:
            t_val = t_critical[lower_df]
        else:
            frac = (df - lower_df) / (upper_df - lower_df)
            t_val = t_critical[lower_df] + frac * (t_critical[upper_df] - t_critical[lower_df])

    margin = t_val * se
    return (m - margin, m + margin)


# =============================================================================
# Benchmark Data from Published Papers
# =============================================================================

# F1 scores and inference times from published papers on CICDDoS2019
# and similar DDoS detection datasets. Reference numbers correspond to
# the paper's bibliography.
ALGORITHM_BENCHMARKS = {
    'cusum_statistical': {
        'display_name': 'CUSUM / Statistical',
        'f1_estimates': [0.76, 0.78, 0.81, 0.75],
        'f1_sources': ['[17]', '[5]', '[8]', '[7]'],
        't_inference_ms': [0.08, 0.10, 0.12],
        't_sources': ['Prometheus alert eval', 'kernel module', 'Python statsmodels'],
        'category': 'statistical',
    },
    'random_forest': {
        'display_name': 'Random Forest',
        'f1_estimates': [0.88, 0.91, 0.89, 0.92],
        'f1_sources': ['[14]', '[22]', '[13]', '[16]'],
        't_inference_ms': [0.6, 0.8, 1.1, 0.9],
        't_sources': ['scikit-learn RF', 'LightGBM', 'Weka RF', 'sklearn optimized'],
        'category': 'ensemble_ml',
    },
    'svm': {
        'display_name': 'SVM',
        'f1_estimates': [0.85, 0.87, 0.84],
        'f1_sources': ['[14]', '[13]', '[5]'],
        't_inference_ms': [1.8, 2.1, 2.5],
        't_sources': ['sklearn LinearSVC', 'libsvm', 'sklearn RBF'],
        'category': 'traditional_ml',
    },
    'lstm': {
        'display_name': 'LSTM',
        'f1_estimates': [0.93, 0.95, 0.92, 0.94],
        'f1_sources': ['[12]', '[7]', '[6]', '[14]'],
        't_inference_ms': [7.2, 8.5, 9.1, 8.0],
        't_sources': ['PyTorch LSTM', 'TensorFlow LSTM', 'Keras LSTM', 'ONNX LSTM'],
        'category': 'deep_learning',
    },
    'transformer': {
        'display_name': 'Transformer',
        'f1_estimates': [0.96, 0.98, 0.97],
        'f1_sources': ['[12]', '[7]', '[6]'],
        't_inference_ms': [42, 45, 51],
        't_sources': ['HuggingFace BERT-base', 'custom Transformer', 'DistilBERT'],
        'category': 'deep_learning',
    },
    'xgboost': {
        'display_name': 'XGBoost',
        'f1_estimates': [0.91, 0.93, 0.92, 0.94],
        'f1_sources': ['[16]', '[22]', '[14]', '[13]'],
        't_inference_ms': [0.9, 1.1, 1.3, 1.2],
        't_sources': ['XGBoost default', 'XGBoost tuned', 'LightGBM', 'CatBoost'],
        'category': 'ensemble_ml',
    },
    'p4_distilled_tree': {
        'display_name': 'P4-Distilled Tree',
        'f1_estimates': [0.82, 0.85, 0.83],
        'f1_sources': ['[7] (P4 compilation)', '[7] (Tofino)', '[9]'],
        't_inference_ms': [0.001, 0.001, 0.002],
        't_sources': ['Intel Tofino ASIC', 'P4 behavioral model', 'BMv2'],
        'category': 'hardware',
    },
    'ebpf_feature_check': {
        'display_name': 'eBPF/XDP Feature Check',
        'f1_estimates': [0.70, 0.72, 0.74],
        'f1_sources': ['[7]', '[9]', 'Cilium benchmark'],
        't_inference_ms': [0.001, 0.002, 0.002],
        't_sources': ['eBPF verifier-approved', 'XDP hook', 'TC hook'],
        'category': 'hardware',
    },
}


# =============================================================================
# TPS Tier Detection Budget Configuration
# =============================================================================

TPS_TIER_BUDGETS = {
    '50k+': {
        'display_name': '50K+ TPS',
        't_sla': 50,       # ms
        't_baseline': 28,  # ms
        'detection_budget': 5,  # ms (conservative: ~23% of remaining headroom)
        'description': 'Tier-1 processors (Visa/Mastercard scale)'
    },
    '10k-50k': {
        'display_name': '10K-50K TPS',
        't_sla': 75,
        't_baseline': 40,
        'detection_budget': 15,  # ms (~43% of remaining headroom)
        'description': 'Mid-tier processors and large acquirers'
    },
    '1k-10k': {
        'display_name': '1K-10K TPS',
        't_sla': 150,
        't_baseline': 60,
        'detection_budget': 40,  # ms (~44% of remaining headroom)
        'description': 'Smaller PSPs and regional processors'
    },
}


# =============================================================================
# DER Computation
# =============================================================================

def compute_der(f1: float, t_inference: float, t_budget: float) -> float:
    """
    Compute Detection Efficiency Ratio.

    DER = F1 * max(0, 1 - t_inference / t_budget)

    DER captures the joint fitness of a detection model for inline deployment
    in payment processing. It penalizes models whose inference time consumes
    a large fraction of the available detection budget.

    Args:
        f1: F-measure (harmonic mean of precision and recall), [0, 1].
        t_inference: Model inference time in milliseconds (P99).
        t_budget: Available detection latency budget in milliseconds.

    Returns:
        DER value in [0, F1]. Returns 0 if t_inference >= t_budget.
    """
    latency_penalty = max(0.0, 1.0 - t_inference / t_budget)
    return f1 * latency_penalty


def determine_deployment_mode(t_inference_mean: float, tiers: Dict) -> str:
    """
    Determine deployment mode based on inference latency.

    Deployment modes:
    - 'inline_hardware': t_inference < 0.01 ms (sub-10 microseconds)
    - 'inline_software': t_inference < smallest detection budget
    - 'inline_conditional': fits some tiers but not all
    - 'async_only': exceeds all detection budgets

    Args:
        t_inference_mean: Mean inference time in milliseconds.
        tiers: TPS tier budget dictionary.

    Returns:
        Deployment mode string.
    """
    if t_inference_mean < 0.01:
        return 'Inline Hardware'

    tier_budgets = sorted([t['detection_budget'] for t in tiers.values()])

    if t_inference_mean < tier_budgets[0]:
        return 'Inline Software (all tiers)'
    elif t_inference_mean < tier_budgets[1]:
        return 'Inline Software (10K-50K, 1K-10K)'
    elif t_inference_mean < tier_budgets[2]:
        return 'Inline Software (1K-10K only)'
    else:
        return 'Async Only'


def compute_all_ders() -> List[Dict]:
    """
    Compute DER for every algorithm x TPS tier combination.

    For each algorithm:
    1. Compute mean and 95% CI for F1 from multiple published estimates.
    2. Compute mean and 95% CI for t_inference from multiple benchmarks.
    3. Compute DER = F1_mean * max(0, 1 - t_inference_mean / t_budget).
    4. Compute DER uncertainty bounds using CI extremes.
    5. Determine deployment mode.

    Returns:
        List of result dictionaries, one per algorithm.
    """
    results = []

    for algo_key, algo_data in ALGORITHM_BENCHMARKS.items():
        f1_mean_val = mean(algo_data['f1_estimates'])
        f1_ci = confidence_interval_95(algo_data['f1_estimates'])
        f1_std = std_dev(algo_data['f1_estimates'])

        t_mean_val = mean(algo_data['t_inference_ms'])
        t_ci = confidence_interval_95(algo_data['t_inference_ms'])
        t_std = std_dev(algo_data['t_inference_ms'])

        deployment_mode = determine_deployment_mode(t_mean_val, TPS_TIER_BUDGETS)

        tier_ders = {}
        for tier_key, tier_data in TPS_TIER_BUDGETS.items():
            t_budget = tier_data['detection_budget']
            der_val = compute_der(f1_mean_val, t_mean_val, t_budget)

            # DER uncertainty: best case (high F1, low t) and worst case (low F1, high t)
            der_best = compute_der(f1_ci[1], t_ci[0], t_budget)
            der_worst = compute_der(f1_ci[0], t_ci[1], t_budget)

            tier_ders[tier_key] = {
                'der': der_val,
                'der_best': der_best,
                'der_worst': der_worst,
                'exceeds_budget': t_mean_val >= t_budget,
            }

        results.append({
            'key': algo_key,
            'display_name': algo_data['display_name'],
            'category': algo_data['category'],
            'f1_mean': f1_mean_val,
            'f1_ci': f1_ci,
            'f1_std': f1_std,
            'f1_n': len(algo_data['f1_estimates']),
            't_inference_mean': t_mean_val,
            't_inference_ci': t_ci,
            't_inference_std': t_std,
            't_inference_n': len(algo_data['t_inference_ms']),
            'deployment_mode': deployment_mode,
            'tier_ders': tier_ders,
            'f1_sources': algo_data['f1_sources'],
            't_sources': algo_data['t_sources'],
        })

    return results


def identify_pareto_frontier(results: List[Dict]) -> List[str]:
    """
    Identify algorithms on the Pareto-optimal frontier of (high DER, low t_inference).

    An algorithm is Pareto-optimal if no other algorithm has both higher DER
    and lower t_inference for at least one TPS tier.

    Args:
        results: List of algorithm result dictionaries.

    Returns:
        List of algorithm keys on the Pareto frontier.
    """
    frontier = []

    for algo in results:
        dominated = False
        for other in results:
            if other['key'] == algo['key']:
                continue

            # Check if other dominates algo in ALL tiers
            other_dominates_all = True
            for tier_key in TPS_TIER_BUDGETS:
                algo_der = algo['tier_ders'][tier_key]['der']
                other_der = other['tier_ders'][tier_key]['der']

                if not (other_der >= algo_der and other['t_inference_mean'] <= algo['t_inference_mean']):
                    if not (other_der > algo_der or other['t_inference_mean'] < algo['t_inference_mean']):
                        other_dominates_all = False
                        break
                    other_dominates_all = False
                    break

            if other_dominates_all:
                dominated = True
                break

        if not dominated:
            frontier.append(algo['key'])

    return frontier


# =============================================================================
# Output Formatting
# =============================================================================

def print_main_table(results: List[Dict]) -> None:
    """Print the main DER table formatted for paper inclusion."""
    print("\n" + "=" * 150)
    print("LATENCY-ACCURACY FRONTIER TABLE (LBMD Framework, Section IX.F.3)")
    print("=" * 150)

    # Header
    print(
        f"{'Algorithm':<22} | {'F1 mean':>8} {'(95% CI)':>14} | "
        f"{'t_inf mean':>10} {'(95% CI)':>14} | "
        f"{'DER @50K+':>9} | {'DER @10-50K':>11} | {'DER @1-10K':>10} | "
        f"{'Deployment Mode':<30}"
    )
    print("-" * 150)

    # Sort by DER at 50K+ tier (descending), then by t_inference (ascending)
    sorted_results = sorted(results,
                           key=lambda r: (-r['tier_ders']['50k+']['der'],
                                          r['t_inference_mean']))

    for r in sorted_results:
        f1_ci_str = f"[{r['f1_ci'][0]:.2f}, {r['f1_ci'][1]:.2f}]"
        t_ci_str = f"[{r['t_inference_ci'][0]:.3f}, {r['t_inference_ci'][1]:.3f}]"

        der_50k = r['tier_ders']['50k+']
        der_10_50k = r['tier_ders']['10k-50k']
        der_1_10k = r['tier_ders']['1k-10k']

        # Format DER with exceeds indicator
        def fmt_der(d):
            if d['exceeds_budget']:
                return f"  0 (exc.)"
            return f"  {d['der']:.3f}   "

        print(
            f"{r['display_name']:<22} | {r['f1_mean']:>8.3f} {f1_ci_str:>14} | "
            f"{r['t_inference_mean']:>9.3f}ms {t_ci_str:>14} | "
            f"{fmt_der(der_50k):>9} | {fmt_der(der_10_50k):>11} | {fmt_der(der_1_10k):>10} | "
            f"{r['deployment_mode']:<30}"
        )

    print("=" * 150)
    print("Note: DER = F1 * max(0, 1 - t_inference/t_budget). 'exc.' = t_inference exceeds t_budget (DER=0).")
    print(f"      t_budget: 50K+ = {TPS_TIER_BUDGETS['50k+']['detection_budget']}ms, "
          f"10K-50K = {TPS_TIER_BUDGETS['10k-50k']['detection_budget']}ms, "
          f"1K-10K = {TPS_TIER_BUDGETS['1k-10k']['detection_budget']}ms")


def print_detailed_analysis(results: List[Dict]) -> None:
    """Print detailed per-algorithm analysis with sources."""
    print("\n" + "=" * 90)
    print("DETAILED PER-ALGORITHM ANALYSIS")
    print("=" * 90)

    for r in results:
        print(f"\n  {r['display_name']} ({r['category']})")
        print(f"  {'-' * 60}")
        print(f"  F1 estimates (n={r['f1_n']}): {[f'{x:.2f}' for x in ALGORITHM_BENCHMARKS[r['key']]['f1_estimates']]}")
        print(f"    Sources: {', '.join(r['f1_sources'])}")
        print(f"    Mean: {r['f1_mean']:.3f}, Std: {r['f1_std']:.3f}, "
              f"95% CI: [{r['f1_ci'][0]:.3f}, {r['f1_ci'][1]:.3f}]")

        print(f"  t_inference estimates (n={r['t_inference_n']}): "
              f"{[f'{x:.3f}ms' for x in ALGORITHM_BENCHMARKS[r['key']]['t_inference_ms']]}")
        print(f"    Sources: {', '.join(r['t_sources'])}")
        print(f"    Mean: {r['t_inference_mean']:.3f}ms, Std: {r['t_inference_std']:.3f}ms, "
              f"95% CI: [{r['t_inference_ci'][0]:.3f}, {r['t_inference_ci'][1]:.3f}]ms")

        print(f"  DER by tier:")
        for tier_key, tier_data in TPS_TIER_BUDGETS.items():
            d = r['tier_ders'][tier_key]
            if d['exceeds_budget']:
                print(f"    {tier_data['display_name']:>12}: 0 (exceeds budget of {tier_data['detection_budget']}ms)")
            else:
                print(f"    {tier_data['display_name']:>12}: {d['der']:.3f} "
                      f"(range: [{d['der_worst']:.3f}, {d['der_best']:.3f}])")

        print(f"  Deployment: {r['deployment_mode']}")


def print_pareto_frontier(results: List[Dict], frontier: List[str]) -> None:
    """Print the Pareto-optimal frontier analysis."""
    print("\n" + "=" * 90)
    print("LATENCY-ACCURACY PARETO FRONTIER")
    print("=" * 90)

    print("\nAlgorithms on the Pareto frontier (not dominated in DER-vs-latency space):\n")

    frontier_results = [r for r in results if r['key'] in frontier]
    frontier_results.sort(key=lambda r: r['t_inference_mean'])

    for r in frontier_results:
        best_tier_der = max(r['tier_ders'][t]['der'] for t in TPS_TIER_BUDGETS)
        print(f"  * {r['display_name']:<22} | F1={r['f1_mean']:.3f} | "
              f"t_inf={r['t_inference_mean']:.3f}ms | "
              f"Best DER={best_tier_der:.3f} | {r['deployment_mode']}")

    print("\nFrontier interpretation:")
    print("  The frontier reveals a characteristic gap between hardware-accelerated")
    print("  approaches (F1=0.70-0.85, t_inference < 0.01ms) and deep learning")
    print("  approaches (F1=0.93-0.97, t_inference > 7ms). This gap represents the")
    print("  primary research challenge for high-TPS inline detection. Closing it")
    print("  requires advances in model compression, hardware inference accelerators,")
    print("  or novel architectures designed for low-latency inference.")

    print("\n  For 50K+ TPS deployments:")
    hw_algos = [r for r in frontier_results if r['t_inference_mean'] < 0.01]
    if hw_algos:
        best_hw = max(hw_algos, key=lambda r: r['tier_ders']['50k+']['der'])
        print(f"    Recommended: {best_hw['display_name']} "
              f"(DER={best_hw['tier_ders']['50k+']['der']:.3f})")

    print("\n  For 10K-50K TPS deployments:")
    sw_algos = [r for r in frontier_results
                if not r['tier_ders']['10k-50k']['exceeds_budget']]
    if sw_algos:
        best_sw = max(sw_algos, key=lambda r: r['tier_ders']['10k-50k']['der'])
        print(f"    Recommended: {best_sw['display_name']} "
              f"(DER={best_sw['tier_ders']['10k-50k']['der']:.3f})")

    print("\n  For 1K-10K TPS deployments:")
    all_algos = [r for r in frontier_results
                 if not r['tier_ders']['1k-10k']['exceeds_budget']]
    if all_algos:
        best_all = max(all_algos, key=lambda r: r['tier_ders']['1k-10k']['der'])
        print(f"    Recommended: {best_all['display_name']} "
              f"(DER={best_all['tier_ders']['1k-10k']['der']:.3f})")


def print_deployment_recommendations(results: List[Dict]) -> None:
    """Print deployment pathway recommendations."""
    print("\n" + "=" * 90)
    print("DEPLOYMENT PATHWAY RECOMMENDATIONS (Section IX.F.4)")
    print("=" * 90)

    print("\n  1. INLINE HARDWARE (P4/XDP) -- DER-maximized for 50K+ TPS:")
    hw = [r for r in results if 'Hardware' in r['deployment_mode']]
    for r in hw:
        print(f"     - {r['display_name']}: F1={r['f1_mean']:.3f}, "
              f"t_inf={r['t_inference_mean']:.3f}ms, "
              f"DER@50K+={r['tier_ders']['50k+']['der']:.3f}")

    print("\n  2. INLINE SOFTWARE (API Gateway Plugin) -- Best for 10K-50K TPS:")
    sw = [r for r in results
          if 'Inline Software' in r['deployment_mode'] and 'Hardware' not in r['deployment_mode']]
    for r in sorted(sw, key=lambda x: -x['tier_ders']['10k-50k']['der']):
        print(f"     - {r['display_name']}: F1={r['f1_mean']:.3f}, "
              f"t_inf={r['t_inference_mean']:.3f}ms, "
              f"DER@10-50K={r['tier_ders']['10k-50k']['der']:.3f}")

    print("\n  3. ASYNCHRONOUS (Parallel Analysis Stream) -- Highest raw F1:")
    async_algos = [r for r in results if 'Async' in r['deployment_mode']]
    for r in sorted(async_algos, key=lambda x: -x['f1_mean']):
        print(f"     - {r['display_name']}: F1={r['f1_mean']:.3f}, "
              f"t_inf={r['t_inference_mean']:.3f}ms "
              f"(detection latency 1-5s, not inline)")

    print("\n  RECOMMENDED COMBINED ARCHITECTURE:")
    print("     Inline P4/eBPF detection (fast, ~0.83 F1) + Async LSTM/Transformer")
    print("     (slower, ~0.96 F1) provides both immediate low-latency filtering")
    print("     and high-accuracy deep analysis within seconds.")


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    print("LBMD: Latency-Bounded ML Detection Framework -- Meta-Analysis")
    print(f"Paper: Adaptive DDoS Defense Strategies for High-TPS Payment Systems")
    print(f"Framework: Section IX.F -- Detection Efficiency Ratio (DER)")
    print(f"Algorithms analyzed: {len(ALGORITHM_BENCHMARKS)}")
    print(f"TPS tiers: {', '.join(t['display_name'] for t in TPS_TIER_BUDGETS.values())}")

    # Compute all DERs
    results = compute_all_ders()

    # Print main table
    print_main_table(results)

    # Print detailed analysis
    print_detailed_analysis(results)

    # Identify and print Pareto frontier
    frontier = identify_pareto_frontier(results)
    print_pareto_frontier(results, frontier)

    # Print deployment recommendations
    print_deployment_recommendations(results)

    # Validation summary
    print(f"\n{'=' * 90}")
    print("VALIDATION AGAINST PAPER TABLE (Section IX.F.3)")
    print(f"{'=' * 90}")

    print("\nComparison of computed DER values with paper's illustrative projections:")
    paper_ders = {
        'cusum_statistical': {'50k+': 0.8, '10k-50k': 0.8, '1k-10k': 0.8},
        'random_forest': {'50k+': 0.7, '10k-50k': 0.8, '1k-10k': 0.9},
        'svm': {'50k+': 0.5, '10k-50k': 0.7, '1k-10k': 0.8},
        'lstm': {'50k+': 0.0, '10k-50k': 0.4, '1k-10k': 0.7},
        'transformer': {'50k+': 0.0, '10k-50k': 0.0, '1k-10k': 0.2},
        'xgboost': {'50k+': 0.7, '10k-50k': 0.8, '1k-10k': 0.9},
        'p4_distilled_tree': {'50k+': 0.8, '10k-50k': 0.8, '1k-10k': 0.8},
        'ebpf_feature_check': {'50k+': 0.7, '10k-50k': 0.7, '1k-10k': 0.7},
    }

    print(f"\n  {'Algorithm':<22} | {'Tier':>8} | {'Paper DER':>9} | {'Computed DER':>12} | {'Delta':>7} | {'Match':>5}")
    print(f"  {'-'*22}-+-{'-'*8}-+-{'-'*9}-+-{'-'*12}-+-{'-'*7}-+-{'-'*5}")

    all_within_tolerance = True
    for algo_key in paper_ders:
        r = next(x for x in results if x['key'] == algo_key)
        for tier_key in ['50k+', '10k-50k', '1k-10k']:
            paper_val = paper_ders[algo_key][tier_key]
            computed_val = r['tier_ders'][tier_key]['der']
            delta = abs(computed_val - paper_val)
            within_tol = delta <= 0.15  # +/-15% tolerance
            if not within_tol:
                all_within_tolerance = False
            print(f"  {r['display_name']:<22} | {tier_key:>8} | {paper_val:>9.1f} | "
                  f"{computed_val:>12.3f} | {delta:>7.3f} | "
                  f"{'OK' if within_tol else 'DIFF':>5}")

    print(f"\n  All DER values within +/-15% of paper projections: "
          f"{'PASS' if all_within_tolerance else 'REVIEW NEEDED'}")
