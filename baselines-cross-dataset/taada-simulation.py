#!/usr/bin/env python3
"""
TAADA Simulation: Transaction-Aware Adaptive Defense Architecture
=================================================================

This script implements a computational simulation of the TAADA framework
proposed in Section VI.G of the paper "Adaptive DDoS Defense Strategies
for High-Throughput Payment Processing Systems."

TAADA formalizes latency-budget-constrained defense orchestration for
payment processing systems. This simulation:

1. Defines the defense mechanism catalog with realistic latency overheads.
2. Implements the Defense Budget Equation (Delta_budget).
3. Implements the Defense Selection Algorithm (DSA).
4. Runs all 24 experiment scenarios (T1-T24) from the experiment matrix.
5. Simulates three attack intensities per scenario.
6. Performs Monte Carlo analysis (100 runs per scenario with +/-20% variation).

Dependencies: numpy, scipy (for statistical functions)
Usage: python3 taada-simulation.py
"""

import math
import random
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

# Try numpy/scipy for statistical functions
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

RANDOM_SEED = 42


# =============================================================================
# Defense Mechanism Catalog
# =============================================================================

DEFENSE_CATALOG = {
    'syn_cookies': {
        'overhead_ms': 0.05,
        'priority': 1,
        'targets': ['syn_flood'],
        'tps_tiers': ['all'],
        'effectiveness': 0.70,  # Fraction of attack traffic mitigated
        'description': 'SYN cookie validation at kernel level'
    },
    'ebpf_xdp': {
        'overhead_ms': 0.10,
        'priority': 2,
        'targets': ['syn_flood', 'http2_rapid_reset', 'slowloris', 'bin_enumeration'],
        'tps_tiers': ['all'],
        'effectiveness': 0.85,
        'description': 'eBPF/XDP packet filtering at network driver level'
    },
    'p4_switch': {
        'overhead_ms': 0.001,
        'priority': 1,
        'targets': ['all'],
        'tps_tiers': ['50k+'],
        'hardware_required': True,
        'effectiveness': 0.95,
        'description': 'P4 programmable switch ASIC filtering'
    },
    'api_rate_limit': {
        'overhead_ms': 1.2,
        'priority': 3,
        'targets': ['bin_enumeration', 'http_flood', 'acs_exhaustion', 'http2_rapid_reset', 'slowloris'],
        'tps_tiers': ['all'],
        'effectiveness': 0.60,
        'description': 'Kong API gateway token bucket rate limiting'
    },
    'waf': {
        'overhead_ms': 3.1,
        'priority': 4,
        'targets': ['http_flood', 'http2_rapid_reset', 'slowloris', 'bin_enumeration'],
        'tps_tiers': ['1k-10k', '10k-50k'],
        'effectiveness': 0.75,
        'description': 'Web Application Firewall signature matching'
    },
    'tls_offload': {
        'overhead_ms': 0.8,
        'priority': 2,
        'targets': ['tls_exhaustion'],
        'tps_tiers': ['all'],
        'effectiveness': 0.90,
        'description': 'TLS termination at CDN/edge layer'
    },
    'scrubbing_center': {
        'overhead_ms': 8.5,
        'priority': 5,
        'targets': ['volumetric', 'syn_flood', 'dns_amplification'],
        'tps_tiers': ['1k-10k'],
        'effectiveness': 0.95,
        'description': 'Cloud scrubbing center (Akamai/Cloudflare)'
    },
    'circuit_breaker': {
        'overhead_ms': 0.3,
        'priority': 3,
        'targets': ['all'],
        'tps_tiers': ['all'],
        'effectiveness': 0.40,
        'description': 'Istio circuit breaker (consecutive 5xx threshold)'
    },
    'hpa_scaling': {
        'overhead_ms': 0.0,
        'priority': 6,
        'targets': ['all'],
        'tps_tiers': ['10k-50k', '50k+'],
        'effectiveness': 0.30,
        'description': 'Kubernetes Horizontal Pod Autoscaler'
    },
    'acs_guard': {
        'overhead_ms': 2.1,
        'priority': 2,
        'targets': ['acs_exhaustion'],
        'tps_tiers': ['all'],
        'effectiveness': 0.92,
        'description': 'ACS-GUARD session protection protocol'
    },
    'bin_watch': {
        'overhead_ms': 0.5,
        'priority': 2,
        'targets': ['bin_enumeration'],
        'tps_tiers': ['all'],
        'effectiveness': 0.88,
        'description': 'BIN-WATCH entropy-based enumeration detection'
    },
    'anycast_dns': {
        'overhead_ms': 0.0,
        'priority': 1,
        'targets': ['dns_amplification'],
        'tps_tiers': ['all'],
        'effectiveness': 0.80,
        'description': 'Anycast DNS distribution (absorbs amplification)'
    },
    'bgp_flowspec': {
        'overhead_ms': 0.0,
        'priority': 1,
        'targets': ['syn_flood', 'dns_amplification', 'volumetric'],
        'tps_tiers': ['all'],
        'effectiveness': 0.70,
        'description': 'BGP Flowspec filtering at network edge'
    },
    'connection_timeout': {
        'overhead_ms': 0.1,
        'priority': 2,
        'targets': ['slowloris'],
        'tps_tiers': ['all'],
        'effectiveness': 0.80,
        'description': 'Aggressive connection timeout enforcement'
    },
    'http2_stream_hardening': {
        'overhead_ms': 0.2,
        'priority': 2,
        'targets': ['http2_rapid_reset'],
        'tps_tiers': ['all'],
        'effectiveness': 0.75,
        'description': 'HTTP/2 stream limit and RST_STREAM rate control'
    },
}

# Attack type aliases (map scenario attack names to catalog target names)
ATTACK_TYPE_MAP = {
    'syn_flood': ['syn_flood'],
    'dns_amplification': ['dns_amplification'],
    'tls_exhaustion': ['tls_exhaustion'],
    'http2_rapid_reset': ['http2_rapid_reset'],
    'slowloris': ['slowloris'],
    'bin_enumeration': ['bin_enumeration'],
    'acs_exhaustion': ['acs_exhaustion'],
    'hybrid_multi_vector': ['syn_flood', 'http2_rapid_reset', 'bin_enumeration'],
}


# =============================================================================
# TPS Tier Configuration
# =============================================================================

TPS_TIER_CONFIG = {
    '1k-10k': {
        't_sla': 150.0,       # ms -- more relaxed SLA for smaller processors
        't_baseline': 60.0,   # ms -- higher baseline (less optimized stack)
    },
    '10k-50k': {
        't_sla': 75.0,        # ms
        't_baseline': 40.0,   # ms
    },
    '50k+': {
        't_sla': 50.0,        # ms -- strictest SLA for tier-1 processors
        't_baseline': 28.0,   # ms -- highly optimized baseline
    },
}


# =============================================================================
# Experiment Matrix (T1-T24)
# =============================================================================

EXPERIMENT_MATRIX = [
    # (scenario_id, attack_type, tps_tier, baseline_tps, defense_bundle_names, primary_metric)
    ('T1',  'syn_flood',          '1k-10k',  5000,  ['bgp_flowspec', 'syn_cookies'],                              'delta_budget_adherence'),
    ('T2',  'syn_flood',          '10k-50k', 25000, ['ebpf_xdp', 'syn_cookies'],                                  'tps_degradation'),
    ('T3',  'syn_flood',          '50k+',    60000, ['p4_switch', 'ebpf_xdp'],                                     'detection_latency'),
    ('T4',  'dns_amplification',  '1k-10k',  5000,  ['anycast_dns', 'scrubbing_center'],                          'collateral_drop_rate'),
    ('T5',  'dns_amplification',  '10k-50k', 25000, ['anycast_dns', 'bgp_flowspec'],                              'tps_maintained'),
    ('T6',  'dns_amplification',  '50k+',    60000, ['anycast_dns', 'p4_switch', 'ebpf_xdp'],                     'delta_budget_adherence'),
    ('T7',  'tls_exhaustion',     '1k-10k',  5000,  ['tls_offload', 'api_rate_limit'],                            'handshake_rate'),
    ('T8',  'tls_exhaustion',     '10k-50k', 25000, ['tls_offload', 'waf'],                                       'p99_latency'),
    ('T9',  'tls_exhaustion',     '50k+',    60000, ['tls_offload', 'ebpf_xdp'],                                  'delta_budget'),
    ('T10', 'http2_rapid_reset',  '1k-10k',  5000,  ['http2_stream_hardening', 'api_rate_limit'],                 'fpr'),
    ('T11', 'http2_rapid_reset',  '10k-50k', 25000, ['ebpf_xdp', 'waf'],                                         'stream_cancellation_rate'),
    ('T12', 'http2_rapid_reset',  '50k+',    60000, ['ebpf_xdp', 'p4_switch'],                                    'delta_budget'),
    ('T13', 'slowloris',          '1k-10k',  5000,  ['connection_timeout', 'api_rate_limit'],                     'connection_exhaustion'),
    ('T14', 'slowloris',          '10k-50k', 25000, ['api_rate_limit', 'ebpf_xdp'],                               'tps_maintained'),
    ('T15', 'slowloris',          '50k+',    60000, ['ebpf_xdp', 'circuit_breaker'],                              'p99_latency'),
    ('T16', 'bin_enumeration',    '1k-10k',  5000,  ['bin_watch', 'api_rate_limit'],                              'precision_recall'),
    ('T17', 'bin_enumeration',    '10k-50k', 25000, ['bin_watch', 'ebpf_xdp'],                                    'detection_latency'),
    ('T18', 'bin_enumeration',    '50k+',    60000, ['bin_watch', 'p4_switch'],                                    'fpr'),
    ('T19', 'acs_exhaustion',     '1k-10k',  5000,  ['acs_guard', 'api_rate_limit', 'circuit_breaker'],           'session_utilization'),
    ('T20', 'acs_exhaustion',     '10k-50k', 25000, ['acs_guard'],                                                't_exhaust'),
    ('T21', 'acs_exhaustion',     '50k+',    60000, ['acs_guard', 'scrubbing_center'],                            'recovery_time'),
    ('T22', 'hybrid_multi_vector','1k-10k',  5000,  None,  # DSA selects automatically
                                                                                                                   'end_to_end_delta_budget'),
    ('T23', 'hybrid_multi_vector','10k-50k', 25000, None,                                                         'tps_degradation'),
    ('T24', 'hybrid_multi_vector','50k+',    60000, None,                                                         'overall_defense_budget'),
]


# =============================================================================
# Core TAADA Functions
# =============================================================================

def compute_delta_budget(t_sla_ms: float, t_baseline_ms: float,
                         deployed_defenses: List[str],
                         overhead_overrides: Optional[Dict[str, float]] = None) -> float:
    """
    Compute the remaining latency budget after applying defense mechanisms.

    Delta_budget = T_SLA - T_baseline - SUM(delta_i * w_i)

    Where delta_i is the latency overhead of defense i and w_i = 1 for all
    deployed defenses (inline mechanisms only; async mechanisms have w_i = 0).

    Args:
        t_sla_ms: Authorization latency SLA in milliseconds.
        t_baseline_ms: Baseline processing time in milliseconds.
        deployed_defenses: List of defense mechanism names from the catalog.
        overhead_overrides: Optional dict of {defense_name: overhead_ms} to
                          override catalog values (used in Monte Carlo).

    Returns:
        Delta_budget in milliseconds. Positive = headroom remaining.
        Negative = SLA violated.
    """
    total_overhead = 0.0
    for defense_name in deployed_defenses:
        if defense_name not in DEFENSE_CATALOG:
            continue
        if overhead_overrides and defense_name in overhead_overrides:
            overhead = overhead_overrides[defense_name]
        else:
            overhead = DEFENSE_CATALOG[defense_name]['overhead_ms']
        total_overhead += overhead

    return t_sla_ms - t_baseline_ms - total_overhead


def is_compatible(defense_name: str, attack_type: str, tps_tier: str) -> bool:
    """
    Check if a defense mechanism is compatible with the given attack type
    and TPS tier.

    Compatibility rules:
    - Defense must target the specific attack type (or 'all').
    - Defense must be available at the TPS tier (or 'all').

    Args:
        defense_name: Name of the defense mechanism.
        attack_type: Attack type being defended against.
        tps_tier: Current TPS operating tier.

    Returns:
        True if compatible, False otherwise.
    """
    defense = DEFENSE_CATALOG[defense_name]

    # Check attack type compatibility
    attack_targets = ATTACK_TYPE_MAP.get(attack_type, [attack_type])
    targets_match = ('all' in defense['targets'] or
                     any(t in defense['targets'] for t in attack_targets))

    # Check TPS tier compatibility
    tier_match = ('all' in defense['tps_tiers'] or tps_tier in defense['tps_tiers'])

    return targets_match and tier_match


def dsa(attack_type: str, tps_tier: str, delta_budget: float,
        overhead_overrides: Optional[Dict[str, float]] = None) -> List[str]:
    """
    Defense Selection Algorithm (DSA).

    Greedy algorithm that selects the highest-priority compatible defense
    mechanisms fitting within the available latency budget.

    From paper Section VI.G.4:
      candidates = lookup(DefenseCombinationMatrix, attack_type, tps_tier)
      candidates sorted by priority (lower number = higher priority)
      for each candidate: if overhead <= remaining budget, add to bundle.

    Args:
        attack_type: Classified attack type from TAADA Layer 1.
        tps_tier: Current TPS operating tier.
        delta_budget: Available latency headroom from TAADA Layer 2.
        overhead_overrides: Optional overhead overrides for Monte Carlo.

    Returns:
        Ordered list of selected defense mechanism names.
    """
    # Build candidate list: all defenses compatible with attack + tier
    candidates = []
    for name, defense in DEFENSE_CATALOG.items():
        if is_compatible(name, attack_type, tps_tier):
            overhead = (overhead_overrides.get(name, defense['overhead_ms'])
                        if overhead_overrides else defense['overhead_ms'])
            candidates.append((name, defense['priority'], overhead))

    # Sort by priority (ascending: lower number = higher priority)
    candidates.sort(key=lambda x: (x[1], x[2]))

    # Greedy selection
    bundle = []
    remaining = delta_budget
    for name, priority, overhead in candidates:
        if overhead <= remaining:
            bundle.append(name)
            remaining -= overhead

    return bundle


def simulate_tps_degradation(baseline_tps: int, attack_multiplier: float,
                             deployed_defenses: List[str],
                             attack_type: str) -> float:
    """
    Simulate TPS degradation under attack with defenses active.

    Model: Each defense blocks a fraction of attack traffic (its effectiveness).
    Combined effectiveness is computed as 1 - product(1 - eff_i) for defenses
    targeting the attack type. Residual attack traffic causes TPS degradation
    proportional to the residual attack intensity.

    Args:
        baseline_tps: Normal legitimate TPS.
        attack_multiplier: Attack traffic as a multiple of legitimate traffic.
        deployed_defenses: List of active defense mechanisms.
        attack_type: The attack being simulated.

    Returns:
        Effective TPS maintained during attack (as fraction of baseline).
    """
    # Compute combined defense effectiveness
    residual_factor = 1.0
    for name in deployed_defenses:
        defense = DEFENSE_CATALOG.get(name)
        if defense:
            attack_targets = ATTACK_TYPE_MAP.get(attack_type, [attack_type])
            if 'all' in defense['targets'] or any(t in defense['targets'] for t in attack_targets):
                residual_factor *= (1.0 - defense['effectiveness'])

    # Residual attack traffic that gets through all defenses
    residual_attack = attack_multiplier * residual_factor

    # TPS degradation model: legitimate TPS drops proportionally to
    # residual attack load on the system
    # Simple model: TPS_maintained = baseline / (1 + residual_attack * saturation_factor)
    saturation_factor = 0.01  # How much each unit of residual attack degrades TPS
    tps_fraction = 1.0 / (1.0 + residual_attack * saturation_factor)

    return tps_fraction


# =============================================================================
# Scenario Execution
# =============================================================================

def run_scenario(scenario_id: str, attack_type: str, tps_tier: str,
                 baseline_tps: int, specified_bundle: Optional[List[str]],
                 attack_multiplier: float,
                 overhead_overrides: Optional[Dict[str, float]] = None) -> Dict:
    """
    Execute a single experiment scenario.

    Args:
        scenario_id: Scenario identifier (T1-T24).
        attack_type: Attack type name.
        tps_tier: TPS tier ('1k-10k', '10k-50k', '50k+').
        baseline_tps: Legitimate TPS baseline.
        specified_bundle: Pre-specified defense bundle, or None for DSA auto-selection.
        attack_multiplier: Attack intensity as multiple of legitimate traffic.
        overhead_overrides: Optional overhead values for Monte Carlo.

    Returns:
        Dictionary with scenario results.
    """
    tier_config = TPS_TIER_CONFIG[tps_tier]
    t_sla = tier_config['t_sla']
    t_baseline = tier_config['t_baseline']

    # Compute initial delta_budget (no defenses active)
    initial_budget = t_sla - t_baseline

    # Select defense bundle
    if specified_bundle is not None:
        defense_bundle = specified_bundle
    else:
        # DSA auto-selection (for hybrid scenarios T22-T24)
        defense_bundle = dsa(attack_type, tps_tier, initial_budget, overhead_overrides)

    # Compute delta_budget with defenses active
    delta_budget_after = compute_delta_budget(t_sla, t_baseline, defense_bundle,
                                              overhead_overrides)

    # Compute total defense overhead
    total_overhead = 0.0
    for name in defense_bundle:
        if overhead_overrides and name in overhead_overrides:
            total_overhead += overhead_overrides[name]
        elif name in DEFENSE_CATALOG:
            total_overhead += DEFENSE_CATALOG[name]['overhead_ms']

    # Simulate TPS degradation
    tps_fraction = simulate_tps_degradation(baseline_tps, attack_multiplier,
                                             defense_bundle, attack_type)

    # Determine SLA compliance
    sla_maintained = delta_budget_after > 0

    return {
        'scenario_id': scenario_id,
        'attack_type': attack_type,
        'tps_tier': tps_tier,
        'baseline_tps': baseline_tps,
        'attack_multiplier': attack_multiplier,
        'defense_bundle': defense_bundle,
        'total_overhead_ms': total_overhead,
        'initial_budget_ms': initial_budget,
        'delta_budget_after_ms': delta_budget_after,
        'tps_maintained_pct': tps_fraction * 100,
        'sla_maintained': sla_maintained,
    }


def run_all_scenarios() -> List[Dict]:
    """Run all 24 scenarios at all 3 attack intensities."""
    intensities = [
        ('Light (10x)', 10.0),
        ('Moderate (50x)', 50.0),
        ('Heavy (200x)', 200.0),
    ]

    all_results = []
    for scenario in EXPERIMENT_MATRIX:
        scenario_id, attack_type, tps_tier, baseline_tps, bundle, primary_metric = scenario
        for intensity_name, multiplier in intensities:
            result = run_scenario(
                scenario_id, attack_type, tps_tier, baseline_tps,
                bundle, multiplier
            )
            result['intensity'] = intensity_name
            result['primary_metric'] = primary_metric
            all_results.append(result)

    return all_results


def run_monte_carlo(num_iterations: int = 100, variation_pct: float = 0.20) -> Dict:
    """
    Run Monte Carlo simulation for all 24 scenarios.

    For each iteration, defense mechanism overheads are perturbed by
    +/- variation_pct (uniform distribution) to simulate real-world
    variability in defense mechanism latency.

    Args:
        num_iterations: Number of Monte Carlo repetitions per scenario.
        variation_pct: Maximum fractional perturbation (+/- this fraction).

    Returns:
        Dictionary mapping scenario_id to Monte Carlo statistics.
    """
    rng = random.Random(RANDOM_SEED)
    mc_results = {}

    intensities = [
        ('Light (10x)', 10.0),
        ('Moderate (50x)', 50.0),
        ('Heavy (200x)', 200.0),
    ]

    for scenario in EXPERIMENT_MATRIX:
        scenario_id, attack_type, tps_tier, baseline_tps, bundle, primary_metric = scenario

        for intensity_name, multiplier in intensities:
            key = f"{scenario_id}_{intensity_name}"
            delta_budgets = []
            tps_fractions = []
            sla_compliance_count = 0

            for _ in range(num_iterations):
                # Generate random overhead overrides
                overrides = {}
                for name, defense in DEFENSE_CATALOG.items():
                    perturbation = 1.0 + rng.uniform(-variation_pct, variation_pct)
                    overrides[name] = defense['overhead_ms'] * perturbation

                result = run_scenario(
                    scenario_id, attack_type, tps_tier, baseline_tps,
                    bundle, multiplier, overhead_overrides=overrides
                )
                delta_budgets.append(result['delta_budget_after_ms'])
                tps_fractions.append(result['tps_maintained_pct'])
                if result['sla_maintained']:
                    sla_compliance_count += 1

            mean_db = sum(delta_budgets) / len(delta_budgets)
            std_db = (sum((x - mean_db) ** 2 for x in delta_budgets) / len(delta_budgets)) ** 0.5
            mean_tps = sum(tps_fractions) / len(tps_fractions)
            std_tps = (sum((x - mean_tps) ** 2 for x in tps_fractions) / len(tps_fractions)) ** 0.5

            mc_results[key] = {
                'scenario_id': scenario_id,
                'intensity': intensity_name,
                'mean_delta_budget': mean_db,
                'std_delta_budget': std_db,
                'min_delta_budget': min(delta_budgets),
                'max_delta_budget': max(delta_budgets),
                'mean_tps_maintained': mean_tps,
                'std_tps_maintained': std_tps,
                'sla_compliance_rate': sla_compliance_count / num_iterations,
                'num_iterations': num_iterations,
            }

    return mc_results


# =============================================================================
# Output Formatting
# =============================================================================

def print_scenario_results(results: List[Dict]) -> None:
    """Print formatted results table for all scenarios."""
    print("\n" + "=" * 140)
    print("TAADA EXPERIMENT MATRIX RESULTS")
    print("=" * 140)

    header = (
        f"{'Scen':>4} | {'Attack Type':>20} | {'Tier':>7} | {'Intensity':>14} | "
        f"{'Defense Bundle':>45} | {'Ovrhd':>6} | {'Budget':>7} | {'TPS%':>6} | {'SLA':>4}"
    )
    print(header)
    print("-" * 140)

    current_scenario = None
    for r in results:
        if r['scenario_id'] != current_scenario:
            if current_scenario is not None:
                print("-" * 140)
            current_scenario = r['scenario_id']

        bundle_str = ", ".join(r['defense_bundle'][:4])
        if len(r['defense_bundle']) > 4:
            bundle_str += f" +{len(r['defense_bundle'])-4} more"

        sla_str = "OK" if r['sla_maintained'] else "FAIL"
        print(
            f"{r['scenario_id']:>4} | {r['attack_type']:>20} | {r['tps_tier']:>7} | "
            f"{r['intensity']:>14} | {bundle_str:>45} | "
            f"{r['total_overhead_ms']:6.2f} | {r['delta_budget_after_ms']:7.2f} | "
            f"{r['tps_maintained_pct']:5.1f}% | {sla_str:>4}"
        )

    print("=" * 140)


def print_summary_statistics(results: List[Dict]) -> None:
    """Print aggregate summary statistics."""
    print("\n" + "=" * 70)
    print("SUMMARY STATISTICS")
    print("=" * 70)

    total = len(results)
    sla_pass = sum(1 for r in results if r['sla_maintained'])
    sla_fail = total - sla_pass

    print(f"\nTotal scenario-intensity combinations: {total}")
    print(f"SLA maintained: {sla_pass} ({sla_pass/total*100:.1f}%)")
    print(f"SLA violated:   {sla_fail} ({sla_fail/total*100:.1f}%)")

    # Per-tier statistics
    print(f"\nPer-Tier SLA Compliance:")
    for tier in ['1k-10k', '10k-50k', '50k+']:
        tier_results = [r for r in results if r['tps_tier'] == tier]
        tier_pass = sum(1 for r in tier_results if r['sla_maintained'])
        print(f"  {tier:>7}: {tier_pass}/{len(tier_results)} "
              f"({tier_pass/len(tier_results)*100:.1f}%)")

    # Per-intensity statistics
    print(f"\nPer-Intensity SLA Compliance:")
    for intensity in ['Light (10x)', 'Moderate (50x)', 'Heavy (200x)']:
        int_results = [r for r in results if r['intensity'] == intensity]
        int_pass = sum(1 for r in int_results if r['sla_maintained'])
        int_tps = [r['tps_maintained_pct'] for r in int_results]
        mean_tps = sum(int_tps) / len(int_tps)
        print(f"  {intensity:>14}: SLA {int_pass}/{len(int_results)} "
              f"({int_pass/len(int_results)*100:.1f}%), "
              f"mean TPS maintained {mean_tps:.1f}%")

    # Per-attack-type statistics
    print(f"\nPer-Attack-Type SLA Compliance:")
    attack_types = sorted(set(r['attack_type'] for r in results))
    for attack in attack_types:
        atk_results = [r for r in results if r['attack_type'] == attack]
        atk_pass = sum(1 for r in atk_results if r['sla_maintained'])
        atk_budgets = [r['delta_budget_after_ms'] for r in atk_results]
        mean_budget = sum(atk_budgets) / len(atk_budgets)
        print(f"  {attack:>20}: SLA {atk_pass}/{len(atk_results)} "
              f"({atk_pass/len(atk_results)*100:.1f}%), "
              f"mean Delta_budget = {mean_budget:.2f} ms")


def print_monte_carlo_results(mc_results: Dict) -> None:
    """Print Monte Carlo simulation results."""
    print("\n" + "=" * 120)
    print(f"MONTE CARLO SENSITIVITY ANALYSIS (100 iterations, +/-20% overhead variation)")
    print("=" * 120)

    header = (
        f"{'Key':>25} | {'Mean DB':>8} | {'Std DB':>7} | {'Min DB':>7} | "
        f"{'Max DB':>7} | {'Mean TPS%':>9} | {'SLA Rate':>8}"
    )
    print(header)
    print("-" * 120)

    # Group by scenario for readability
    scenarios = sorted(set(v['scenario_id'] for v in mc_results.values()))
    for scenario in scenarios:
        scenario_entries = {k: v for k, v in mc_results.items()
                          if v['scenario_id'] == scenario}
        for key in sorted(scenario_entries.keys()):
            mc = scenario_entries[key]
            print(
                f"{key:>25} | {mc['mean_delta_budget']:8.2f} | "
                f"{mc['std_delta_budget']:7.2f} | {mc['min_delta_budget']:7.2f} | "
                f"{mc['max_delta_budget']:7.2f} | {mc['mean_tps_maintained']:8.1f}% | "
                f"{mc['sla_compliance_rate']:7.1%}"
            )

    # Overall Monte Carlo summary
    all_compliance = [v['sla_compliance_rate'] for v in mc_results.values()]
    mean_compliance = sum(all_compliance) / len(all_compliance)
    min_compliance = min(all_compliance)

    print("-" * 120)
    print(f"\nOverall Monte Carlo SLA Compliance:")
    print(f"  Mean compliance rate across all scenarios: {mean_compliance:.1%}")
    print(f"  Minimum compliance rate (worst scenario):  {min_compliance:.1%}")

    # Identify scenarios with <90% compliance
    low_compliance = [(k, v) for k, v in mc_results.items()
                      if v['sla_compliance_rate'] < 0.90]
    if low_compliance:
        print(f"\n  Scenarios with <90% SLA compliance under variation:")
        for key, mc in sorted(low_compliance, key=lambda x: x[1]['sla_compliance_rate']):
            print(f"    {key}: {mc['sla_compliance_rate']:.1%} "
                  f"(mean Delta_budget = {mc['mean_delta_budget']:.2f} ms)")
    else:
        print(f"\n  All scenarios maintain >90% SLA compliance under +/-20% variation.")


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    print("TAADA: Transaction-Aware Adaptive Defense Architecture Simulation")
    print(f"Paper: Adaptive DDoS Defense Strategies for High-TPS Payment Systems")
    print(f"Framework: Section VI.G -- TAADA Defense Orchestration")
    print(f"Random seed: {RANDOM_SEED}")
    print(f"Defense mechanisms in catalog: {len(DEFENSE_CATALOG)}")
    print(f"Experiment scenarios: {len(EXPERIMENT_MATRIX)}")

    # Print defense catalog
    print(f"\n{'=' * 90}")
    print("DEFENSE MECHANISM CATALOG")
    print(f"{'=' * 90}")
    print(f"{'Name':>25} | {'Overhead':>8} | {'Priority':>8} | {'Effect.':>7} | {'Description'}")
    print("-" * 90)
    for name, d in sorted(DEFENSE_CATALOG.items(), key=lambda x: x[1]['priority']):
        print(f"{name:>25} | {d['overhead_ms']:7.3f}ms | {d['priority']:>8} | "
              f"{d['effectiveness']:6.0%} | {d['description']}")

    # Run all scenarios
    print("\nRunning 24 scenarios x 3 intensities = 72 experiments...")
    results = run_all_scenarios()
    print_scenario_results(results)
    print_summary_statistics(results)

    # Run Monte Carlo
    print("\nRunning Monte Carlo simulation (100 iterations per scenario)...")
    mc_results = run_monte_carlo(num_iterations=100, variation_pct=0.20)
    print_monte_carlo_results(mc_results)

    # Validation summary
    total_scenarios = len(results)
    sla_pass = sum(1 for r in results if r['sla_maintained'])
    print(f"\n{'=' * 70}")
    print("VALIDATION AGAINST PAPER CRITERIA (Section VI.G)")
    print(f"{'=' * 70}")
    print(f"  Delta_budget > 0 in >= 95% of scenarios: "
          f"{'PASS' if sla_pass / total_scenarios >= 0.95 else 'FAIL'} "
          f"(actual: {sla_pass/total_scenarios*100:.1f}%)")
    print(f"  DSA selects non-empty bundle for all scenarios: "
          f"{'PASS' if all(len(r['defense_bundle']) > 0 for r in results) else 'FAIL'}")

    all_mc_compliance = [v['sla_compliance_rate'] for v in mc_results.values()]
    mean_mc = sum(all_mc_compliance) / len(all_mc_compliance)
    print(f"  Monte Carlo mean SLA compliance >= 90%: "
          f"{'PASS' if mean_mc >= 0.90 else 'FAIL'} (actual: {mean_mc:.1%})")
