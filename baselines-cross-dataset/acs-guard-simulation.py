#!/usr/bin/env python3
"""
ACS-GUARD Simulation: 3-D Secure Access Control Server Defense Protocol
========================================================================

This script implements a computational simulation of the ACS-GUARD protocol
proposed in Section VII.E of the paper "Adaptive DDoS Defense Strategies
for High-Throughput Payment Processing Systems."

ACS-GUARD defends 3-D Secure Access Control Servers against three attack
modes: Challenge Exhaustion Attack (CEA), Frictionless Flood Attack (FFA),
and Protocol Timing Abuse (PTA). The protocol defines three defense
mechanisms: session pre-pooling with hard cap, frictionless rate budgeting,
and adaptive session TTL.

This simulation models ACS session dynamics at 1-second timesteps over
600 seconds, comparing system behavior with and without ACS-GUARD active
for each attack mode.

Dependencies: None (standard library only)
Usage: python3 acs-guard-simulation.py
"""

import math
from typing import Dict, List, Tuple


# =============================================================================
# ACS Configuration
# =============================================================================

ACS_CONFIG = {
    'session_pool_size': 100_000,     # Total available sessions (M_session_pool)
    'alpha': 0.85,                    # Safety margin (paper recommends 0.85)
    'normal_tau': 300,                # Normal session timeout (seconds)
    'tau_min': 30,                    # Minimum session timeout floor (seconds)
    'u_threshold': 0.65,             # Utilization threshold for TTL compression
    'frictionless_budget_per_min': 10_000,  # Normal frictionless requests/minute
    'legitimate_request_rate': 500,   # Normal legitimate AReq/second
    'frictionless_legitimate_rate': 200,  # Normal legitimate frictionless/second
}

# Derived constants
M_CAP = int(ACS_CONFIG['session_pool_size'] * ACS_CONFIG['alpha'])

SIMULATION_DURATION = 600  # seconds


# =============================================================================
# Attack Mode Definitions
# =============================================================================

def cea_attack_rate(t: int) -> int:
    """
    Challenge Exhaustion Attack (CEA) rate profile.

    Linear ramp from 0 to 2000 AReq/sec over 60 seconds, then sustained.
    Each AReq triggers a challenge flow; attacker never sends RReq,
    leaving sessions abandoned until timeout.

    Args:
        t: Time in seconds from simulation start.

    Returns:
        Attack AReq rate at time t (sessions/second).
    """
    attack_start = 60  # Attack begins at t=60
    ramp_duration = 60  # 60-second ramp
    max_rate = 2000

    if t < attack_start:
        return 0
    elif t < attack_start + ramp_duration:
        progress = (t - attack_start) / ramp_duration
        return int(max_rate * progress)
    elif t < 420:  # Attack sustained until t=420 (6 minutes of attack)
        return max_rate
    else:
        return 0  # Attack stops, recovery period


def ffa_attack_rate(t: int) -> int:
    """
    Frictionless Flood Attack (FFA) rate profile.

    Ramp from 0 to 5000 frictionless req/sec over 30 seconds, then sustained.
    Frictionless requests do not consume session pool directly but exhaust
    frictionless processing capacity.

    Args:
        t: Time in seconds.

    Returns:
        Attack frictionless request rate at time t.
    """
    attack_start = 60
    ramp_duration = 30
    max_rate = 5000

    if t < attack_start:
        return 0
    elif t < attack_start + ramp_duration:
        progress = (t - attack_start) / ramp_duration
        return int(max_rate * progress)
    elif t < 420:
        return max_rate
    else:
        return 0


def pta_attack_rate(t: int) -> int:
    """
    Protocol Timing Abuse (PTA) rate profile.

    Sustained moderate rate (300 AReq/sec) designed to maximize session
    lifetime. Attacker responds to CReq just before timeout, keeping
    sessions active for maximum duration.

    Args:
        t: Time in seconds.

    Returns:
        Attack AReq rate at time t.
    """
    attack_start = 60

    if t < attack_start:
        return 0
    elif t < 420:
        return 300
    else:
        return 0


# =============================================================================
# ACS Session Dynamics
# =============================================================================

def compute_adaptive_tau(utilization: float, config: Dict) -> float:
    """
    Compute adaptive session TTL under ACS-GUARD.

    tau' = max(tau_min, tau * (1 - rho))

    Where rho = max(0, (utilization - U_threshold) / (1 - U_threshold))

    This progressively reduces session timeout as utilization increases
    beyond the threshold, reclaiming abandoned sessions faster.

    Args:
        utilization: Current session pool utilization (0.0 to 1.0).
        config: ACS configuration dictionary.

    Returns:
        Adaptive session timeout in seconds.
    """
    u_threshold = config['u_threshold']
    tau = config['normal_tau']
    tau_min = config['tau_min']

    if utilization <= u_threshold:
        rho = 0.0
    else:
        rho = min(1.0, (utilization - u_threshold) / (1.0 - u_threshold))

    tau_prime = max(tau_min, tau * (1.0 - rho))
    return tau_prime


def simulate_without_guard(attack_mode: str) -> Dict:
    """
    Simulate ACS session dynamics WITHOUT ACS-GUARD.

    Without ACS-GUARD:
    - No session cap (all M_session_pool sessions available)
    - Fixed session timeout (tau = 300 seconds)
    - No frictionless budgeting
    - Sessions accumulate until pool is exhausted

    Args:
        attack_mode: One of 'CEA', 'FFA', 'PTA'.

    Returns:
        Dictionary with time-series data and summary metrics.
    """
    config = ACS_CONFIG
    pool_size = config['session_pool_size']
    tau = config['normal_tau']
    legit_rate = config['legitimate_request_rate']

    # Select attack rate function
    attack_fn = {'CEA': cea_attack_rate, 'FFA': ffa_attack_rate, 'PTA': pta_attack_rate}[attack_mode]

    # Session tracking: list of (creation_time, is_legitimate)
    # For efficiency, we track sessions as a queue with expiry times
    active_sessions = []  # list of expiry_time values
    time_series = []

    exhaustion_time = None
    legit_accepted = 0
    legit_rejected = 0

    for t in range(SIMULATION_DURATION):
        # Remove expired sessions
        active_sessions = [exp for exp in active_sessions if exp > t]

        current_active = len(active_sessions)
        utilization = current_active / pool_size

        # Determine attack rate
        if attack_mode == 'FFA':
            # FFA attacks frictionless path, not session pool directly
            # But without budgeting, excess frictionless requests still
            # create some session overhead (simplified model)
            attack_rate = attack_fn(t) // 5  # 1 in 5 frictionless creates session overhead
        else:
            attack_rate = attack_fn(t)

        # PTA: sessions last the full tau (attacker keeps them alive)
        if attack_mode == 'PTA':
            session_duration = tau  # Max lifetime
        else:
            session_duration = tau  # Normal timeout for abandoned sessions

        # Process legitimate requests
        legit_this_step = legit_rate
        for _ in range(legit_this_step):
            if current_active < pool_size:
                active_sessions.append(t + session_duration)
                current_active += 1
                legit_accepted += 1
            else:
                legit_rejected += 1

        # Process attack requests
        for _ in range(attack_rate):
            if current_active < pool_size:
                active_sessions.append(t + session_duration)
                current_active += 1

        # Check exhaustion
        if current_active >= pool_size and exhaustion_time is None:
            exhaustion_time = t

        time_series.append({
            'time': t,
            'active_sessions': min(current_active, pool_size),
            'utilization': min(current_active / pool_size, 1.0),
            'tau': tau,
            'attack_rate': attack_rate,
            'legit_accepted_this_step': min(legit_this_step, max(0, pool_size - current_active + legit_this_step)),
        })

    total_legit = legit_accepted + legit_rejected
    acceptance_rate = legit_accepted / total_legit if total_legit > 0 else 1.0

    # Recovery time: time from attack end (t=420) to utilization < 0.1
    recovery_time = None
    for entry in time_series:
        if entry['time'] > 420 and entry['utilization'] < 0.10:
            recovery_time = entry['time'] - 420
            break

    return {
        'time_series': time_series,
        'exhaustion_time': exhaustion_time,
        'legit_accepted': legit_accepted,
        'legit_rejected': legit_rejected,
        'acceptance_rate': acceptance_rate,
        'recovery_time': recovery_time,
        'peak_utilization': max(e['utilization'] for e in time_series),
    }


def simulate_with_guard(attack_mode: str) -> Dict:
    """
    Simulate ACS session dynamics WITH ACS-GUARD active.

    With ACS-GUARD:
    - Hard cap at M_cap = M_session_pool * alpha (reserves 15%)
    - Adaptive TTL reduces timeout under load
    - Frictionless rate budgeting limits per-merchant frictionless volume
    - Excess requests receive "try again later" (ARes transStatus = "U")

    Args:
        attack_mode: One of 'CEA', 'FFA', 'PTA'.

    Returns:
        Dictionary with time-series data and summary metrics.
    """
    config = ACS_CONFIG
    pool_size = config['session_pool_size']
    tau = config['normal_tau']
    legit_rate = config['legitimate_request_rate']
    frictionless_budget = config['frictionless_budget_per_min']

    attack_fn = {'CEA': cea_attack_rate, 'FFA': ffa_attack_rate, 'PTA': pta_attack_rate}[attack_mode]

    # Session tracking with individual expiry times
    active_sessions = []  # list of expiry_time values
    time_series = []

    exhaustion_time = None
    legit_accepted = 0
    legit_rejected = 0
    frictionless_used_this_minute = 0
    last_minute_reset = 0

    for t in range(SIMULATION_DURATION):
        # Reset frictionless budget every 60 seconds
        if t - last_minute_reset >= 60:
            frictionless_used_this_minute = 0
            last_minute_reset = t

        # Remove expired sessions (using adaptive TTL)
        active_sessions = [exp for exp in active_sessions if exp > t]

        current_active = len(active_sessions)
        utilization = current_active / pool_size

        # Compute adaptive tau
        current_tau = compute_adaptive_tau(utilization, config)

        # Determine attack rate
        raw_attack_rate = attack_fn(t)

        if attack_mode == 'FFA':
            # Frictionless budgeting: limit frictionless requests
            allowed_frictionless = max(0, (frictionless_budget // 60) - frictionless_used_this_minute // 60)
            effective_attack_sessions = min(raw_attack_rate // 5, allowed_frictionless)
            frictionless_used_this_minute += raw_attack_rate
        elif attack_mode == 'PTA':
            # PTA tries to keep sessions alive for full tau,
            # but adaptive TTL reduces the effective session lifetime
            effective_attack_sessions = raw_attack_rate
        else:
            effective_attack_sessions = raw_attack_rate

        # Process legitimate requests (prioritized over attack)
        legit_this_step = legit_rate
        for _ in range(legit_this_step):
            if current_active < M_CAP:
                active_sessions.append(t + current_tau)
                current_active += 1
                legit_accepted += 1
            else:
                # Session pool at cap -- but check if recycling frees slots
                # Under adaptive TTL, sessions expire faster
                legit_rejected += 1

        # Process attack requests (capped by M_CAP)
        attack_sessions_created = 0
        for _ in range(effective_attack_sessions):
            if current_active < M_CAP:
                active_sessions.append(t + current_tau)
                current_active += 1
                attack_sessions_created += 1

        # Check if hard cap reached (not full exhaustion -- 15% reserved)
        if current_active >= M_CAP and exhaustion_time is None:
            exhaustion_time = t

        time_series.append({
            'time': t,
            'active_sessions': current_active,
            'utilization': current_active / pool_size,
            'tau': current_tau,
            'attack_rate': raw_attack_rate,
            'attack_sessions_created': attack_sessions_created,
            'legit_accepted_this_step': legit_this_step - max(0, current_active - M_CAP + legit_this_step - legit_this_step),
        })

    total_legit = legit_accepted + legit_rejected
    acceptance_rate = legit_accepted / total_legit if total_legit > 0 else 1.0

    # Recovery time
    recovery_time = None
    for entry in time_series:
        if entry['time'] > 420 and entry['utilization'] < 0.10:
            recovery_time = entry['time'] - 420
            break

    return {
        'time_series': time_series,
        'exhaustion_time': exhaustion_time,
        'legit_accepted': legit_accepted,
        'legit_rejected': legit_rejected,
        'acceptance_rate': acceptance_rate,
        'recovery_time': recovery_time,
        'peak_utilization': max(e['utilization'] for e in time_series),
    }


# =============================================================================
# ASCII Visualization
# =============================================================================

def ascii_chart(without_ts: List[Dict], with_ts: List[Dict],
                attack_mode: str, width: int = 80, height: int = 25) -> str:
    """
    Generate an ASCII time-series chart of session pool utilization.

    Plots two lines: utilization without ACS-GUARD (x) and with ACS-GUARD (o),
    plus the hard cap line (---) and attack period markers.

    Args:
        without_ts: Time-series data without ACS-GUARD.
        with_ts: Time-series data with ACS-GUARD.
        attack_mode: Attack mode name for title.
        width: Chart width in characters.
        height: Chart height in characters.

    Returns:
        ASCII chart as a multi-line string.
    """
    # Sample time points to fit width
    total_time = len(without_ts)
    step = max(1, total_time // width)
    sampled_times = list(range(0, total_time, step))[:width]

    without_util = [without_ts[t]['utilization'] for t in sampled_times]
    with_util = [with_ts[t]['utilization'] for t in sampled_times]

    lines = []
    lines.append(f"  Session Pool Utilization: {attack_mode} Attack")
    lines.append(f"  Duration: {total_time}s | Pool: {ACS_CONFIG['session_pool_size']:,} sessions")
    lines.append("")

    # Y-axis: 0% to 100%
    for row in range(height, -1, -1):
        y_val = row / height  # 0.0 to 1.0
        y_label = f"{y_val*100:5.0f}% |"

        row_chars = []
        for col in range(len(sampled_times)):
            w_row = int(without_util[col] * height + 0.5)
            g_row = int(with_util[col] * height + 0.5)
            cap_row = int(ACS_CONFIG['alpha'] * height + 0.5)

            char = ' '
            if row == cap_row:
                char = '-'
            if row == w_row and row == g_row:
                char = '*'  # Both lines overlap
            elif row == w_row:
                char = 'x'  # Without ACS-GUARD
            elif row == g_row:
                char = 'o'  # With ACS-GUARD

            row_chars.append(char)

        lines.append(y_label + ''.join(row_chars))

    # X-axis
    x_axis = "      +" + "-" * len(sampled_times)
    lines.append(x_axis)

    # Time labels
    time_labels = "       "
    for i, t in enumerate(sampled_times):
        if i % (len(sampled_times) // 6) == 0:
            label = str(t)
            time_labels += label
            time_labels += " " * max(0, (len(sampled_times) // 6) - len(label))
    lines.append(time_labels + "  (seconds)")

    # Legend
    lines.append("")
    lines.append("  Legend: x = Without ACS-GUARD | o = With ACS-GUARD | - = Hard Cap (M_cap) | * = overlap")
    lines.append(f"  Attack period: t=60 to t=420 | Alpha = {ACS_CONFIG['alpha']}")

    return "\n".join(lines)


# =============================================================================
# Output Formatting
# =============================================================================

def print_comparison(attack_mode: str, without: Dict, with_guard: Dict) -> None:
    """Print comparison table for a single attack mode."""
    print(f"\n{'=' * 75}")
    print(f"  {attack_mode} -- ACS Session Dynamics Comparison")
    print(f"{'=' * 75}")

    print(f"\n  {'Metric':<40} {'Without':>15} {'With Guard':>15}")
    print(f"  {'-'*40} {'-'*15} {'-'*15}")

    # Time to exhaustion
    exh_without = f"{without['exhaustion_time']}s" if without['exhaustion_time'] else "Never"
    exh_with = f"{with_guard['exhaustion_time']}s (cap)" if with_guard['exhaustion_time'] else "Never"
    print(f"  {'Time to pool exhaustion/cap':<40} {exh_without:>15} {exh_with:>15}")

    # Peak utilization
    print(f"  {'Peak utilization':<40} {without['peak_utilization']:>14.1%} {with_guard['peak_utilization']:>14.1%}")

    # Legitimate acceptance rate
    print(f"  {'Legitimate acceptance rate':<40} {without['acceptance_rate']:>14.1%} {with_guard['acceptance_rate']:>14.1%}")

    # Legitimate requests accepted
    print(f"  {'Legitimate requests accepted':<40} {without['legit_accepted']:>15,} {with_guard['legit_accepted']:>15,}")

    # Legitimate requests rejected
    print(f"  {'Legitimate requests rejected':<40} {without['legit_rejected']:>15,} {with_guard['legit_rejected']:>15,}")

    # Recovery time
    rec_without = f"{without['recovery_time']}s" if without['recovery_time'] else ">180s"
    rec_with = f"{with_guard['recovery_time']}s" if with_guard['recovery_time'] else ">180s"
    print(f"  {'Recovery time (after attack ends)':<40} {rec_without:>15} {rec_with:>15}")


def print_time_series_sample(ts_data: List[Dict], label: str,
                              sample_interval: int = 30) -> None:
    """Print sampled time-series data points."""
    print(f"\n  Time-Series Sample ({label}, every {sample_interval}s):")
    print(f"  {'Time':>6} | {'Active':>8} | {'Util':>7} | {'Tau':>6} | {'Attack Rate':>11}")
    print(f"  {'-'*6}-+-{'-'*8}-+-{'-'*7}-+-{'-'*6}-+-{'-'*11}")

    for entry in ts_data:
        if entry['time'] % sample_interval == 0:
            print(f"  {entry['time']:6d} | {entry['active_sessions']:8,} | "
                  f"{entry['utilization']:6.1%} | {entry['tau']:6.0f} | "
                  f"{entry['attack_rate']:11,}")


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    print("ACS-GUARD: 3-D Secure Access Control Server Defense Protocol Simulation")
    print(f"Paper: Adaptive DDoS Defense Strategies for High-TPS Payment Systems")
    print(f"Framework: Section VII.E -- ACS-GUARD Protocol")
    print(f"Simulation duration: {SIMULATION_DURATION} seconds")
    print(f"Session pool size: {ACS_CONFIG['session_pool_size']:,}")
    print(f"Hard cap (M_cap = pool * alpha): {M_CAP:,} "
          f"(alpha = {ACS_CONFIG['alpha']})")
    print(f"Normal tau: {ACS_CONFIG['normal_tau']}s, "
          f"tau_min: {ACS_CONFIG['tau_min']}s")
    print(f"Legitimate request rate: {ACS_CONFIG['legitimate_request_rate']}/s")

    attack_modes = ['CEA', 'FFA', 'PTA']
    all_results = {}

    for mode in attack_modes:
        print(f"\n{'#' * 75}")
        print(f"  Simulating {mode} attack...")
        print(f"{'#' * 75}")

        # Run both conditions
        without = simulate_without_guard(mode)
        with_guard = simulate_with_guard(mode)

        all_results[mode] = {'without': without, 'with': with_guard}

        # Print comparison
        print_comparison(mode, without, with_guard)

        # Print time-series samples
        print_time_series_sample(without['time_series'], f"{mode} WITHOUT Guard")
        print_time_series_sample(with_guard['time_series'], f"{mode} WITH Guard")

        # Print ASCII chart
        print(f"\n{ascii_chart(without['time_series'], with_guard['time_series'], mode)}")

    # Overall summary
    print(f"\n{'=' * 75}")
    print("OVERALL ACS-GUARD VALIDATION SUMMARY")
    print(f"{'=' * 75}")

    print(f"\n  {'Attack Mode':>10} | {'Without: Exhaustion':>20} | {'Without: Accept%':>16} | "
          f"{'With Guard: Accept%':>18} | {'Guard: Recovery':>15}")
    print(f"  {'-'*10}-+-{'-'*20}-+-{'-'*16}-+-{'-'*18}-+-{'-'*15}")

    for mode in attack_modes:
        w = all_results[mode]['without']
        g = all_results[mode]['with']
        exh = f"{w['exhaustion_time']}s" if w['exhaustion_time'] else "Never"
        rec = f"{g['recovery_time']}s" if g['recovery_time'] else ">180s"
        print(f"  {mode:>10} | {exh:>20} | {w['acceptance_rate']:>15.1%} | "
              f"{g['acceptance_rate']:>17.1%} | {rec:>15}")

    # Validation criteria
    print(f"\n{'=' * 75}")
    print("VALIDATION AGAINST PAPER CRITERIA (Section VII.E)")
    print(f"{'=' * 75}")

    for mode in attack_modes:
        g = all_results[mode]['with']
        w = all_results[mode]['without']

        pool_never_full = g['peak_utilization'] < 1.0
        accept_high = g['acceptance_rate'] > 0.99
        better_than_without = g['acceptance_rate'] > w['acceptance_rate']

        print(f"\n  {mode}:")
        print(f"    Pool never reaches 100%: {'PASS' if pool_never_full else 'FAIL'} "
              f"(peak: {g['peak_utilization']:.1%})")
        print(f"    Legit acceptance > 99%:  {'PASS' if accept_high else 'FAIL'} "
              f"(actual: {g['acceptance_rate']:.1%})")
        print(f"    Better than unprotected: {'PASS' if better_than_without else 'FAIL'} "
              f"({g['acceptance_rate']:.1%} vs {w['acceptance_rate']:.1%})")
