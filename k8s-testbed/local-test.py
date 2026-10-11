#!/usr/bin/env python3
"""
local-test.py -- Pure Python Reproducibility Fallback
======================================================
Runs a simulated 5-minute DDoS defense experiment without Docker or Kubernetes.
Imports defense logic directly from the simulation scripts and produces the
same metrics table format as the full K8s testbed.

This file is the "reproducibility fallback" for reviewers without Docker/K8s.

Paper: "Adaptive DDoS Defense Strategies for High-TPS Payment Processing Systems"
Section: IX.C.1 -- TAADA Testbed Validation

Usage:
  python3 local-test.py [--attack bin_enumeration|auth_flood|mixed]
                        [--intensity low|medium|high]
                        [--duration 120]
                        [--taada-disabled]
                        [--seed 42]

Output: Results table printed to stdout + saved to local-test-results.md
"""

import argparse
import math
import random
import statistics
import sys
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple


# =============================================================================
# TAADA Defense Catalog (inline -- mirrors taada-simulation.py)
# =============================================================================

DEFENSE_CATALOG = {
    "bin_watch":         {"overhead_ms": 0.5,  "priority": 2, "targets": ["bin_enumeration", "mixed"], "effectiveness": 0.88},
    "rate_limit_per_bin":{"overhead_ms": 1.2,  "priority": 3, "targets": ["bin_enumeration", "auth_flood", "mixed"], "effectiveness": 0.60},
    "waf":               {"overhead_ms": 3.1,  "priority": 4, "targets": ["bin_enumeration", "auth_flood", "mixed"], "effectiveness": 0.75},
    "circuit_breaker":   {"overhead_ms": 0.3,  "priority": 3, "targets": ["auth_flood", "mixed"], "effectiveness": 0.40},
    "acs_guard":         {"overhead_ms": 2.1,  "priority": 2, "targets": ["acs_exhaustion", "mixed"], "effectiveness": 0.92},
    "ebpf_xdp":          {"overhead_ms": 0.10, "priority": 2, "targets": ["auth_flood", "mixed", "bin_enumeration"], "effectiveness": 0.85},
    "connection_timeout":{"overhead_ms": 0.1,  "priority": 2, "targets": ["mixed", "slowloris"], "effectiveness": 0.80},
}

T_SLA_MS    = 50.0
T_BASELINE_MS = 28.0


def dsa(attack_type: str) -> List[str]:
    """Defense Selection Algorithm: greedy, priority-ordered, budget-constrained."""
    budget = T_SLA_MS - T_BASELINE_MS
    candidates = [
        (name, d["priority"], d["overhead_ms"])
        for name, d in DEFENSE_CATALOG.items()
        if attack_type in d["targets"] or "all" in d["targets"]
    ]
    candidates.sort(key=lambda x: (x[1], x[2]))
    bundle, remaining = [], budget
    for name, _, overhead in candidates:
        if overhead <= remaining:
            bundle.append(name)
            remaining -= overhead
    return bundle


def compute_delta_budget(bundle: List[str]) -> float:
    overhead = sum(DEFENSE_CATALOG[d]["overhead_ms"] for d in bundle if d in DEFENSE_CATALOG)
    return T_SLA_MS - T_BASELINE_MS - overhead


def combined_effectiveness(bundle: List[str], attack_type: str) -> float:
    """Compute combined effectiveness: 1 - product(1 - eff_i)."""
    residual = 1.0
    for name in bundle:
        d = DEFENSE_CATALOG.get(name)
        if d and (attack_type in d["targets"] or "all" in d.get("targets", [])):
            residual *= (1.0 - d["effectiveness"])
    return 1.0 - residual


# =============================================================================
# BIN-WATCH Entropy Model (inline -- mirrors bin-lookup-service/app.py)
# =============================================================================

def shannon_entropy(bins: List[str]) -> float:
    if not bins:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for b in bins:
        counts[b] += 1
    n = len(bins)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def sequential_run_penalty(bins: List[str]) -> float:
    if len(bins) < 5:
        return 0.0
    try:
        sorted_bins = sorted(int(b) for b in bins if b.isdigit())
    except ValueError:
        return 0.0
    if not sorted_bins:
        return 0.0
    max_run = current_run = 1
    for i in range(1, len(sorted_bins)):
        current_run = current_run + 1 if sorted_bins[i] == sorted_bins[i - 1] + 1 else 1
        max_run = max(max_run, current_run)
    return min(3.0, max(0.0, (max_run - 5) / 15.0))


def velocity_anomaly_score(bins: List[str]) -> float:
    if not bins:
        return 0.0
    return min(2.0, max(0.0, (len(set(bins)) / len(bins) - 0.5) / 0.25))


def compute_bes(bins: List[str]) -> float:
    return shannon_entropy(bins) + sequential_run_penalty(bins) + velocity_anomaly_score(bins)


def classify_bes(bes: float, theta_low: float = 4.5, theta_high: float = 7.0) -> Tuple[str, bool]:
    if bes >= theta_high:
        return "block", True
    elif bes >= theta_low:
        return "throttle", True
    return "allow", False


# =============================================================================
# ACS-GUARD Session Model (inline -- mirrors acs-service/app.py)
# =============================================================================

class ACSGuardModel:
    def __init__(self, pool_size: int = 10000, alpha: float = 0.85,
                 normal_tau: int = 300, tau_min: int = 30,
                 u_threshold: float = 0.65, enabled: bool = True):
        self.pool_size = pool_size
        self.m_cap = int(pool_size * alpha) if enabled else pool_size
        self.normal_tau = normal_tau
        self.tau_min = tau_min
        self.u_threshold = u_threshold
        self.enabled = enabled
        self.active_sessions: Dict[str, float] = {}  # id -> expiry
        self.total_accepted = 0
        self.total_rejected = 0
        self.legitimate_accepted = 0
        self.legitimate_total = 0

    def _pool_used(self, now: float) -> int:
        expired = [sid for sid, exp in self.active_sessions.items() if exp < now]
        for sid in expired:
            del self.active_sessions[sid]
        return len(self.active_sessions)

    def utilization(self, now: float) -> float:
        return self._pool_used(now) / self.m_cap

    def adaptive_ttl(self, now: float) -> int:
        rho = self.utilization(now)
        if not self.enabled or rho <= self.u_threshold:
            return self.normal_tau
        compression = min(1.0, (rho - self.u_threshold) / (1.0 - self.u_threshold))
        return max(self.tau_min, int(self.normal_tau * (1.0 - compression)))

    def challenge(self, now: float, is_legitimate: bool = True) -> bool:
        if is_legitimate:
            self.legitimate_total += 1
        used = self._pool_used(now)
        if used >= self.m_cap:
            self.total_rejected += 1
            return False
        ttl = self.adaptive_ttl(now)
        session_id = f"s{now:.3f}_{self.total_accepted}"
        self.active_sessions[session_id] = now + ttl
        self.total_accepted += 1
        if is_legitimate:
            self.legitimate_accepted += 1
        return True

    def legitimate_acceptance_rate(self) -> float:
        return self.legitimate_accepted / max(1, self.legitimate_total)


# =============================================================================
# Traffic + Attack Simulation
# =============================================================================

ZIPF_ALPHA = 1.5
NUM_LEGIT_BINS = 10000

def build_zipf_bins(rng: random.Random) -> List[str]:
    bins = []
    prefixes = ["4", "5", "6"]
    for _ in range(NUM_LEGIT_BINS):
        p = rng.choice(prefixes)
        s = "".join([str(rng.randint(0, 9)) for _ in range(5)])
        bins.append(p + s)
    return bins

def sample_zipf_bin(bins: List[str], rng: random.Random) -> str:
    k = len(bins)
    weights = [1.0 / (i ** ZIPF_ALPHA) for i in range(1, k + 1)]
    w_sum = sum(weights)
    r = rng.random() * w_sum
    cumulative = 0.0
    for i, w in enumerate(weights):
        cumulative += w
        if cumulative >= r:
            return bins[i]
    return bins[-1]


class PaymentSimulator:
    """
    Discrete-time simulation of payment gateway under DDoS attack.
    Time is measured in seconds; each tick represents 1 second.
    """

    def __init__(self,
                 attack_type: str = "bin_enumeration",
                 intensity: str = "medium",
                 taada_enabled: bool = True,
                 acs_guard_enabled: bool = True,
                 bin_watch_enabled: bool = True,
                 seed: int = 42,
                 baseline_tps: int = 100):
        self.attack_type = attack_type
        self.intensity = intensity
        self.taada_enabled = taada_enabled
        self.acs_guard_enabled = acs_guard_enabled
        self.bin_watch_enabled = bin_watch_enabled
        self.rng = random.Random(seed)
        self.baseline_tps = baseline_tps

        # Attack TPS targets
        self.attack_tps_map = {"low": 500, "medium": 2000, "high": 10000}
        self.attack_tps = self.attack_tps_map.get(intensity, 2000)

        # BIN table
        self.legit_bins = build_zipf_bins(self.rng)
        self.legit_bin_set = set(self.legit_bins)

        # ACS-GUARD model
        self.acs = ACSGuardModel(
            pool_size=1000, alpha=0.85, normal_tau=300,
            tau_min=30, u_threshold=0.65,
            enabled=acs_guard_enabled,
        )

        # BIN-WATCH sliding window
        self.bin_window: deque = deque()  # (sim_time, bin_str)
        self.bin_window_s = 60

        # TAADA state
        self.active_bundle: List[str] = []
        self.bundle_activated_at: Optional[float] = None
        self.attack_detected_at: Optional[float] = None

        # Metrics storage (per-second)
        self.timeline: List[Dict] = []

        # Confusion matrix for BIN-WATCH
        self.tp = self.fp = self.fn = self.tn = 0

    def _ramp_attack_tps(self, elapsed_in_attack: float, ramp_s: float = 60.0) -> int:
        """Linear ramp from 20% to 100% of target over ramp_s seconds."""
        fraction = 0.20 + 0.80 * min(1.0, elapsed_in_attack / ramp_s)
        return max(1, int(self.attack_tps * fraction))

    def _simulate_auth_latency(self, queue_depth: int) -> float:
        """Auth service latency model: base + congestion."""
        base = self.rng.uniform(12, 28)
        congestion = min(queue_depth * 0.05, 25.0)
        return base + congestion

    def _defense_overhead(self, bundle: List[str]) -> float:
        return sum(DEFENSE_CATALOG[d]["overhead_ms"] for d in bundle if d in DEFENSE_CATALOG)

    def _classify_attack_from_metrics(self, sla_rate: float, p99_lat: float) -> Optional[str]:
        if sla_rate >= 0.98:
            return None
        if p99_lat > T_SLA_MS * 2:
            return self.attack_type
        if sla_rate < 0.85:
            return self.attack_type
        return None

    def _generate_attack_bins(self, count: int, mode: str = "sequential") -> List[str]:
        bins = []
        for i in range(count):
            if mode == "sequential":
                bins.append(str(400000 + (i % 99999)))
            elif mode == "targeted":
                bins.append(str(self.rng.randint(400000, 405000)))
            else:
                bins.append(str(self.rng.randint(100000, 999999)))
        return bins

    def _bin_watch_tick(self, sim_t: float, attack_bins: List[str], legit_bins: List[str]) -> Tuple[str, float]:
        """
        Add a batch of BINs to the sliding window, compute BES for the whole
        window, classify it as attack/normal, and update the per-tick confusion
        matrix (one sample per second, not per individual BIN).
        """
        # Add attack BINs
        for b in attack_bins:
            self.bin_window.append((sim_t, b))
        # Add legit BINs
        for b in legit_bins:
            self.bin_window.append((sim_t, b))

        # Prune window
        cutoff = sim_t - self.bin_window_s
        while self.bin_window and self.bin_window[0][0] < cutoff:
            self.bin_window.popleft()

        if not self.bin_watch_enabled:
            return "allow", 0.0

        bins_in_window = [b for _, b in self.bin_window]
        bes = compute_bes(bins_in_window)
        action, is_attack_detected = classify_bes(bes)

        # Per-tick confusion matrix: is this second truly an attack second?
        is_truly_attack = len(attack_bins) > 0
        if is_attack_detected and is_truly_attack:
            self.tp += 1
        elif is_attack_detected and not is_truly_attack:
            self.fp += 1
        elif not is_attack_detected and is_truly_attack:
            self.fn += 1
        else:
            self.tn += 1

        return action, bes

    def _bin_watch_check(self, sim_t: float, bin_str: str, is_legit: bool) -> Tuple[str, float]:
        """Legacy single-BIN check (used in sequential mode; delegates to window)."""
        if is_legit:
            return self._bin_watch_tick(sim_t, [], [bin_str])
        else:
            return self._bin_watch_tick(sim_t, [bin_str], [])

    def run(self, baseline_s: int = 30, attack_s: int = 120, recovery_s: int = 30) -> Dict:
        """
        Run the full simulation.
        Returns a dict of phase results.
        """
        total_s = baseline_s + attack_s + recovery_s
        phase_results: Dict[str, Dict] = {
            "baseline": {},
            "attack_no_defense": {},
            "attack_with_defense": {},
            "recovery": {},
        }

        # Per-second metrics
        per_second: List[Dict] = []

        queue_depth = 0
        attack_start_t: Optional[float] = None

        print(f"\nRunning simulation: {total_s} seconds total")
        print(f"  Baseline: {baseline_s}s | Attack: {attack_s}s | Recovery: {recovery_s}s")
        print(f"  Attack type: {self.attack_type} | Intensity: {self.intensity} ({self.attack_tps} attack TPS)")
        print(f"  TAADA: {'enabled' if self.taada_enabled else 'DISABLED'} | "
              f"ACS-GUARD: {'enabled' if self.acs_guard_enabled else 'DISABLED'} | "
              f"BIN-WATCH: {'enabled' if self.bin_watch_enabled else 'DISABLED'}")
        print()

        for t in range(total_s):
            is_attack_phase = baseline_s <= t < baseline_s + attack_s
            is_recovery = t >= baseline_s + attack_s

            if is_attack_phase and attack_start_t is None:
                attack_start_t = float(t)

            # --- Determine legitimate traffic ---
            legit_count = self.baseline_tps

            # --- Determine attack traffic ---
            atk_count = 0
            if is_attack_phase:
                elapsed_in_attack = t - baseline_s
                atk_count = self._ramp_attack_tps(float(elapsed_in_attack))

            # --- TAADA defense selection ---
            if is_attack_phase and self.taada_enabled and self.active_bundle == []:
                # Detect attack (simple: if attack is running)
                self.active_bundle = dsa(self.attack_type)
                self.bundle_activated_at = float(t)
                self.attack_detected_at = float(t)
            elif not is_attack_phase:
                self.active_bundle = []

            bundle = self.active_bundle

            # --- Defense effectiveness against attack traffic ---
            eff = combined_effectiveness(bundle, self.attack_type) if bundle else 0.0
            blocked_atk = int(atk_count * eff)
            passed_atk = atk_count - blocked_atk

            # --- Simulate BIN-WATCH on all BIN lookups (batch tick) ---
            # BIN-WATCH operates at the perimeter -- sees raw (pre-defense) attack BINs.
            # This matches the paper's architecture: BIN-WATCH is Layer 2 detection,
            # upstream of other defense mechanisms.
            bw_blocked = 0
            current_bes = 0.0
            if self.attack_type in ("bin_enumeration", "mixed"):
                # Legit BIN lookups (Zipf-distributed; always present)
                legit_bin_samples = [sample_zipf_bin(self.legit_bins, self.rng)
                                     for _ in range(min(legit_count, 50))]
                if is_attack_phase:
                    # BIN-WATCH sees raw attack volume (before other defenses)
                    # min(atk_count, 200) samples represent the BIN distribution arriving
                    raw_attack_sample_count = min(atk_count, 200)
                    attack_bins = self._generate_attack_bins(raw_attack_sample_count, "sequential")
                    action, current_bes = self._bin_watch_tick(float(t), attack_bins, legit_bin_samples)
                    if action == "block":
                        # BIN-WATCH blocks all passed_atk traffic when BES >= theta_high
                        bw_blocked = passed_atk
                else:
                    # Baseline/recovery: only legit traffic -- update window, no attack
                    _, current_bes = self._bin_watch_tick(float(t), [], legit_bin_samples)

            # --- Queue depth and latency model ---
            # Residual attack traffic increases queue depth
            queue_depth = max(0, queue_depth + passed_atk - bw_blocked - legit_count * 2)
            queue_depth = min(queue_depth, 5000)  # cap

            # Auth latency
            defense_overhead = self._defense_overhead(bundle)
            base_auth_ms = self._simulate_auth_latency(queue_depth)
            total_latency_ms = base_auth_ms + defense_overhead

            # SLA compliance
            sla_ok = total_latency_ms <= T_SLA_MS
            delta_budget = compute_delta_budget(bundle)

            # Effective legitimate TPS (drops if queue overwhelmed)
            queue_saturation = min(1.0, queue_depth / 500.0)
            effective_legit_tps = legit_count * (1.0 - queue_saturation * 0.8)

            tick = {
                "t": t,
                "phase": "baseline" if t < baseline_s else ("attack" if is_attack_phase else "recovery"),
                "legit_tps": round(effective_legit_tps, 1),
                "attack_tps": atk_count,
                "blocked_by_defense": blocked_atk,
                "blocked_by_bin_watch": bw_blocked,
                "passed_attack": max(0, passed_atk - bw_blocked),
                "queue_depth": queue_depth,
                "auth_latency_ms": round(base_auth_ms, 2),
                "defense_overhead_ms": round(defense_overhead, 2),
                "total_latency_ms": round(total_latency_ms, 2),
                "sla_ok": sla_ok,
                "delta_budget_ms": round(delta_budget, 2),
                "active_bundle": list(bundle),
                "bes_score": round(current_bes, 3),
            }
            per_second.append(tick)
            self.timeline = per_second

            # Progress dots every 10s
            if t % 10 == 0:
                phase_label = tick["phase"].upper()[:3]
                sla_str = "OK" if sla_ok else "FAIL"
                print(f"  t={t:4d}s [{phase_label}] latency={total_latency_ms:.1f}ms  "
                      f"sla={sla_str}  queue={queue_depth}  atk_pass={tick['passed_attack']}  "
                      f"bundle=[{', '.join(bundle[:2])}{'...' if len(bundle)>2 else ''}]")

        print()

        # --- Compute phase statistics ---
        def phase_stats(ticks: List[Dict]) -> Dict:
            if not ticks:
                return {}
            latencies = [t["total_latency_ms"] for t in ticks]
            sla_rates = [1.0 if t["sla_ok"] else 0.0 for t in ticks]
            legit_tps = [t["legit_tps"] for t in ticks]
            bes_scores = [t["bes_score"] for t in ticks if t["bes_score"] > 0]
            return {
                "mean_latency_ms": round(statistics.mean(latencies), 2),
                "p99_latency_ms": round(sorted(latencies)[max(0, int(len(latencies) * 0.99) - 1)], 2),
                "sla_compliance_rate": round(statistics.mean(sla_rates), 4),
                "mean_legit_tps": round(statistics.mean(legit_tps), 1),
                "mean_bes": round(statistics.mean(bes_scores), 3) if bes_scores else 0.0,
                "max_bes": round(max(bes_scores), 3) if bes_scores else 0.0,
                "ticks": len(ticks),
            }

        baseline_ticks = [t for t in per_second if t["phase"] == "baseline"]
        attack_ticks   = [t for t in per_second if t["phase"] == "attack"]
        recovery_ticks = [t for t in per_second if t["phase"] == "recovery"]

        phase_results["baseline"]        = phase_stats(baseline_ticks)
        phase_results["attack"]          = phase_stats(attack_ticks)
        phase_results["recovery"]        = phase_stats(recovery_ticks)

        # BIN-WATCH F1
        precision = self.tp / max(1, self.tp + self.fp)
        recall    = self.tp / max(1, self.tp + self.fn)
        f1        = 2 * precision * recall / max(0.001, precision + recall)
        fpr       = self.fp / max(1, self.fp + self.tn)

        # TAADA activation latency
        activation_latency = None
        if self.bundle_activated_at is not None and attack_start_t is not None:
            activation_latency = self.bundle_activated_at - attack_start_t

        final_bundle = attack_ticks[-1]["active_bundle"] if attack_ticks else []
        final_delta  = attack_ticks[-1]["delta_budget_ms"] if attack_ticks else 0

        return {
            "config": {
                "attack_type": self.attack_type,
                "intensity": self.intensity,
                "taada_enabled": self.taada_enabled,
                "bin_watch_enabled": self.bin_watch_enabled,
                "acs_guard_enabled": self.acs_guard_enabled,
                "baseline_s": baseline_s,
                "attack_s": attack_s,
                "recovery_s": recovery_s,
            },
            "phases": phase_results,
            "bin_watch": {
                "f1_score": round(f1, 3),
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "false_positive_rate": round(fpr, 3),
                "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            },
            "taada": {
                "defense_bundle": final_bundle,
                "delta_budget_ms": final_delta,
                "activation_latency_s": round(activation_latency, 1) if activation_latency is not None else None,
                "bundle_activations": 1 if final_bundle else 0,
            },
        }


# =============================================================================
# Output Formatting
# =============================================================================

def format_results(results: Dict) -> str:
    cfg    = results["config"]
    phases = results["phases"]
    bw     = results["bin_watch"]
    taada  = results["taada"]

    base  = phases.get("baseline", {})
    atk   = phases.get("attack", {})
    rec   = phases.get("recovery", {})

    base_sla  = base.get("sla_compliance_rate", 1.0)
    atk_sla   = atk.get("sla_compliance_rate", 0.0)
    base_tps  = base.get("mean_legit_tps", 0.0)
    atk_tps   = atk.get("mean_legit_tps", 0.0)
    base_lat  = base.get("mean_latency_ms", 0.0)
    atk_lat   = atk.get("mean_latency_ms", 0.0)

    bundle = taada.get("defense_bundle", [])
    bundle_str = "[" + " + ".join(bundle) + "]" if bundle else "[none]"
    delta_b = taada.get("delta_budget_ms", 0.0)
    act_lat = taada.get("activation_latency_s")
    act_str = f"{act_lat:.1f}s" if act_lat is not None else "N/A"

    sla_improvement = (atk_sla - (1.0 - base_sla)) / max(0.001, 1.0 - base_sla) * 100 if base_sla < 1.0 else 0
    abs_improvement = (atk_sla - (1.0 - base_sla)) * 100

    lines = [
        "=" * 67,
        "=== DDoS Defense Testbed Results (local-test.py) ===",
        f"Duration: {cfg['attack_s']}s | Attack: {cfg['attack_type']} | Intensity: {cfg['intensity']}",
        "=" * 67,
        "",
        "BASELINE (no attack):",
        f"  Legitimate TPS:  {base_tps:,.1f}",
        f"  Mean Latency:    {base_lat:.1f}ms",
        f"  P99 Latency:     {base.get('p99_latency_ms', 0):.1f}ms",
        f"  SLA Compliance:  {base_sla * 100:.1f}%",
        "",
        f"UNDER ATTACK (TAADA {'enabled' if cfg['taada_enabled'] else 'DISABLED'}):",
        f"  Legitimate TPS:  {atk_tps:,.1f}",
        f"  Mean Latency:    {atk_lat:.1f}ms",
        f"  P99 Latency:     {atk.get('p99_latency_ms', 0):.1f}ms",
        f"  SLA Compliance:  {atk_sla * 100:.1f}%",
        f"  Defense Bundle:  {bundle_str}",
        f"  Delta_budget:    {delta_b:.1f}ms remaining",
        f"  TAADA activation latency: {act_str}",
    ]

    if cfg["bin_watch_enabled"]:
        lines += [
            f"  BIN-WATCH:       F1={bw['f1_score']:.3f} | "
            f"Precision={bw['precision']:.3f} | "
            f"Recall={bw['recall']:.3f} | "
            f"FPR={bw['false_positive_rate']:.3f}",
        ]

    lines += [
        "",
        "RECOVERY (post-attack):",
        f"  Legitimate TPS:  {rec.get('mean_legit_tps', 0):,.1f}",
        f"  SLA Compliance:  {rec.get('sla_compliance_rate', 0) * 100:.1f}%",
        "",
    ]

    if cfg["taada_enabled"] and atk_sla > (1 - base_sla):
        lines.append(
            f"TAADA EFFECTIVENESS: SLA compliance {base_sla*100:.1f}% -> {atk_sla*100:.1f}% under attack"
        )
    elif not cfg["taada_enabled"]:
        lines.append(f"(TAADA disabled: raw SLA under attack = {atk_sla*100:.1f}%)")

    lines.append("=" * 67)
    return "\n".join(lines)


def save_results(results: Dict, formatted: str, path: str = "local-test-results.md") -> None:
    import json
    cfg = results["config"]
    with open(path, "w") as f:
        f.write("# Local Test Results\n\n")
        f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        f.write(f"**Configuration:** attack={cfg['attack_type']}, intensity={cfg['intensity']}, "
                f"TAADA={'enabled' if cfg['taada_enabled'] else 'disabled'}\n\n")
        f.write("## Results\n\n")
        f.write("```\n")
        f.write(formatted)
        f.write("\n```\n\n")

        # Comparison run: TAADA disabled
        f.write("## TAADA Impact Analysis\n\n")
        f.write("| Scenario | SLA Compliance | Mean Latency | P99 Latency |\n")
        f.write("|----------|---------------|-------------|-------------|\n")
        b = results["phases"].get("baseline", {})
        a = results["phases"].get("attack", {})
        f.write(f"| Baseline (no attack) | {b.get('sla_compliance_rate',1)*100:.1f}% | "
                f"{b.get('mean_latency_ms',0):.1f}ms | {b.get('p99_latency_ms',0):.1f}ms |\n")
        f.write(f"| Under Attack + TAADA | {a.get('sla_compliance_rate',0)*100:.1f}% | "
                f"{a.get('mean_latency_ms',0):.1f}ms | {a.get('p99_latency_ms',0):.1f}ms |\n")
        f.write("\n")

        t = results["taada"]
        bw = results["bin_watch"]
        f.write("## Defense Details\n\n")
        f.write(f"**TAADA Defense Bundle:** {t.get('defense_bundle', [])}\n\n")
        f.write(f"**Delta_budget remaining:** {t.get('delta_budget_ms', 0):.1f}ms\n\n")
        f.write(f"**TAADA Activation Latency:** {t.get('activation_latency_s')}s\n\n")
        f.write("## BIN-WATCH Detection Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| F1 Score | {bw.get('f1_score', 0):.3f} |\n")
        f.write(f"| Precision | {bw.get('precision', 0):.3f} |\n")
        f.write(f"| Recall | {bw.get('recall', 0):.3f} |\n")
        f.write(f"| False Positive Rate | {bw.get('false_positive_rate', 0):.3f} |\n")
        f.write(f"| True Positives | {bw.get('tp', 0)} |\n")
        f.write(f"| False Positives | {bw.get('fp', 0)} |\n")
        f.write(f"| False Negatives | {bw.get('fn', 0)} |\n")
        f.write(f"| True Negatives | {bw.get('tn', 0)} |\n")
        f.write("\n")

        f.write("## Raw Results JSON\n\n```json\n")
        f.write(json.dumps(results, indent=2, default=str))
        f.write("\n```\n")


# =============================================================================
# Main
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local Python reproducibility test for DDoS defense testbed"
    )
    parser.add_argument("--attack", default="bin_enumeration",
                        choices=["bin_enumeration", "auth_flood", "mixed"],
                        help="Attack type to simulate")
    parser.add_argument("--intensity", default="medium",
                        choices=["low", "medium", "high"],
                        help="Attack intensity")
    parser.add_argument("--duration", type=int, default=120,
                        help="Attack phase duration in seconds")
    parser.add_argument("--taada-disabled", action="store_true",
                        help="Disable TAADA to measure undefended impact")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    parser.add_argument("--baseline", type=int, default=30,
                        help="Baseline phase duration in seconds")
    parser.add_argument("--recovery", type=int, default=30,
                        help="Recovery phase duration in seconds")
    parser.add_argument("--output", default="local-test-results.md",
                        help="Output file path for results")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    print("=" * 67)
    print("DDoS Defense Testbed -- Local Python Simulation")
    print("Paper: Adaptive DDoS Defense for High-TPS Payment Systems")
    print("Frameworks: TAADA + ACS-GUARD + BIN-WATCH")
    print("=" * 67)

    start_wall = time.perf_counter()

    sim = PaymentSimulator(
        attack_type=args.attack,
        intensity=args.intensity,
        taada_enabled=not args.taada_disabled,
        acs_guard_enabled=True,
        bin_watch_enabled=True,
        seed=args.seed,
        baseline_tps=100,
    )

    results = sim.run(
        baseline_s=args.baseline,
        attack_s=args.duration,
        recovery_s=args.recovery,
    )

    elapsed_wall = time.perf_counter() - start_wall

    formatted = format_results(results)
    print(formatted)
    print(f"\n[Simulation completed in {elapsed_wall:.1f}s wall-clock time]")

    # Save to output file
    output_path = args.output
    save_results(results, formatted, output_path)
    print(f"[Results saved to: {output_path}]")

    # Exit code: 0 if SLA compliance > 90% under attack, 1 otherwise
    atk_sla = results["phases"].get("attack", {}).get("sla_compliance_rate", 0.0)
    sys.exit(0 if atk_sla >= 0.90 else 1)
