"""
TIG-CDO Evaluation Harness — calibrated parametric/analytical model

IMPORTANT (added 2026-08-16, post multi-reviewer audit — see
paper2-solution/review/2026-08-15/00_CONSOLIDATED_REVIEW.md, findings C2/M10):
This harness does NOT run an end-to-end simulation through the STC/CLCS/BIM/PSRG
components for the CSDA configuration comparison or the FDCE (30-scenario) comparison. SLA is
Monte Carlo sampled from per-config latency means that were back-solved to approximate
target SLA values; FPR, detection latency, and the attack block rate are per-config
constants (see _FPR, _DET_LATENCY, _ATTACK_BLOCK below), not measured outputs. Treat
every number this script prints as a calibrated design target with Monte Carlo sampling
noise layered on top, not as an independent measurement of the TIG-CDO architecture.
The Phase 1-4 CLCS/PADO test below (`run_phase_detection_test`) DOES exercise the real
stc/clcs/bim/pado modules directly and is a genuine (if single-scenario, uncalibrated)
functional exercise of those components.

v1.2.0 corrections (2026-10-15):
  * FPR denominator (review R1-009): v1.1.0 computed
        n_legit_rejected / (n_processed - n_attack_total + n_legit_rejected),
    which subtracts blocked attack transactions and counts rejected legitimate
    transactions twice. The FPR is now n_legit_rejected / n_legit_total, where
    n_legit_total counts every legitimate transaction offered in the run.
  * Scenario grid (review R1-008): the CSDA comparison depends only on whether
    an attack is active and on its intensity (attack share 10/25/45%). The TPS
    tier and the CSDA phase never entered the computation. The grid is now
    described as what it is: 4 distinct conditions (no attack, light, moderate,
    heavy) per configuration, run as 39 replicate runs (3 no-attack replicates
    and 12 replicates of each attack intensity). The run order of v1.1.0 is kept
    so that seed-42 SLA values are unchanged; the former phase/TPS labels survive
    only as replicate identifiers. The stale "270 scenarios" label is removed.
  * Results are also written to tigcdo_eval_results.json (machine-readable).

v1.3.0 corrections (2026-10-22, review round 3):
  * Each configuration draws from its own random.Random stream (R3-025): in
    v1.2 all configurations shared the global stream, so changing one
    configuration's constants shifted another's draws. Seed-42 values therefore
    differ from v1.2.1.
  * No literal values in the results JSON (R3-025): Phase-1 TCS at detection is
    the computed value; the Phase-3 "detection latency" literal (1.8 s) is
    removed; the Phase-4 TCS change rate is labelled as a configured value.
  * Phase 1 (R3-006): every reconnaissance probe is answered (94% declined with
    codes 14/54, 6% approved and never captured), with the reference STC fixed
    (R3-005). Two layouts are reported: probes inside the legitimate BIN family
    (realistic) and probes in their own BIN family; TCS_str and TCS_dst are
    reported separately. Detection uses the STC threshold 0.50 (S1 Table S1).
  * Phase 3 (R3-012): the configured point is evaluated with the issuer-side
    ACS signal s4 shared and for a processor that cannot observe s4 (weights
    renormalized over s1, s2, s3, s5).
  * The validation checks are printed for information; they are self-checks of
    this harness, not tests of the design, and do not set the exit code.

Usage:
    python3 run_tigcdo_eval.py

All results are deterministic (seed=42).
"""

import sys
import os
import time
import random
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))
from stc.stc import SemanticTransactionCorrelator, PaymentEvent, EventType
from clcs.clcs import CLCSEngine, CLCSConfig, LayerScores
from bim.bim import (BaselineIntegrityMonitor, BaselineStat, zipf_distribution,
                      zipf_s_for_entropy, sample_categorical_counts)
from fdce.scenario import simulate_fdce_scenario

# BIM v2 JS-CUSUM parameters (calibrate_bim_js_cusum.py, Monte Carlo over
# organic seasonality; ~3% false-alarm rate per 90-day run, CSDA-rate (2.8%/day)
# mean detection 6.15 days from onset). See BIM_JS_CUSUM_CALIBRATION.json.
BIM_K_CATEGORIES = 50
BIM_WINDOW_SAMPLES = 2000
BIM_MU0_ENTROPY_BITS = 1.80
BIM_WEEKDAY_AMPLITUDE = 0.06
BIM_MU0_JS = 0.00334
BIM_K = 0.00036
BIM_H = 0.00583
BIM_SEED_S0 = zipf_s_for_entropy(BIM_K_CATEGORIES, BIM_MU0_ENTROPY_BITS)
BIM_SEED_DIST = zipf_distribution(BIM_K_CATEGORIES, BIM_SEED_S0)


def _bim_organic_entropy(day_index: int, rng: random.Random) -> float:
    dow = day_index % 7
    weekend_boost = BIM_WEEKDAY_AMPLITUDE if dow >= 5 else -BIM_WEEKDAY_AMPLITUDE * 0.4
    return BIM_MU0_ENTROPY_BITS + weekend_boost + rng.gauss(0, 0.02)


def _bim_observe_entropy_target(bim: BaselineIntegrityMonitor, target_entropy_bits: float,
                                 ts: float, rng: random.Random):
    """Sample a distribution at the given target entropy and feed it to BIM."""
    s = zipf_s_for_entropy(BIM_K_CATEGORIES, target_entropy_bits)
    dist = zipf_distribution(BIM_K_CATEGORIES, s)
    observed = sample_categorical_counts(dist, BIM_WINDOW_SAMPLES, rng)
    return bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, observed, ts)
from psrg.psrg import PaymentSemanticRateGovernor
from pado.pado import PreAuthorizedDefenseOrchestrator, TIGContext

logging.basicConfig(level=logging.WARNING)
SEED = 42
CONFIG_INDEX = {"no_defense": 0, "taada": 1, "ensemble": 2, "tig_cdo": 3}


def config_rng(config: str, purpose: str) -> random.Random:
    """Independent stream per configuration and purpose (v1.3.0, R3-025)."""
    base = {"csda": 1000, "fdce": 2000}[purpose]
    return random.Random(SEED + base + 100 * CONFIG_INDEX[config])

SLA_BUDGET_MS = 50.0

# Calibration targets from paper v1 (main.md, pre-2026-08-16 rewrite). These are the
# values the latency/FPR/detection-latency/capacity-gain constants below were fitted to
# reproduce approximately -- NOT independently-derived ground truth. Retained so `main()`
# can print an explicit target-vs-realized comparison rather than silently diverging.
CALIBRATION_TARGETS = {
    "no_defense": (41.2, None, None, 623),
    "taada":      (78.4, 2.3,  4.2,  891),
    "ensemble":   (84.1, 1.8,  3.1,  943),
    "tig_cdo":    (98.3, 0.08, 1.8, 1198),
}

# ---------------------------------------------------------------------------
# Latency model for one transaction
# ---------------------------------------------------------------------------

# Per-config latency model — calibrated 2026-03-23 from CICDDoS2019 (125,170 flows).
#
# Key insight: under DDoS, server saturation degrades ALL transactions (not just
# attack traffic). The attack floods CPU/connection-tables/network queues, raising
# service latency for every transaction reaching the payment stack.
#
# mean_attack = service latency for ANY transaction when residual attack load is
# at full-intensity (heavy, 45% traffic, 0% blocked). Derived by solving:
#   P(N(mean_a, 10) ≤ 50ms) = target_phase3_sla
# where target_phase3_sla is back-calculated from Table II aggregate SLA.
#
# CICDDoS2019 empirical validation: Cohen's d = 0.71 (benign vs attack IAT),
# confirming strong separation. Benign SLA proxy 74.2%, attack 37.8%.
#
# no_defense: SLA=41.2%  → mean_attack=73.3ms  P(N(73.3,10)≤50)≈1.0% → agg≈41%
# taada:      SLA=78.4%  → mean_attack=65.1ms  45% blocked → partial recovery
# ensemble:   SLA=84.1%  → mean_attack=59.9ms  55% blocked → moderate recovery
# tig_cdo:    SLA=98.3%  → mean_attack=55.2ms  95% blocked → near-full recovery

_LATENCY_PARAMS = {
    # (mean_legit_ms, std_legit_ms, mean_attack_ms, std_attack_ms)
    # mean_attack applies to ALL transactions when service is under attack load
    "no_defense": (27.0, 6.0,  73.3, 10.0),
    "taada":      (27.8, 6.0,  65.1, 10.0),
    "ensemble":   (28.1, 6.0,  59.9, 10.0),
    "tig_cdo":    (28.5, 6.0,  55.2, 10.0),
}

# Residual attack load fraction: how much attack traffic reaches the payment stack.
# When residual load > SATURATION_THRESHOLD, ALL transactions see degraded latency.
SATURATION_THRESHOLD = 0.05  # >5% residual attack load → service-wide degradation

def sample_latency(config: str, is_attack_scenario: bool, residual_load: float = 1.0,
                   rng: Optional[random.Random] = None) -> float:
    """Sample transaction latency.
    Under attack, if residual_load > threshold, ALL transactions see degraded latency
    (server saturation model). Otherwise only attack transactions are affected.
    residual_load = attack_frac * (1 - block_rate) — fraction of capacity consumed by attack.
    """
    rng = rng or random
    mean_l, std_l, mean_a, std_a = _LATENCY_PARAMS[config]
    if is_attack_scenario and residual_load > SATURATION_THRESHOLD:
        # Service is saturated: interpolate latency between legit and attack params
        # proportional to residual load (0 = clean, 1 = full saturation)
        sat_factor = min(1.0, residual_load / 0.45)  # normalize to heavy attack baseline
        mean = mean_l + sat_factor * (mean_a - mean_l)
        std  = std_l  + sat_factor * (std_a  - std_l)
        return rng.gauss(mean, std)
    return rng.gauss(mean_l, std_l)

# Per-config false positive rates (fraction of legitimate transactions blocked)
_FPR = {
    "no_defense": 0.000,
    "taada":      0.023,
    "ensemble":   0.018,
    "tig_cdo":    0.0008,
}

# Per-config attack blocking efficiency (fraction of attack traffic stopped before processing)
# Determines what fraction of attack traffic actually degrades service
_ATTACK_BLOCK = {
    "no_defense": 0.00,
    "taada":      0.45,
    "ensemble":   0.55,
    "tig_cdo":    0.95,   # PSRG TCS-blocking at TCS=0.23 → 95% blocked
}

# Attack traffic fraction per intensity
_ATTACK_FRAC = {"none": 0.0, "light": 0.10, "moderate": 0.25, "heavy": 0.45}

# Detection latencies (seconds) — from paper Table I/II
_DET_LATENCY = {
    "no_defense": None,
    "taada":      4.2,
    "ensemble":   3.1,
    "tig_cdo":    1.8,
}

# ---------------------------------------------------------------------------
# Scenario simulation
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    config: str
    tps: int
    csda_phase: int
    intensity: str
    n_processed: int = 0
    n_sla_ok: int = 0
    n_legit_rejected: int = 0
    n_attack_blocked: int = 0
    n_attack_total: int = 0
    n_legit_total: int = 0
    detection_latency_s: Optional[float] = None

    @property
    def sla_pct(self):
        return 100.0 * self.n_sla_ok / max(1, self.n_processed)

    @property
    def fpr_pct(self):
        # v1.2.0: share of legitimate transactions blocked. Denominator is the
        # number of legitimate transactions offered (R1-009 fix).
        return 100.0 * self.n_legit_rejected / max(1, self.n_legit_total)

    @property
    def legit_tps(self):
        # Effective legitimate TPS, normalized to 1000 TPS reference tier.
        #
        # Two components:
        #   1. SLA-compliant transactions (legit_ok_frac × 1000)
        #   2. Freed server capacity from blocked attack traffic
        #      Each blocked attack tx frees resources for CAPACITY_GAIN=1.75 legit txs.
        #      Under TIG-CDO (95% block, heavy 45% attack): freed ≈ 0.427×1.75 = 0.748
        #      Combined: (0.573 + 0.748) × 1000 ≈ 1321 TPS/scenario → aggregate ≈ 1198.
        #
        # This models the paper's claim that TIG-CDO achieves 1198 TPS > 1000 baseline
        # by eliminating 95% of attack traffic that was wasting server resources.
        _CAPACITY_GAIN = 1.75
        n_total = self.n_processed + self.n_attack_blocked
        if n_total == 0:
            return 0.0
        legit_ok_frac = self.n_sla_ok / n_total
        freed_frac = (self.n_attack_blocked / n_total) * _CAPACITY_GAIN
        return (legit_ok_frac + freed_frac) * 1000


def run_scenario(
    config: str, tps: int, csda_phase: int, intensity: str, n_samples: int = 400,
    rng: Optional[random.Random] = None,
) -> ScenarioResult:
    """Simulate n_samples transactions for given config and attack condition.

    Only two arguments affect the computation: whether an attack is active
    (csda_phase > 0) and the intensity. `tps` and the value of `csda_phase`
    are recorded as labels only (v1.2.0, R1-008).
    """
    rng = rng or random
    eff_intensity = intensity if csda_phase > 0 else "none"
    attack_frac = _ATTACK_FRAC[eff_intensity]
    is_attack_active = csda_phase > 0
    block_rate = _ATTACK_BLOCK[config] if is_attack_active else 0.0
    fpr_rate = _FPR[config] if is_attack_active else 0.0
    det_latency = _DET_LATENCY[config] if is_attack_active else None

    # Residual attack load = fraction of capacity consumed after blocking.
    # This drives server saturation: when residual_load > SATURATION_THRESHOLD,
    # ALL transactions (legit + attack) experience elevated latency.
    residual_load = attack_frac * (1.0 - block_rate) if is_attack_active else 0.0

    r = ScenarioResult(
        config=config, tps=tps, csda_phase=csda_phase,
        intensity=eff_intensity, detection_latency_s=det_latency
    )

    for _ in range(n_samples):
        is_attack_tx = is_attack_active and (rng.random() < attack_frac)

        if is_attack_tx:
            r.n_attack_total += 1
            # PSRG/defense blocks most attack traffic at gateway
            if rng.random() < block_rate:
                r.n_attack_blocked += 1
                continue

        # Transaction enters service
        r.n_processed += 1
        if not is_attack_tx:
            r.n_legit_total += 1

        # False positive: legitimate tx incorrectly blocked
        if not is_attack_tx and rng.random() < fpr_rate:
            r.n_legit_rejected += 1
            continue  # blocked, does not get SLA measurement

        # SLA evaluation — pass residual_load so saturation model applies to all tx
        lat = sample_latency(config, is_attack_active, residual_load, rng)
        if lat <= SLA_BUDGET_MS:
            r.n_sla_ok += 1

    return r


# CSDA attack conditions that actually change the computation.
CSDA_CONDITIONS = ["none", "light", "moderate", "heavy"]


def clopper_pearson_pct(k: int, n: int, conf: float = 0.95) -> Optional[List[float]]:
    """Exact (Clopper-Pearson) two-sided interval for k/n, in percent."""
    if n <= 0:
        return None
    from scipy.stats import beta as _beta
    a = (1.0 - conf) / 2.0
    lo = 0.0 if k == 0 else float(_beta.ppf(a, k, n - k + 1))
    hi = 1.0 if k == n else float(_beta.ppf(1.0 - a, k + 1, n - k))
    return [round(100.0 * lo, 4), round(100.0 * hi, 4)]


def csda_run_schedule() -> List[Tuple[str, int, int]]:
    """Run order of the CSDA comparison: (intensity, replicate_label_phase,
    replicate_label_tps). It reproduces the v1.1.0 loop order exactly, so the
    seed-42 random stream (and every SLA value) is unchanged. Phase and TPS are
    replicate labels only; they do not enter run_scenario's computation.
    Result: 3 no-attack replicates + 12 replicates of each attack intensity
    = 39 runs per configuration, 4 distinct conditions."""
    sched: List[Tuple[str, int, int]] = []
    tps_labels = [1000, 10000, 50000]
    for tps in tps_labels:
        sched.append(("none", 0, tps))
    for phase in [1, 2, 3, 4]:
        for intensity in ["light", "moderate", "heavy"]:
            for tps in tps_labels:
                sched.append((intensity, phase, tps))
    return sched


def run_csda_evaluation() -> Dict[str, Dict]:
    """CSDA configuration comparison: 4 conditions x replicates x 4 configs.

    Returns, per configuration, the run-mean SLA and FPR (as in v1.1.0, now with
    the corrected FPR denominator), pooled legitimate-transaction counts so an
    exact interval can be computed, the FPR over attack runs only (the defenses
    apply their configured false-positive probability only while an attack is
    active), and per-condition breakdowns.
    """
    configs = ["no_defense", "taada", "ensemble", "tig_cdo"]
    sched = csda_run_schedule()
    result: Dict[str, Dict] = {}
    for cfg in configs:
        sla, fpr, det, tps_v = [], [], [], []
        pooled = {"legit": 0, "rejected": 0, "legit_attack_runs": 0, "rejected_attack_runs": 0}
        per_cond: Dict[str, Dict] = {c: {"sla": [], "fpr": [], "legit": 0, "rejected": 0}
                                     for c in CSDA_CONDITIONS}
        rng = config_rng(cfg, "csda")
        for intensity, phase, tps in sched:
            r = run_scenario(cfg, tps, phase, intensity, n_samples=400, rng=rng)
            sla.append(r.sla_pct)
            fpr.append(r.fpr_pct)
            if r.detection_latency_s is not None:
                det.append(r.detection_latency_s)
            if tps == 1000:
                tps_v.append(r.legit_tps)
            pooled["legit"] += r.n_legit_total
            pooled["rejected"] += r.n_legit_rejected
            if intensity != "none":
                pooled["legit_attack_runs"] += r.n_legit_total
                pooled["rejected_attack_runs"] += r.n_legit_rejected
            pc = per_cond[intensity]
            pc["sla"].append(r.sla_pct); pc["fpr"].append(r.fpr_pct)
            pc["legit"] += r.n_legit_total; pc["rejected"] += r.n_legit_rejected
        attack_fpr_runs = [f for (i, _, _), f in zip(sched, fpr) if i != "none"]
        result[cfg] = {
            "sla_compliance_pct": round(sum(sla) / len(sla), 1),
            "fpr_pct": round(sum(fpr) / len(fpr), 3),
            "fpr_pct_attack_runs": round(sum(attack_fpr_runs) / len(attack_fpr_runs), 3),
            "fpr_pooled_pct_attack_runs": round(
                100.0 * pooled["rejected_attack_runs"] / max(1, pooled["legit_attack_runs"]), 4),
            "fpr_pooled_ci95_pct_attack_runs": clopper_pearson_pct(
                pooled["rejected_attack_runs"], pooled["legit_attack_runs"]),
            "legit_rejected_attack_runs": pooled["rejected_attack_runs"],
            "legit_total_attack_runs": pooled["legit_attack_runs"],
            "legit_rejected_all_runs": pooled["rejected"],
            "legit_total_all_runs": pooled["legit"],
            "configured_fpr_pct": round(_FPR[cfg] * 100, 3),
            "detection_latency_s": round(sum(det) / len(det), 1) if det else None,
            "legitimate_tps": round(sum(tps_v) / len(tps_v), 0),
            "runs": len(sla),
            "distinct_conditions": len(CSDA_CONDITIONS),
            "per_condition": {
                c: {"runs": len(v["sla"]),
                    "sla_compliance_pct": round(sum(v["sla"]) / len(v["sla"]), 2),
                    "fpr_pct": round(sum(v["fpr"]) / len(v["fpr"]), 3),
                    "legit_rejected": v["rejected"], "legit_total": v["legit"]}
                for c, v in per_cond.items()},
        }
    return result


# Backward-compatible name used by v1.1.0 callers. The old name's "270" was a
# stale label; the comparison runs 39 replicate runs of 4 conditions per config.
run_270_scenario_evaluation = run_csda_evaluation


# ---------------------------------------------------------------------------
# FDCE (Federated Declined-Card Exhaustion) sub-variant evaluation
# ---------------------------------------------------------------------------
#
# FDCE: bots posing as merchant terminals submit bulk expired/damaged card
# credentials, flooding the authorization processor with declines.
# v1.3.0: each grid cell runs fdce.scenario.simulate_fdce_scenario with the v1.3.0
# detector (R-11 baseline-excess statistic, censoring-aware R-12), single-message
# flow, 120 s per run; the replication over seeds is in experiments/.
# Unlike volumetric CSDA, FDCE attacks the *auth capacity* rather than the
# network layer — individual-layer thresholds are never exceeded.
#
# 30 scenarios: 3 cluster sizes (50, 200, 500 merchant terminals)
#             × 2 card-damage types (expired_only, mixed)
#             × 5 intensities (20–100% of authorization service capacity)
#
# Detection (TIG-CDO only):
#   R-11: >80% decline codes {14,54,57,82} in BIN window → triggers in 44–62s
#   R-12: 0100→0200 completion rate <5% at >100 txn/min per merchant cluster
#   PSRG: pre-blocks 65–81% before PADO activation (avg 73%)
#   No individual-layer threshold exceeded → composite-only detection
#
# TAADA, Ensemble: no FDCE-specific detection rules → full auth load sustained.

# v2 (finding C7): TIG-CDO's FDCE block rate/detection latency are no longer
# hardcoded -- they are computed per-scenario by fdce/scenario.py, which runs
# real R-11/R-12 detectors (fdce/fdce.py) against simulated bot + organic
# traffic. See FDCE_RULE_ENGINE_REPORT.md for the full 30-scenario grid and
# the adversarial decline-spreading robustness check. Baselines (no_defense,
# TAADA, ensemble) have no FDCE-specific detection capability -- unchanged
# from v1 -- so they stay at a flat 0.00.
_FDCE_BLOCK_BASELINE = {"no_defense": 0.00, "taada": 0.00, "ensemble": 0.00}
_FDCE_DET_S_BASELINE = {"no_defense": None, "taada": None, "ensemble": None}

# Maximum auth-service latency inflation at 100% intensity with no defense.
# FDCE saturates the auth processor; each unblocked request adds queuing delay.
FDCE_MAX_AUTH_LAT_MS = 40.0

FDCE_INTENSITIES    = [0.20, 0.40, 0.60, 0.80, 1.00]
FDCE_CLUSTER_SIZES  = [50, 200, 500]
FDCE_CARD_TYPES     = ["expired_only", "mixed"]


def run_fdce_evaluation() -> Dict[str, Dict]:
    """
    30 FDCE scenarios per config: cluster_size × card_type × intensity.

    FDCE raises auth-service latency proportional to residual unblocked load.
    v2 (finding C7): for tig_cdo, block_rate and detection_latency_s are no
    longer hardcoded -- each of the 30 scenarios runs the real R-11/R-12
    detector (fdce/scenario.py) against simulated bot+organic traffic. See
    FDCE_RULE_ENGINE_REPORT.md.
    """
    configs = ["no_defense", "taada", "ensemble", "tig_cdo"]
    result: Dict[str, Dict] = {}

    for cfg in configs:
        sla_vals: List[float] = []
        det_vals: List[float] = []
        block_vals: List[float] = []
        rules: List[str] = []
        rng = config_rng(cfg, "fdce")

        for cluster_size in FDCE_CLUSTER_SIZES:
            for card_type in FDCE_CARD_TYPES:
                for intensity in FDCE_INTENSITIES:
                    if cfg == "tig_cdo":
                        fdce_result = simulate_fdce_scenario(
                            cluster_size, card_type, intensity,
                            seed=SEED + cluster_size + int(intensity * 100))
                        fdce_block = fdce_result.block_rate
                        if fdce_result.detection_latency_s is not None:
                            det_vals.append(fdce_result.detection_latency_s)
                            rules.append(fdce_result.triggered_rule)
                    else:
                        fdce_block = _FDCE_BLOCK_BASELINE[cfg]
                    residual     = intensity * (1.0 - fdce_block)
                    block_vals.append(fdce_block)

                    # Auth-service latency inflation from unblocked FDCE load
                    lat_inflate  = residual * FDCE_MAX_AUTH_LAT_MS
                    # Mixed card types have higher latency variance (more varied decline processing)
                    extra_std    = 4.0 if card_type == "mixed" else 2.0

                    mean_l, std_l = _LATENCY_PARAMS[cfg][:2]
                    fdce_mean    = mean_l + lat_inflate
                    fdce_std     = std_l + extra_std

                    # FPR active only when residual FDCE load is significant
                    fpr_rate     = _FPR[cfg] if residual > 0.05 else 0.0

                    n_samples = 400
                    n_sla_ok  = 0
                    for _ in range(n_samples):
                        if rng.random() < fpr_rate:
                            continue
                        lat = rng.gauss(fdce_mean, fdce_std)
                        if lat <= SLA_BUDGET_MS:
                            n_sla_ok += 1

                    sla_vals.append(100.0 * n_sla_ok / n_samples)

        result[cfg] = {
            "sla_compliance_pct":  round(sum(sla_vals) / len(sla_vals), 1),
            "detection_latency_s": round(sum(det_vals) / len(det_vals), 2) if det_vals else None,
            "mean_block_rate":     round(sum(block_vals) / len(block_vals), 4),
            "scenarios_run":       len(sla_vals),   # 30
            "detected_cells":      len(det_vals),
            "first_rule_counts":   {r: rules.count(r) for r in sorted(set(rules))},
            "duration_s":          120.0,
        }

    return result


# ---------------------------------------------------------------------------
# CSDA phase detection test (Table I)
# ---------------------------------------------------------------------------

PHASE1_TCS_THRESHOLD = 0.50     # STC alarm threshold (S1 Table S1)
PHASE1_MIN_SEQUENCES = 20
PHASE3_SIGNALS = dict(s1_waf=0.12, s2_lbmd=0.18, s3_bin_watch=0.22, s4_acs_guard=0.31, s5_hpa_delta=0.14)
PHASE3_TCS = 0.23               # configured coherence at the Phase-3 point (not an STC output)
PHASE4_TCS_CHANGE_PER_HOUR = 0.04   # configured value, not an output


def run_phase1(layout: str, days: int = 7, flow: str = "dual_0220") -> Dict:
    """CSDA Phase 1 with every probe answered (v1.3.0, R3-006).

    Legitimate traffic: 200 sequences per hour on BIN 411111 (0100, approved
    0110, 0220 advice 25 s later). Reconnaissance from day 1: 100 probes per
    hour, each answered: 94% declined (code 14 at 70%, 54 at 30%), 6% approved
    and never captured or reversed. layout "shared": probes use BIN 411111, the
    family that carries the legitimate traffic; layout "own": probes use BIN
    555555, a family with no legitimate traffic (the v1.2 layout). TCS is
    evaluated hourly over W = 3600 s; detection is TCS < 0.50 with at least 20
    resolved sequences."""
    rng = random.Random(SEED)
    stc = SemanticTransactionCorrelator(window_s=3600.0, flow=flow, rho_star=0.50,
                                        decline_baseline={"411111": 0.0, "555555": 0.12})
    probe_bin = "411111" if layout == "shared" else "555555"
    DAY, HOUR = 86400.0, 3600.0
    first = None
    hourly = []
    for day in range(days):
        for hour in range(24):
            ts = day * DAY + hour * HOUR
            for i in range(200):
                e_ts = ts + i * 18.0
                stan = f"LS{day:02d}{hour:02d}{i:03d}"
                kw = dict(bin_prefix="411111", terminal_id="T_LEGIT", source_ip=f"172.16.{(i % 50) + 1}.1",
                          stan=stan, amount=49.0)
                stc.ingest_event(PaymentEvent(f"l_0100_{stan}", EventType.ISO_0100, timestamp=e_ts, **kw))
                stc.ingest_event(PaymentEvent(f"l_0110_{stan}", EventType.ISO_0110, timestamp=e_ts + 0.8,
                                              response_code="00", **kw))
                stc.ingest_event(PaymentEvent(f"l_0220_{stan}", EventType.ISO_0220, timestamp=e_ts + 25.0, **kw))
            if day >= 1:
                for i in range(100):
                    e_ts = ts + i * 36.0
                    stan = f"AS{day:02d}{hour:02d}{i:03d}"
                    u = rng.random()
                    code = "00" if u < 0.06 else ("14" if rng.random() < 0.70 else "54")
                    kw = dict(bin_prefix=probe_bin, terminal_id="T_RECON",
                              source_ip=f"10.{(i * 7) % 256}.{(i * 3) % 256}.1", stan=stan, amount=49.0)
                    stc.ingest_event(PaymentEvent(f"a_0100_{stan}", EventType.ISO_0100, timestamp=e_ts, **kw))
                    stc.ingest_event(PaymentEvent(f"a_0110_{stan}", EventType.ISO_0110, timestamp=e_ts + 0.5,
                                                  response_code=code, **kw))
            r = stc.compute_tcs(probe_bin, ts + HOUR)
            hourly.append((day + (hour + 1) / 24.0, r.tcs, r.tcs_str, r.tcs_dst))
            if (day >= 1 and first is None and r.total_sequences >= PHASE1_MIN_SEQUENCES
                    and r.tcs < PHASE1_TCS_THRESHOLD):
                first = {"day": round(day + (hour + 1) / 24.0, 3), "tcs": round(r.tcs, 4),
                         "tcs_str": round(r.tcs_str, 4), "tcs_dst": round(r.tcs_dst, 4),
                         "resolved": r.total_sequences, "coherent": r.coherent_sequences,
                         "anomalies": r.anomaly_distribution,
                         "decline_excess": None if r.watched_share is None else round(r.watched_share, 4),
                         "completion_bound": None if r.completion_rate is None else round(r.completion_rate, 4)}
    att = [h for h in hourly if h[0] > 2.0]          # after day 2, steady state
    legit = stc.compute_tcs("411111", days * DAY) if layout == "own" else None
    return {
        "layout": layout, "flow": flow,
        "detected": first is not None, "first_detection": first,
        "steady_state_after_day2": {
            "tcs_min": round(min(h[1] for h in att), 4), "tcs_mean": round(sum(h[1] for h in att) / len(att), 4),
            "tcs_str_mean": round(sum(h[2] for h in att) / len(att), 4),
            "tcs_dst_mean": round(sum(h[3] for h in att) / len(att), 4)},
        "legitimate_family_tcs_end": None if legit is None else round(legit.tcs, 4),
    }


def run_phase_detection_test(no_defense_baseline: Optional[Dict] = None) -> Dict[str, Dict]:
    """Phase-by-phase exercise of the implemented components (Table 8, Section 5.1)."""
    random.seed(SEED)
    clcs_engine = CLCSEngine()
    bim = BaselineIntegrityMonitor()
    pado = PreAuthorizedDefenseOrchestrator()
    DAY = 86400.0
    HOUR = 3600.0
    results = {}

    print("\n[Phase 1] Reconnaissance, every probe answered (94% declined, 6% approved, none captured)...")
    results["phase1"] = {lay: run_phase1(lay) for lay in ("shared", "own")}
    for lay, r in results["phase1"].items():
        print(f"  layout={lay}: detected={r['detected']} first={r['first_detection']} "
              f"steady={r['steady_state_after_day2']}")

    # Phase 2: BIM. The harness keeps a 200-day checkpoint interval so that the
    # clean day-0 reference survives Phase 2 (default interval: 7 days).
    CHECKPOINT_OVERRIDE_DAYS = 200
    bim.CHECKPOINT_INTERVAL_S = CHECKPOINT_OVERRIDE_DAYS * DAY
    bim_rng = random.Random(SEED)
    bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, mu0_js=BIM_MU0_JS, k=BIM_K, h=BIM_H,
                        timestamp=0.0, seed_distribution=BIM_SEED_DIST)
    for day in range(7):
        _bim_observe_entropy_target(bim, _bim_organic_entropy(day, bim_rng), day * DAY + 23 * HOUR, bim_rng)

    print("\n[Phase 2] Baseline poisoning: 2.8%/day entropy-equivalent drift from day 8...")
    phase2_detect_day: Optional[float] = None
    alarm_info = None
    PHASE2_ONSET_DAY = 8
    for day in range(14):
        abs_day = PHASE2_ONSET_DAY + day
        ts = abs_day * DAY
        seasonal = _bim_organic_entropy(abs_day, bim_rng) - BIM_MU0_ENTROPY_BITS
        target_entropy = BIM_MU0_ENTROPY_BITS + seasonal + (day + 1) * (0.028 * BIM_MU0_ENTROPY_BITS)
        alarm = _bim_observe_entropy_target(bim, target_entropy, ts, bim_rng)
        if alarm is not None and phase2_detect_day is None:
            phase2_detect_day = float(abs_day)
            alarm_info = alarm
            print(f"  Phase 2 alarm on day {phase2_detect_day:.0f}: JS={alarm.js_divergence:.5f}, "
                  f"monitor drift estimate={alarm.drift_rate_per_day * 100:.1f}%/day, "
                  f"placeholder peer rule={alarm.fs_isac_decision.value}")
    results["phase2"] = {
        "detection_day": phase2_detect_day,
        "injected_drift_rate_pct_per_day": 2.8,
        "monitor_drift_estimate_pct_per_day": round(alarm_info.drift_rate_per_day * 100, 2) if alarm_info else None,
        "placeholder_peer_rule_decision": alarm_info.fs_isac_decision.value if alarm_info else None,
        "checkpoint_interval_override_days": CHECKPOINT_OVERRIDE_DAYS,
        "mechanism": "BIM one-sided JS-divergence CUSUM vs week-aligned reference; rollback resets "
                     "the CUSUM only; the peer rule is a placeholder threshold on the monitor's own estimate",
    }

    print("\n[Phase 3] Configured composite point, with and without the issuer-side ACS signal s4...")
    attack_scores = LayerScores(timestamp=22 * DAY, bin_prefix="555555", **PHASE3_SIGNALS)
    r3 = clcs_engine.evaluate(attack_scores, tcs=PHASE3_TCS)
    w = CLCSConfig().w_base
    sv = [PHASE3_SIGNALS[k] for k in ("s1_waf", "s2_lbmd", "s3_bin_watch", "s4_acs_guard", "s5_hpa_delta")]
    w_no4 = sum(w[i] * sv[i] for i in (0, 1, 2, 4))
    w_no4_renorm = w_no4 / (1.0 - w[3])
    a = 1.0 + CLCSConfig().beta_tcs * (1.0 - PHASE3_TCS)
    proc_only = {"W_unnormalized": round(w_no4, 4), "clcs_unnormalized": round(min(1.0, w_no4 * a), 4),
                 "W_renormalized": round(w_no4_renorm, 4), "clcs_renormalized": round(min(1.0, w_no4_renorm * a), 4),
                 "activates": min(1.0, w_no4_renorm * a) > CLCSConfig().theta_clcs,
                 "beta_needed_renormalized": round((CLCSConfig().theta_clcs / w_no4_renorm - 1.0) / (1.0 - PHASE3_TCS), 3)}
    print(f"  s4 shared: W={r3.base_weighted_sum:.4f}, A={r3.tcs_amplification:.3f}, CLCS={r3.clcs:.3f}")
    print(f"  processor only (no s4): {proc_only}")

    context = TIGContext(
        timestamp=22 * DAY, clcs=r3.clcs, tcs_distribution={"555555": PHASE3_TCS},
        mean_tcs=PHASE3_TCS, min_tcs=PHASE3_TCS,
        active_vectors={"bin_recon", "3ds_flood", "auth_flood", "token_abuse", "ecos"},
        bim_alarm_active=False, hpa_scaling_active=True, tps_tier="50k",
    )
    if no_defense_baseline is not None:
        current_sla_pct = no_defense_baseline["sla_compliance_pct"]
        current_tps = float(no_defense_baseline["legitimate_tps"])
    else:
        current_sla_pct, current_tps = 41.2, 623.0
    pado_rec = pado.activate(context, current_sla_pct=current_sla_pct, current_tps=current_tps)

    results["phase3"] = {
        "signals": PHASE3_SIGNALS, "tcs_configured": PHASE3_TCS,
        "s4_shared": {"clcs": round(r3.clcs, 4), "base_weighted_sum": round(r3.base_weighted_sum, 4),
                      "tcs_amplification": round(r3.tcs_amplification, 4), "triggered": r3.triggered,
                      "composite_only": r3.composite_only},
        "processor_only_no_s4": proc_only,
        "pado_bundle": pado_rec.bundle_id if pado_rec else None,
        "pado_audit_article": pado_rec.governance_dora_article if pado_rec else None,
    }
    results["phase4"] = {
        "tcs_change_rate_per_hour_configured": PHASE4_TCS_CHANGE_PER_HOUR,
        "status": "configured value; Phase 4 is not simulated",
    }
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("TIG-CDO Evaluation — Paper Tables I and II")
    print("=" * 70)
    t0 = time.time()

    print("\n[1/3] CSDA configuration comparison (4 conditions, 39 replicate runs per configuration)...")
    t2 = run_csda_evaluation()

    print("\n[2/3] 30-scenario FDCE sub-variant evaluation...")
    fdce = run_fdce_evaluation()

    labels = {
        "no_defense": "No defense",
        "taada":      "TAADA-only",
        "ensemble":   "ACS-GUARD+BIN-WATCH",
        "tig_cdo":    "TIG-CDO",
    }

    # The comparison table uses the CSDA-only runs (4 conditions, 39 runs per configuration).
    # FDCE results are reported separately below (Section VI-C in the paper).
    combined = t2  # alias for validation section below

    print("\n" + "=" * 70)
    print("CSDA configuration comparison (4 distinct conditions; 39 replicate runs per configuration)")
    print("=" * 70)
    print(f"  {'Configuration':<24} {'SLA%':>6} {'FPR%':>8} {'FPR%atk':>8} {'cfgFPR%':>8} {'Det(s)':>8} {'TPS@1K*':>8}")
    print("  " + "-" * 78)
    for cfg in ["no_defense", "taada", "ensemble", "tig_cdo"]:
        m = t2[cfg]
        det_str = f"{m['detection_latency_s']:.1f}s" if m['detection_latency_s'] else "N/A"
        fpr_str = f"{m['fpr_pct']:.3f}%" if m['fpr_pct'] else "N/A"
        fpa_str = f"{m['fpr_pct_attack_runs']:.3f}%" if m['fpr_pct_attack_runs'] else "N/A"
        print(f"  {labels[cfg]:<24} {m['sla_compliance_pct']:>5.1f}% {fpr_str:>8} {fpa_str:>8} "
              f"{m['configured_fpr_pct']:>7.3f}% {det_str:>8} {int(m['legitimate_tps']):>8}")
    print("  FPR% = mean over all 39 runs (no-attack runs apply no false positives);")
    print("  FPR%atk = mean over the 36 attack runs; cfgFPR% = configured probability.")
    print("  * TPS@1K includes a configured capacity-recovery coefficient (1.75); not a throughput measurement.")

    print("\n  Calibration targets (paper v1 main.md, pre-2026-08-16 -- NOT independently")
    print("  measured; see CALIBRATION_TARGETS docstring note at top of file):")
    print(f"  {'No defense':<24} {'41.2%':>6} {'N/A':>8} {'N/A':>8} {'623':>8}")
    print(f"  {'TAADA-only':<24} {'78.4%':>6} {'2.3%':>8} {'4.2s':>8} {'891':>8}")
    print(f"  {'ACS-GUARD+BIN-WATCH':<24} {'84.1%':>6} {'1.8%':>8} {'3.1s':>8} {'943':>8}")
    print(f"  {'TIG-CDO':<24} {'98.3%':>6} {'0.08%':>8} {'1.8s':>8} {'1198':>8}")

    print("\n  Delta (realized - target), SLA percentage points:")
    for cfg in ["no_defense", "taada", "ensemble", "tig_cdo"]:
        realized_sla = t2[cfg]["sla_compliance_pct"]
        target_sla = CALIBRATION_TARGETS[cfg][0]
        print(f"  {labels[cfg]:<24} {realized_sla - target_sla:+.1f} pp")
    gap_realized = t2["tig_cdo"]["sla_compliance_pct"] - t2["ensemble"]["sla_compliance_pct"]
    gap_target = CALIBRATION_TARGETS["tig_cdo"][0] - CALIBRATION_TARGETS["ensemble"][0]
    print(f"\n  TIG-CDO vs. best baseline SLA gap: {gap_target:.1f}pp (target) vs. "
          f"{gap_realized:.1f}pp (realized)")

    print("\n" + "=" * 70)
    print("FDCE Sub-Variant (30 scenarios: 3 clusters × 2 card-types × 5 intensities)")
    print("=" * 70)
    print(f"  {'Configuration':<24} {'FDCE SLA%':>10} {'Det (s)':>10}  Notes")
    print("  " + "-" * 65)
    for cfg in ["no_defense", "taada", "ensemble", "tig_cdo"]:
        fd = fdce[cfg]
        fdet = f"{fd['detection_latency_s']:.1f}" if fd['detection_latency_s'] else "—"
        block_pct = f"{fd['mean_block_rate']*100:.1f}%"
        note = (f"R-11/R-12 live detector, mean block={block_pct}" if cfg == "tig_cdo"
                else "no card-exhaustion detection")
        print(f"  {labels[cfg]:<24} {fd['sla_compliance_pct']:>9.1f}% {fdet:>10}  {note}")
    print(f"\n  v2: block rate and detection latency are now genuinely computed per scenario")
    print(f"  by fdce/scenario.py (real R-11/R-12 detectors), not hardcoded constants.")

    print("\n[3/3] CSDA phase detection (Table I)...")
    t1 = run_phase_detection_test(no_defense_baseline=t2["no_defense"])

    print("\n" + "=" * 70)
    print("TABLE I: TIG-CDO CSDA Phase Detection")
    print("=" * 70)

    p1 = t1["phase1"]
    p2_d = t1["phase2"]["detection_day"]
    p3 = t1["phase3"]["s4_shared"]
    p3p = t1["phase3"]["processor_only_no_s4"]

    for lay in ("shared", "own"):
        print(f"\n  Phase 1 ({lay} BIN family): detected={p1[lay]['detected']} "
              f"first={p1[lay]['first_detection']}")
    print(f"  Phase 2 (Baseline Poisoning): Day {p2_d}")
    print(f"  Phase 3 (configured point): CLCS={p3['clcs']} with s4; "
          f"{p3p['clcs_renormalized']} without s4 (renormalized)")
    print(f"  Phase 4: configured TCS change rate {t1['phase4']['tcs_change_rate_per_hour_configured']}/hour")

    print("\n" + "=" * 70)
    print("SELF-CHECKS OF THIS HARNESS (informational; not tests of the design)")
    print("=" * 70)

    tig = t2["tig_cdo"]
    checks = [
        ("TIG-CDO SLA > Ensemble (configured comparison)",
         tig["sla_compliance_pct"] > t2["ensemble"]["sla_compliance_pct"], ""),
        ("FDCE grid: every cell detected", fdce["tig_cdo"]["detected_cells"] == fdce["tig_cdo"]["scenarios_run"],
         f"{fdce['tig_cdo']['detected_cells']}/{fdce['tig_cdo']['scenarios_run']}"),
        ("Phase 1 detected, probes in own family", p1["own"]["detected"], ""),
        ("Phase 1 detected, probes inside the legitimate family", p1["shared"]["detected"], ""),
        ("Phase 2 alarm within the 14-day window", isinstance(p2_d, float) and p2_d <= 21, f"day={p2_d}"),
        ("Phase 3 activates with s4", p3["triggered"], f"CLCS={p3['clcs']}"),
        ("Phase 3 activates without s4", p3p["activates"], f"CLCS={p3p['clcs_renormalized']}"),
    ]
    passed = 0
    for label, ok, note in checks:
        if ok:
            passed += 1
        suffix = f"  [{note}]" if note else ""
        print(f"  [{'yes' if ok else 'no '}] {label}{suffix}")
    print(f"\n  {passed}/{len(checks)} self-checks true")

    # 50-seed Monte Carlo dispersion (added 2026-08-16 -- previously computed by
    # run_followup_analyses.py into followup_analyses.json but never surfaced here;
    # consolidated review finding C2 notes this band never contains the calibration
    # targets above, which is the clearest evidence the gap is structural, not seed noise).
    print("\n" + "=" * 70)
    print("50-SEED MONTE CARLO DISPERSION (Monte Carlo sampling noise around the fixed")
    print("configured constants above -- NOT parameter/measurement uncertainty)")
    print("=" * 70)
    try:
        import json as _json
        _followup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "followup_analyses.json")
        with open(_followup_path) as _f:
            _bands = _json.load(_f)["C_nseed_dispersion"]["bands"]
        _rows = [
            ("TIG-CDO SLA%",   _bands["sla"],       CALIBRATION_TARGETS["tig_cdo"][0]),
            ("TIG-CDO FPR%",   _bands["fpr"],        CALIBRATION_TARGETS["tig_cdo"][1]),
            ("TIG-CDO TPS",    _bands["tps"],        CALIBRATION_TARGETS["tig_cdo"][3]),
            ("No-defense SLA%", _bands["nd_sla"],    CALIBRATION_TARGETS["no_defense"][0]),
            ("TAADA SLA%",     _bands["taada_sla"],  CALIBRATION_TARGETS["taada"][0]),
            ("Ensemble SLA%",  _bands["ensemble_sla"], CALIBRATION_TARGETS["ensemble"][0]),
            ("FDCE SLA%",      _bands["fdce_sla"],   None),
        ]
        for name, band, target in _rows:
            in_band = (target is not None) and (band["min"] <= target <= band["max"])
            flag = "" if target is None else ("  [target IN band]" if in_band else "  [target OUTSIDE band]")
            print(f"  {name:<16} n=50  [{band['min']:.3f}, {band['max']:.3f}]  "
                  f"mean={band['mean']:.3f}{flag}")
    except (FileNotFoundError, KeyError) as _e:
        print(f"  (dispersion bands unavailable: {_e})")

    # Machine-readable results (v1.2.0). Written to the working directory so a
    # clean-copy re-run does not overwrite the archived file in place.
    import json as _json_out
    _out = os.environ.get("TIGCDO_RESULTS_OUT", "tigcdo_eval_results.json")
    with open(_out, "w") as _fo:
        _json_out.dump({
            "seed": SEED,
            "csda_comparison": t2,
            "fdce_comparison": fdce,
            "phase_detection": t1,
            "self_checks": {label: bool(ok) for label, ok, _ in checks},
        }, _fo, indent=1, default=str)
    print(f"\nResults written to {_out}")

    print(f"\nTotal runtime: {time.time() - t0:.1f}s")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
