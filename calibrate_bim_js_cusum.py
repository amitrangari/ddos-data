#!/usr/bin/env python3
"""
calibrate_bim_js_cusum.py  (Paper 2 TIG-CDO — BIM v2, finding C6)

Empirically calibrates the JS-divergence one-sided CUSUM chart in bim/bim.py:
  - mu0_js: expected organic JS divergence against the week-aligned reference
  - k: CUSUM allowance
  - h: CUSUM decision interval

Unlike the v1 scalar-mean CUSUM (CUSUMState.calibrate() in the old bim.py),
JS divergence of a finite-sample categorical distribution doesn't have a clean
closed form, so this is done by Monte Carlo: simulate the organic (no-attack)
scenario with realistic weekday/weekend seasonality, measure the resulting
JS-divergence distribution against the week-aligned reference, and pick
mu0_js/k/h from that empirical distribution. Then verify against the CSDA
poisoning scenarios (1.5%/day, 2.8%/day, 4.0%/day entropy-equivalent drift,
matching the original Table IV structure) that detection still works within a
similar horizon to v1, and that false alarms on organic traffic stay low.

Organic seasonality model: entropy oscillates by day-of-week (weekday vs.
weekend BIN-lookup mix differs), consistent with CESNET-TLS-Year22's own
finding of real weekly service-mix seasonality (calibrate_drift_from_real_data.py).
"""
import random
import sys
import os
import json

sys.path.insert(0, os.path.dirname(__file__))
from bim.bim import (
    BaselineIntegrityMonitor, BaselineStat, js_divergence, zipf_distribution,
    zipf_s_for_entropy, sample_categorical_counts, shannon_entropy_bits,
    SECONDS_PER_DAY,
)

K = 50
N_SAMPLES = 2000
MU0_ENTROPY = 1.80          # organic baseline entropy, bits (matches v1's mu0)
WEEKDAY_AMPLITUDE = 0.06    # organic weekday/weekend entropy oscillation, bits
S0 = zipf_s_for_entropy(K, MU0_ENTROPY)
SEED_DIST = zipf_distribution(K, S0)


def organic_entropy(day_index: int, rng: random.Random) -> float:
    """Organic entropy for a given absolute day: base + weekly seasonality
    (weekend = higher entropy, more varied lookups) + small daily noise."""
    dow = day_index % 7
    weekend_boost = WEEKDAY_AMPLITUDE if dow >= 5 else -WEEKDAY_AMPLITUDE * 0.4
    noise = rng.gauss(0, 0.02)
    return MU0_ENTROPY + weekend_boost + noise


def run_organic_scenario(n_days: int, seed: int, mu0_js: float, k: float, h: float):
    """No-attack scenario: does the monitor stay quiet?"""
    rng = random.Random(seed)
    bim = BaselineIntegrityMonitor(seed=seed)
    bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, mu0_js, k, h, 0.0, SEED_DIST)
    js_values = []
    alarm_day = None
    for day in range(n_days):
        ts = float(day * SECONDS_PER_DAY)
        h_target = organic_entropy(day, rng)
        s = zipf_s_for_entropy(K, h_target)
        dist = zipf_distribution(K, s)
        observed = sample_categorical_counts(dist, N_SAMPLES, rng)
        dow = day % 7
        ref = bim.week_ref[BaselineStat.BIN_WATCH_ENTROPY].get(dow, SEED_DIST)
        js_values.append(js_divergence(observed, ref))
        alarm = bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, observed, ts)
        if alarm is not None and alarm_day is None:
            alarm_day = day
    return js_values, alarm_day


def run_poisoning_scenario(drift_pct_per_day: float, n_days: int, seed: int,
                            mu0_js: float, k: float, h: float, warmup_days: int = 28):
    """Warmup (organic, with seasonality, long enough for week-aligned
    references to populate all 7 day-of-week buckets several times over),
    then linear entropy drift starting at warmup_days, matching the original
    Table IV parametrization (drift_pct_per_day of the organic mean, applied
    to the underlying entropy target each day)."""
    rng = random.Random(seed)
    bim = BaselineIntegrityMonitor(seed=seed)
    bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, mu0_js, k, h, 0.0, SEED_DIST)

    for day in range(warmup_days):
        ts = float(day * SECONDS_PER_DAY)
        h_target = organic_entropy(day, rng)
        s = zipf_s_for_entropy(K, h_target)
        dist = zipf_distribution(K, s)
        observed = sample_categorical_counts(dist, N_SAMPLES, rng)
        bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, observed, ts)

    drift_per_day_abs = (drift_pct_per_day / 100.0) * MU0_ENTROPY
    detection_day = None
    for day in range(n_days):
        abs_day = warmup_days + day
        ts = float(abs_day * SECONDS_PER_DAY)
        seasonal = organic_entropy(abs_day, rng) - MU0_ENTROPY  # keep seasonality during attack too
        h_target = MU0_ENTROPY + seasonal + (day + 1) * drift_per_day_abs
        s = zipf_s_for_entropy(K, h_target)
        dist = zipf_distribution(K, s)
        observed = sample_categorical_counts(dist, N_SAMPLES, rng)
        alarm = bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, observed, ts)
        if alarm is not None:
            detection_day = day + 1  # days since onset
            decision = bim.alarm_log[-1].fs_isac_decision.value
            return detection_day, decision
    return None, None


def calibrate():
    """Monte Carlo search: pick mu0_js/k/h from organic JS-divergence stats,
    then grid-search h for a specificity/sensitivity tradeoff."""
    # Step 1: characterize organic JS divergence with a placeholder monitor
    # (mu0_js=0,k=0,h=inf so nothing alarms and we just harvest the raw JS series)
    all_js = []
    for seed in range(10):
        js_values, _ = run_organic_scenario(120, seed, mu0_js=0.0, k=0.0, h=float("inf"))
        all_js.extend(js_values[7:])  # drop first week (buckets still cold-start seeding)
    all_js.sort()
    n = len(all_js)
    mu0_js = sum(all_js) / n
    p90 = all_js[int(0.90 * n)]
    p99 = all_js[int(0.99 * n)]
    std = (sum((x - mu0_js) ** 2 for x in all_js) / n) ** 0.5

    print(f"Organic JS-divergence stats over {n} samples (10 seeds x 113 days, post-warmup):")
    print(f"  mean={mu0_js:.5f}  std={std:.5f}  p90={p90:.5f}  p99={p99:.5f}  max={max(all_js):.5f}")

    k = 0.5 * std
    # grid search h for false-alarm rate vs CSDA-rate detection horizon
    best = None
    for h_mult in [3, 4, 5, 6, 8, 10, 12, 16, 20]:
        h = h_mult * std
        fp_days = 0
        total_days = 0
        for seed in range(20):
            _, alarm_day = run_organic_scenario(90, seed + 1000, mu0_js, k, h)
            total_days += 90
            if alarm_day is not None:
                fp_days += (90 - alarm_day)  # days spent "frozen" due to a false alarm
        fp_rate = fp_days / total_days

        det_days = []
        for seed in range(20):
            d, decision = run_poisoning_scenario(2.8, 14, seed + 2000, mu0_js, k, h)
            if d is not None and decision == "poisoning":
                det_days.append(d)
        det_rate = len(det_days) / 20
        mean_det = sum(det_days) / len(det_days) if det_days else None

        print(f"  h={h_mult}*std={h:.5f}: organic false-alarm-day-rate={fp_rate:.3f}  "
              f"CSDA(2.8%/day) detect-rate={det_rate:.2f}  mean_detect_day={mean_det}")

        if best is None and fp_rate < 0.05 and det_rate >= 0.9:
            best = (h_mult, h)

    if best is None:
        best = (12, 12 * std)
    print(f"\nSelected: k={k:.5f} ({k/mu0_js*100 if mu0_js else 0:.1f}% of mu0_js), "
          f"h={best[1]:.5f} ({best[0]}*std)")
    return mu0_js, k, best[1], std


if __name__ == "__main__":
    mu0_js, k, h, std = calibrate()

    print("\n=== Verification against Table IV structure (20 seeds each) ===")
    results = {}
    for drift_pct, label in [(1.5, "1.5%/day"), (2.8, "2.8%/day (CSDA)"), (4.0, "4.0%/day")]:
        detections = []
        poisoning_calls = 0
        for seed in range(20):
            d, decision = run_poisoning_scenario(drift_pct, 21, seed + 3000, mu0_js, k, h)
            if d is not None:
                detections.append(d)
                if decision == "poisoning":
                    poisoning_calls += 1
        mean_d = sum(detections) / len(detections) if detections else None
        results[label] = {
            "n_detected": len(detections), "n_poisoning_calls": poisoning_calls,
            "mean_detection_day": round(mean_d, 2) if mean_d else None,
            "min_day": min(detections) if detections else None,
            "max_day": max(detections) if detections else None,
        }
        print(f"  {label}: detected {len(detections)}/20 runs "
              f"(poisoning-classified {poisoning_calls}/20), "
              f"mean day-from-onset={mean_d}")

    print("\n=== 90-day organic false-alarm check (30 seeds) ===")
    n_alarms = 0
    for seed in range(30):
        _, alarm_day = run_organic_scenario(90, seed + 5000, mu0_js, k, h)
        if alarm_day is not None:
            n_alarms += 1
    print(f"  false alarms: {n_alarms}/30 seeds over 90 organic days each")

    out = {
        "method": "Monte Carlo (organic JS-divergence Monte Carlo characterization, "
                  "then grid search on h for false-alarm/detection tradeoff)",
        "n_categories": K, "window_samples": N_SAMPLES, "organic_entropy_bits": MU0_ENTROPY,
        "weekday_seasonality_amplitude_bits": WEEKDAY_AMPLITUDE,
        "mu0_js": round(mu0_js, 6), "k": round(k, 6), "h": round(h, 6), "std": round(std, 6),
        "table_iv_verification": results,
        "organic_false_alarm_rate_30seed_90day": round(n_alarms / 30, 3),
    }
    out_path = os.path.join(os.path.dirname(__file__), "BIM_JS_CUSUM_CALIBRATION.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {out_path}")
