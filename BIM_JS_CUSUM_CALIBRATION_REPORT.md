# BIM v2 Calibration Report — Jensen-Shannon Divergence CUSUM

**Produced by:** `calibrate_bim_js_cusum.py`
**Raw output:** `BIM_JS_CUSUM_CALIBRATION.json`
**Addresses:** consolidated review finding C6 (`paper2-solution/review/2026-08-15/00_CONSOLIDATED_REVIEW.md`)
**Real-data anchor:** `calibrate_drift_from_real_data.py` against CESNET-TLS-Year22 —
secular (deseasonalized) organic drift 0.985%/day, raw day-over-day 5.39%/day (dominated
by weekly seasonality); 2.3%/day alarm threshold is false-positive-safe on only 95.8% of
raw days but is comfortably safe once deseasonalized.

## What changed from v1

v1's `bim.py` ran CUSUM on a single scalar mean, compared each day against whatever the
immediately-preceding checkpoint held — no distribution, no Jensen-Shannon divergence, no
deseasonalization, despite the manuscript (§IV.E) describing all three as implemented. v2
replaces this with what the manuscript always claimed: BIM tracks a real categorical
distribution (synthetic BIN-lookup frequencies, 50 categories, sampled 2,000 observations
per window), computes Jensen-Shannon divergence between each day's observed distribution
and a week-aligned reference (a per-day-of-week EWMA maintained separately for each of the
7 weekdays), and runs a **one-sided** CUSUM (JS divergence is non-negative, so only upward
drift is meaningful) on that divergence signal.

## Calibration method

JS divergence of a finite-sample categorical distribution doesn't have the clean closed
form the v1 scalar CUSUM's analytic `calibrate()` assumed, so parameters were set by Monte
Carlo instead:

1. Characterized the organic (no-attack) JS-divergence distribution against the
   week-aligned reference, including realistic weekday/weekend entropy seasonality
   (±0.06 bits, modeling the real weekly service-mix variation CESNET-TLS-Year22 shows),
   over 10 seeds × 113 post-warmup days.
2. Set `mu0_js` = the empirical mean (0.00334), `k` = 0.5·std (0.00036).
3. Grid-searched the decision interval `h` over `{3,4,5,6,8,10,12,16,20}·std`, evaluating
   both the organic false-alarm rate and the CSDA-rate (2.8%/day entropy-equivalent drift)
   detection rate/latency at each. Selected the smallest `h` clearing false-alarm-rate
   < 5% and detection-rate ≥ 90%: **`h = 8·std = 0.00583`**.

## Results (20-seed Monte Carlo per scenario, matching the original Table IV structure)

| Injected drift | Detected | Mean day from onset | Range |
|---|---|---|---|
| 1.5%/day | 20/20 | 9.85 | 7–14 |
| 2.8%/day (CSDA) | 20/20 | 6.15 | 5–7 |
| 4.0%/day | 20/20 | 4.85 | 4–6 |

**Organic false-alarm rate:** 1/30 seeds (3.3%) saw at least one false alarm over a 90-day
organic run.

## How this differs from v1's reported behavior, and why that's the honest outcome

v1 claimed a hard threshold: drift below ~2.3%/day was "not detected" within the
evaluation window; at or above it, detection followed within a few days of onset. The real
JS-divergence CUSUM does not have a hard cutoff — like any CUSUM chart, it eventually
alarms on *any* sustained positive drift given enough time, just more slowly for smaller
drift rates. This is not a mechanism failure; it's the actual (and more honest) statistical
behavior of a CUSUM chart, and it does not contradict the paper's central claim: CSDA-rate
drift (2.8%/day) is still detected within ~6 days of onset, comfortably inside the 14-day
Phase 2 attack window, with a low (~3%) organic false-alarm rate. What changes is that
"1.5%/day never alarms" is no longer claimed — instead, 1.5%/day alarms too, just roughly
60% slower than the CSDA rate, which is the qualitatively correct and more defensible
relationship between drift magnitude and detection latency.

The secondary FS-ISAC organic-vs-poisoning classification (a heuristic on the
post-hoc-computed drift rate, unchanged in spirit from v1) called all detected drifts in
this test "poisoning," including the 1.5%/day case. This is a known limitation of that
heuristic rather than of the JS-CUSUM detector itself — the classification's `drift_rate`
is computed from elapsed time since the last checkpoint, which does not perfectly track
the true injected rate once CUSUM accumulation has been running for several days.
Reconciling that heuristic is out of scope for this pass; it is not load-bearing for any
number reported in `main_v2.md`, which reports detection latency, not classification
accuracy at the 1.5%/day operating point.

## Reproducibility

```bash
cd research-data/ddos/implementation/v2
python3 calibrate_bim_js_cusum.py       # regenerates BIM_JS_CUSUM_CALIBRATION.json
python3 run_tigcdo_eval.py              # Phase 2 now uses these calibrated parameters
```

Both scripts are deterministic given their internal seeds (0–5999 range, offset by scenario
to avoid correlation between organic/poisoning Monte Carlo batches).
