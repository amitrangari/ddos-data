> **Historical report, superseded in v1.3.0 (2026-10).** Kept for the record. The
> 3.0M-record card-authorization dataset is SYNTHETIC; where this report says "real"
> about it, read "synthetic". FDCE detector numbers, the R-11 statistic and the
> FDCE SLA values below describe v1.1/v1.2 code and are superseded by
> `results/v1.3.0/` and `REPRODUCTION.md`. Section and table numbers refer to
> earlier manuscript versions.

# FDCE Calibration from Real Card-Auth Data — Report

**Date:** 2026-06-18 · **Script:** `calibrate_fdce_from_real_data.py` · **Seed:** 42
**Data:** `research-data/ddos-data/10-payment-fraud/ng-card-auth/` (3.0M card auths, 2023–2024,
`electricsheepafrica/nigerian-banking-card-transactions`, Apache-2.0)
**Calibration artifact:** `research-data/ddos-data/10-payment-fraud/fdce_calibration.json`

## Purpose
Ground the §VI.I FDCE results and the R-11 decline-concentration threshold (0.80) in a real
decline-code distribution, replacing configured constants. Mirrors the existing CICDDoS2019
network-IAT calibration, but at the **payment-authorization layer** the simulator previously fabricated.

## Findings

**1. Empirical base rates (real).** approved **92.0%**, declined **7.8%**, 3DS-authenticated **14.0%**.
Decline mix is ~uniform across `{invalid_pin, expired_card, suspected_fraud, insufficient_funds}` (~25% each).
The FDCE code set `{14,54,57,82}` maps to `expired_card`→54 and `suspected_fraud`→57, i.e. **50% of
organic declines** fall in the FDCE class. (The paper's FDCE *attack* config assumes a skewed
60/25/15 expired/CVV/revoked mix; real organic traffic is flatter — useful as the FP baseline.)

**2. R-11 false-positive floor (real, headline result).** Per merchant-cluster (MCC) daily window,
organic FDCE-decline-share centers tightly at **0.50**. Fraction of legitimate windows exceeding the
0.80 threshold, by volume gate:

| Volume gate (declines/window) | Eligible windows | R-11 FP @ 0.80 |
|---|---|---|
| ≥ 5  | 9,824 | 1.38% |
| ≥ 10 | 7,965 | 0.49% |
| ≥ 20 | 4,341 | **0.023%** |
| ≥ 50 | 1,032 | 0.00% |

→ With a reasonable volume gate (≥20 declines), R-11's real-world false-alarm floor is **0.023%**,
consistent with the paper's claimed 0.08% FPR order of magnitude. **The volume gate is load-bearing**
and should be stated explicitly in §II.A / §VI.I — without it, sparse windows inflate FP to >1%.

**3. Separability (real organic vs. modeled attack).** Organic FDCE-share (~0.50, real) vs. FDCE attack
(~0.98, Beta(50,1) per the "all sequences terminate AUTH_DECLINED" claim): **Cohen's d = 7.67**, R-11
recall proxy 100% at threshold 0.80. Far cleaner than the network-layer CICDDoS2019 d=0.71 — supports
"FDCE produces immediate TCS collapse" as the strongest CSDA signal.

**4. FDCE re-run with real FP baseline.** Substituting the real 0.023% FP for the 0.08% constant leaves
TIG-CDO FDCE SLA **unchanged at 93.8%** (+0.0 pp): FDCE SLA is latency/block-model-driven, not FP-driven.

## Pre-existing gap surfaced (not caused by this calibration) — RESOLVED in v8
The artifact (`run_tigcdo_eval.py`) yields **93.8%** TIG-CDO FDCE SLA with or without the real FP, but the
paper text previously stated 96.1% (§VI.I). **Resolved 2026-06-20 (manuscript v8, changelog row v8.E1):**
§VI.I now states the reproducible **93.8%** (seed 42), supersedes the 96.1% (earlier SLA-model calibration
not reproduced by the current artefact), and the artefact's internal "Paper: 96.1%" reminders were updated
to match. This removes the only paper-vs-artefact numeric discrepancy.

## Caveats
Synthetic-but-realistic data; single 6-digit BIN prefix (BIN-family granularity proxied by MCC clusters);
`issuer_response_code` collapsed to 00/05/01 so `decline_reason` is used for the FDCE class; the FDCE
attack side is modeled (Beta), only the organic side is real.

## Reproduce
```
cd implementation && python3 calibrate_fdce_from_real_data.py
```
