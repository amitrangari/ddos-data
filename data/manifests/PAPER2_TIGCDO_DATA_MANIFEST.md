# TIG-CDO (paper2) — Real Payment Data Added for Simulator Calibration

**Paper:** `research-papers/ddos/paper2-solution/mainv2.md` — *Transaction Intent Graph: Semantic Cross-Layer Defense Orchestration for Microservices Payment Systems* (IEEE TNSM, rev v7)
**Added:** 2026-06-17 · **Source:** Hugging Face dataset hub (auto-converted parquet, public, no auth)

---

## Why this data was needed

The v5–v7 reviews flagged that the entire evaluation is **simulator-projected from configured
constants** (`_FPR`, `_ATTACK_BLOCK`, `_DET_LATENCY`, `_LATENCY_PARAMS`), not from real measurement.
The only real calibration source cited in the paper is **CICDDoS2019** (network inter-arrival times,
Cohen's *d* = 0.71 benign vs. attack), which is already in `01-benchmark/cic-ddos2019/`.

What the simulator still fabricates as constants — and which these datasets can ground — is the
**payment-transaction layer**: the ISO 8583 0100/0110 authorization outcome mix, 3DS authentication
rate, decline-code distribution (the heart of the FDCE / R-11 / R-12 model), BIN-family and merchant
fan-out (the Zipf α=0.8 and 85/10/5 transaction-mix assumptions in §V.B), and the directed
entity→entity graph structure the STC builds (Algorithm 1).

These are **synthetic-but-realistic** payment datasets (no real cardholder data exists publicly for
ISO 8583 traffic). They are calibration/realism anchors, not ground truth — see caveats per dataset.

---

## Datasets added (under `10-payment-fraud/`)

### 1. `ng-card-auth/` — ⭐ primary: ISO 8583 + 3DS + decline-code calibration
`electricsheepafrica/nigerian-banking-card-transactions` · 3.0M rows · 18 cols · 177 MB · Apache-2.0
HF: https://hf.co/datasets/electricsheepafrica/nigerian-banking-card-transactions

Schema maps almost 1:1 to TIG-CDO's authorization model:

| Column | Maps to paper concept |
|---|---|
| `card_id` | BIN family vertex `V_BIN` (§IV.C); STC session key |
| `merchant_category_code` (14 MCCs) | Merchant vertex `V_MID`; transaction-mix priors |
| `timestamp` | Inter-arrival times / time-of-day variation (§V.B) |
| `card_present` | CP vs. CNP split |
| `cvv_provided`, `avs_result` | card-testing signal inputs |
| `3ds_authenticated` | EMVCo 3DS AReq/CReq flow (§II.A) |
| `authorization_result` | ISO 8583 0110 approve/decline outcome |
| `decline_reason` | **FDCE decline-code model (R-11)** — expired / wrong-PIN / suspected-fraud / NSF |
| `issuer_response_code` | ISO 8583 DE39 response code (00/05/01) |
| `fraud_flag`, `chargeback_flag` | fraud-adjacency boundary (§VII.E) |

**Real distributions observed** (vs. the paper's current constants):
- `authorization_result`: **approved 92.0% / declined 7.8% / referral 0.2%** (issuer code `00`/`05`/`01`).
  → grounds the "≈85% completions legitimate" baseline in §II.C and the approval-rate prior.
- `decline_reason`: ~uniform 25% across {expired_card, invalid_pin, suspected_fraud, insufficient_funds}.
  → the paper's FDCE config assumes a *skewed* mix (≈60% expired/code-54, 25% wrong-CVV, 15% revoked);
    this dataset gives a **uniform-baseline** to sensitivity-test that assumption (Table III).
- `3ds_authenticated`: 14.0% True → realistic 3DS-enrolment fraction for §VI.D ACS modelling.
- `card_present`: 79.0% True / 21.0% CNP.

**Caveats:** synthetic; all `card_id`s share a single 6-digit prefix (so BIN-family *granularity* must be
derived from `card_id` identity, not real BIN ranges); `issuer_response_code` collapsed to 3 codes
(use `decline_reason` for the finer FDCE decline-class split). Nigerian-market priors (NGN amounts).

### 2. `ibm-aml-graph/` — directed transaction-graph structure at scale
`eexzzm/IBM-Transactions-for-Anti-Money-Laundering-HI-Small-Trans` · 5.1M rows · 11 cols · 155 MB (2 files)
HF: https://hf.co/datasets/eexzzm/IBM-Transactions-for-Anti-Money-Laundering-HI-Small-Trans

`Timestamp, From Bank, Account → To Bank, Account.1, Amount, Currency, Payment Format, Is Laundering`.
A real **directed multigraph** of account→account transfers with timestamps — useful for stress-testing
STC graph construction / `O(k log n)` update cost (§IV.C), edge fan-out, and velocity features at the
260k-events/s scale claimed in §VII.A, independent of the payment-protocol semantics. Egressy et al. [75]
(directed-multigraph GNN) cited in §III.A use exactly this IBM AML family.

**Caveat:** AML inter-bank transfers, not card-auth ISO 8583 — use for graph *structure/scale*, not for
decline/3DS semantics.

### 3. `ng-retail-casa/` — legitimate retail baseline (merchant + channel + time)
`electricsheepafrica/nigerian-banking-retail-transactions` · 5.0M rows · 16 cols · 403 MB · Apache-2.0
HF: https://hf.co/datasets/electricsheepafrica/nigerian-banking-retail-transactions

`account_id, customer_id, timestamp, amount, transaction_type, channel, merchant_category_code,
merchant_name, location_state, device_id, status, fraud_flag`. Provides a **legitimate-traffic baseline**
for merchant fan-out (Zipf check), channel mix, device-graph edges, and time-of-day seasonality that
feed the BIM organic-drift bound (§IV.E, 1.1%/day calibrated organic drift) and the no-attack baseline strip.

---

## How to use (suggested next simulation steps)

1. Fit `decline_reason` / `authorization_result` empirical distributions from `ng-card-auth/` and replace
   the hand-set FDCE decline mix in the simulator; re-run the 30 FDCE scenarios → report sensitivity of
   TCS-collapse latency (44–62 s) to a *real* vs. assumed decline mix.
2. Derive BIN-family / merchant fan-out and IAT distributions to replace the synthetic Poisson+Zipf(α=0.8)
   traffic generator (§V.B) with a trace-driven generator; re-derive the N=50-seed dispersion bands.
3. Use `ibm-aml-graph/` to benchmark real STC graph-update throughput against the 260k events/s design target.

All three are CSV/parquet, load with `pandas`/`pyarrow` (installed). Random seed 42 per paper convention.

---

## Calibration run (2026-06-18) — FDCE decline-mix grounded in `ng-card-auth/`

Script `paper2-solution/implementation/calibrate_fdce_from_real_data.py` →
artifact `fdce_calibration.json` (this dir); report
`paper2-solution/implementation/FDCE_CALIBRATION_REPORT.md`.

Headline results: organic FDCE-decline-share centers at **0.50**; R-11's 0.80 threshold has a
**0.023% false-positive floor** at a ≥20-decline volume gate (gate sweep in JSON); organic-vs-FDCE
separation **Cohen's d = 7.67** (cf. CICDDoS2019 d=0.71). Real FP leaves TIG-CDO FDCE SLA unchanged at
**93.8%** — surfacing a pre-existing paper-vs-artifact gap (paper text says 96.1%) to reconcile.
