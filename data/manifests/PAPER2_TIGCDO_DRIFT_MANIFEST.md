# TIG-CDO (paper2) — Organic-Drift / Baseline-Poisoning Anchor (BIM)

**Paper:** `research-papers/ddos/paper2-solution/mainv4.md` / `ddos/paper2-solution/main.md`
**Added:** 2026-07-28 · **Dir:** `research-data/ddos-data/15-drift-cesnet/`
**Gap closed:** **G4** (from `DATA_GROUNDING_REVIEW.md`) — the Baseline Integrity Monitor's **organic-drift bound (1.1%/day) and poisoning threshold (2.3%/day)** were calibrated from assumption. These datasets supply real long-horizon drift to bound them.

## Why this data was needed
BIM uses CUSUM SPC to separate slow **baseline poisoning** (a CSDA phase) from legitimate concept drift. The 1.1%/day organic-drift and 2.3%/day alarm thresholds had no empirical basis. A real multi-week/-month traffic series is required to measure organic drift and its seasonality, then inject synthetic poisoning above it.

## Datasets added (both Zenodo, CC-BY-4.0)

### `cesnet-tls-year22.zip` — CESNET-TLS-Year22 (PRIMARY)
Zenodo `10.5281/zenodo.10608607` (Hynek et al., 2024) · **CC-BY-4.0** · **30.5 GB · 1,203 files**
Structure: `CESNET-TLS-Year22/WEEK-2022-NN/YYYY-MM-DD/flows-YYYYMMDD.csv.xz` + `stats-*.json`, spanning **52 weeks of 2022** on CESNET3 100 Gbps backbone (~½M users), 180 web-service labels.
→ The paper it accompanies documents **gradual drift (acc 96.3%→90.5% over 8 weeks) + an abrupt Week-10 shift** — the empirical template for bounding the 1.1%/day organic drift and setting the 2.3%/day poisoning threshold against real seasonality.
**Extraction note:** per-day `.xz` files — extract only the weeks needed for the drift series (no need to unpack all 30 GB).

### `cesnet-quic22.zip` — CESNET-QUIC22 (SECONDARY / shorter companion)
Zenodo `10.5281/zenodo.10728760` (Luxemburk et al.) · **CC-BY-4.0** · **20.95 GB · 103 files**
Structure: `cesnet-quic22/W-2022-NN/D_Day/flows-YYYYMMDD.csv.gz` + stats; **4 weeks** (W-2022-44…47, Oct 31–Nov 27 2022), 153M flows enriched with packet metadata + QUIC handshake fields.
→ Shorter, clean-license drift companion for a 4-week window.

**Caveat (honest framing):** both are **TLS/QUIC network flows, not payment transactions** — a cross-domain transfer. They ground the *shape/magnitude of organic drift and seasonality*, which the BIM thresholds must survive; they do not themselves contain payment baselines. Report as a cross-domain drift anchor.

## Calibration run (2026-07-30)
Script `ddos/paper2-solution/implementation/calibrate_drift_from_real_data.py` → artifact `drift_calibration.json`. Built from the 365 per-day `stats-*.json` service-mix distributions (180 apps) — **no flow-CSV decompression needed**. Drift metric = total-variation distance of the daily service-mix distribution (%/day).

Headline results (357 valid days, Jan–Dec 2022):

| Measure | Result | vs paper |
|---|---|---|
| **Raw day-over-day drift** | median **5.39%/day** (p90 19.3, max 41.7) | — dominated by weekday/weekend seasonality |
| **Deseasonalized secular drift** (7-day-lag, same weekday) | **0.98%/day** (6.89%/week) | ✅ **≈ paper's assumed 1.1%/day — VINDICATED** |
| **Cumulative drift vs Week-0** | plateaus at **~22–28%** all year | bounded seasonal oscillation, *not* runaway drift |
| **Abrupt-shift days** | **87** days > 16.9% day-over-day (largest 41.7% on 2022-01-31) | the seasonality the CUSUM must not mistake for poisoning |

**Key finding (nuanced, defensible):**
1. **The 1.1%/day organic-drift bound is empirically validated** — real *secular* (deseasonalized) drift is 0.98%/day, within 12% of the assumption.
2. **But the BIM must deseasonalize first.** Raw traffic swings ~5.4%/day on weekday/weekend cycles, so a naive CUSUM applying the 2.3%/day alarm to the raw daily baseline would fire on **~96% of days** (only 4.2% sit below 2.3% raw). Once the baseline is week-aligned / same-weekday, the 1.1%–2.3% band holds.
3. The cumulative-drift plateau (~22–28% from Week-0, never running away) confirms the monitored baseline is stationary-with-seasonality — the regime CUSUM is designed for, *provided* seasonality is removed.

## Recommended paper use (G4)
- Replace "assumed 1.1%/day organic drift" with **"measured secular drift 0.98%/day on real backbone traffic (CESNET-TLS-Year22, 357 days), validating the 1.1%/day bound."**
- Add a **required design note**: the BIM baseline must be **deseasonalized (week-aligned)** before CUSUM; report that raw daily seasonality is ~5.4%/day and 87 abrupt-shift days/year exist, so the 2.3%/day alarm is only false-positive-safe on a deseasonalized baseline.
- Optionally inject synthetic poisoning on top of the real deseasonalized series to re-derive the BIM detection-day table.

## Citations
- Hynek, K., Luxemburk, J., Pešek, J., Čejka, T., Šiška, P. *CESNET-TLS-Year22: A year-spanning TLS network traffic dataset from backbone lines.* Zenodo 10.5281/zenodo.10608607 (2024). CC-BY-4.0. (Sci. Data s41597-024-03927-4.)
- Luxemburk, J. et al. *CESNET-QUIC22.* Zenodo 10.5281/zenodo.10728760. CC-BY-4.0.
