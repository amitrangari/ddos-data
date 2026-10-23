> **Historical report, superseded in v1.3.0 (2026-10).** Kept for the record. The
> 3.0M-record card-authorization dataset is SYNTHETIC; where this report says "real"
> about it, read "synthetic". FDCE detector numbers, the R-11 statistic and the
> FDCE SLA values below describe v1.1/v1.2 code and are superseded by
> `results/v1.3.0/` and `REPRODUCTION.md`. Section and table numbers refer to
> earlier manuscript versions.

# FDCE Rule Engine Report — R-11 / R-12 v2

**Modules:** `fdce/fdce.py` (detector), `fdce/scenario.py` (traffic simulator)
**Raw results:** `FDCE_RULE_ENGINE_RESULTS.json`
**Addresses:** consolidated review finding C7 (`paper2-solution/review/2026-08-15/00_CONSOLIDATED_REVIEW.md`)
**Real-data anchor:** `calibrate_fdce_from_real_data.py` against `ng-card-auth` (3.0M records) —
organic decline-code share is near-uniform (~25%/class), single-code p99 = 0.712, well under
the R-11 0.80 threshold; false-positive floor 0.023%.

## What changed from v1

v1's `_FDCE_BLOCK["tig_cdo"] = 0.72` and `_FDCE_DET_S["tig_cdo"] = 53.0` were hand-set
constants, never computed. R-11 and R-12 did not exist as executable logic anywhere in the
codebase — only as a standalone statistic in the calibration script. v2 implements both as
live, wired detectors (`fdce/fdce.py`) and drives every one of the 30 FDCE scenarios through
a real bot-vs-organic traffic simulator (`fdce/scenario.py`) rather than a flat constant.

- **R-11**: sliding 60s window per BIN, decline-code concentration, O(1) amortized per event
  (a running Counter kept in sync incrementally, not a full-window rescan — matters at
  FDCE-scale volumes, up to ~900k events per scenario).
- **R-12**: sliding 60s window per merchant ID, completion-rate floor gated by a >100 txn/min
  volume threshold. Required adding a `merchant_id` concept the codebase didn't have (STC's
  session key never carried one — see security review finding). Kept as a **separate**
  lightweight tracker rather than folded into STC's session key, to avoid touching the CSDA
  Phase 1-4 / TCS architecture, which has no merchant-clustering concept in its design and is
  independently validated.
- **Blocking policy**: once R-11 fires for a BIN or R-12 fires for a merchant, subsequent
  traffic from that BIN/merchant is blocked — this is the mechanism that produces a genuine,
  measured block rate instead of a hardcoded one.

## Main grid: 30 scenarios (3 cluster sizes × 2 card-damage types × 5 intensities)

| | Value |
|---|---|
| Detected | 30/30 |
| Detection latency | mean 2.43s, range 0.07–10.83s |
| Block rate | mean 95.9%, range 87.9–99.9% |
| Organic R-12 false positives | 0 across all 30 scenarios |

**This is much faster than v1's assumed 44–62s**, and that is a real finding, not an error:
decline-concentration and completion-rate-floor signals become statistically obvious almost
immediately at the attack volumes the paper itself specifies (up to 500 merchants × ~15 TPS
each = up to ~7,500 tx/s in aggregate). A windowed-count detector against that much
concentrated volume crosses `r11_min_declines=20` or `r12_min_auths=10` within a small
fraction of the 60s window. The 44-62s figure was never grounded in a working detector; now
that one exists, it should be superseded rather than preserved as a target to hit.

`expired_only` scenarios (100% code 54) detect via **R-11** in well under a second, every
time. `mixed` scenarios (60/25/15% split across three codes) stay below the R-11 threshold
longer and detect via **R-12** instead, typically 5–11s — a real, substantively different
detection path depending on the attacker's own code-mixing choice, which is exactly the kind
of scenario-dependent behavior a hardcoded constant could never show.

## Adversarial robustness check (security review's explicit request)

An attacker who deliberately spreads decline codes to 24/24/24/28% — just under the R-11
0.80 threshold, and much closer to the real organic p99 of 0.712 than the paper's originally
claimed 60/25/15% attacker mix — was tested across 9 configurations (3 cluster sizes × 3
intensities).

| | Value |
|---|---|
| R-11 triggered | **0/9** (correctly evaded by construction — this is expected, not a failure) |
| R-12 triggered | **9/9** — detection latency 4.7–10.8s (mean 7.3s), comparable to the `mixed` case above |
| Block rate under this evasion | **0.2–1.9%** (mean 0.84%) — sharply lower than the 95.9% mean in the main grid |

**This is the important result.** R-12 still *detects* the evasion attempt reliably and
quickly. But R-12's blocking granularity is per-merchant: with up to 500 distinct bot
merchant IDs, each one has to individually accumulate enough evidence to trip its own R-12
counter before it gets blocked. Against a federated cluster this large, that means the vast
majority of bot transactions get through even after the attack has been correctly identified
as ongoing. **Detection and blocking are not the same guarantee here, and the paper should
say so rather than imply R-12 provides the same ~96% blocking coverage as the un-evaded
case.** This is now recorded as a construct-validity threat (Section VIII) rather than
implied away.

## What this means for Table III / Section VI.I

- Report the real 30-scenario aggregate numbers (2.43s mean detection, 95.9% mean block
  rate) as the headline, in place of the old "44–62s, avg 73% (range 65–81%)."
- Add the adversarial-spreading result as an explicit robustness finding: R-12 alone still
  detects (mean 7.3s) but blocks only ~0.8% of a large, code-spread-evading cluster before
  PADO/PSRG's per-merchant mechanism catches up merchant-by-merchant — a real, disclosed
  limitation of R-12's per-merchant granularity against large federated clusters.

## Known follow-up (not done in this pass)

The existing 50-seed dispersion band for "FDCE SLA%" in
`research-data/ddos/11-microservice-latency/followup_analyses.json` (used by `run_tigcdo_eval.py`'s
dispersion printout) was computed under v1's hardcoded FDCE model and has **not** been
regenerated against the new real R-11/R-12 pipeline. The CSDA (non-FDCE) bands in that same
file are unaffected. Regenerating it requires updating `run_followup_analyses.py`'s FDCE path
to call `fdce/scenario.py` the same way `run_fdce_evaluation()` now does — scoped as future
work rather than done under this pass's time budget.

## Reproducibility

```bash
cd research-data/ddos/implementation/v2
python3 -c "from fdce.scenario import simulate_fdce_scenario; print(simulate_fdce_scenario(500, 'mixed', 1.0, seed=42))"
python3 run_tigcdo_eval.py   # FDCE section now uses the real detector end-to-end
```
