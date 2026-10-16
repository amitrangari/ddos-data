# REPRODUCTION.md

Maps every result table and figure of *"Transaction Intent Graph: Semantic
Cross-Layer Defense Orchestration for Microservices Payment Systems"* to the
command that regenerates it from this package. **Table and figure numbers
follow the MDPI *Journal of Cybersecurity and Privacy* version of the
manuscript (2026-10) and its Supplementary Materials S1.** A map from the
earlier Empirical Software Engineering numbering (2026-08) is at the end.

Setup (once):
```bash
pip install -r requirements.txt
# or: docker build -t tig-cdo-repro . && docker run --rm -it -v "$PWD:/repro" tig-cdo-repro bash
```
All scripts are deterministic (seed 42) and self-contained; run them from the
repository root exactly as shown.

## Confidence key
- **Verified**: re-run from a clean copy of version 1.2.0; the output matches
  the checked-in file (see "Clean-copy verification" below).
- **Archived**: the checked-in output is cited; the script needs an external
  dataset that is not bundled (see README.md) and was not re-run for 1.2.0.
- **Design**: a specification, worked example or configured parameter. No
  script reproduces it because none is supposed to.

---

## Figures

| Figure | What it shows | Command | Confidence |
|---|---|---|---|
| Fig. 1 | Architecture diagram | Hand-authored (`figures/fig1-architecture.pdf`); no data | Illustration |
| Fig. 2 | BIM JS-divergence CUSUM trajectory, CSDA Phase 2 (Table 8) | `python3 trace_bim_phase2.py` (writes `BIM_PHASE2_TRACE.json`), then `python3 generate_paper_figures.py` (plots Figure 2 from that file) | **Verified** |
| Fig. 3 | CLCS sensitivity to beta (Table 11) | `python3 generate_paper_figures.py`; computed from the amplification formula in `clcs/clcs.py` | **Verified** |
| Fig. 4 | FDCE block rate over the 30-scenario grid | `python3 write_fdce_results.py` (writes `FDCE_RULE_ENGINE_RESULTS.json`), then `python3 generate_paper_figures.py` | **Verified** |

`generate_paper_figures.py` writes Figures 2 to 4 to `figures/` (or to
`$FIG_OUT`). The configuration heatmap that earlier versions shipped as
Figure 5 was removed in 1.2.0 (see CHANGELOG.md).

## Tables

| Table | Content | Command | Confidence |
|---|---|---|---|
| 1 to 5 | Protocol rules, TCS signatures, CLCS signals and weights, PSRG projection, PADO bundles | Design specification; constants live in `stc/`, `clcs/`, `psrg/`, `pado/`, `fdce/` | Design |
| 6 | Component latency design budget | **Design targets, not measurements.** No script measures them; `psrg/psrg.py` and `pado/pado.py` state the 1.2 ms PSRG target and the configured 340 ms PADO activation mean as design/configured values | Design |
| 7 | Simulator outputs versus configured inputs | Constants `_ATTACK_BLOCK`, `_FPR`, `_DET_LATENCY`, `_LATENCY_PARAMS` in `run_tigcdo_eval.py` | Design |
| 8 | CSDA Phase-2 JS-CUSUM trajectory (seed 42) | `python3 trace_bim_phase2.py` -> `BIM_PHASE2_TRACE.json` | **Verified** |
| 9 | Configuration comparison over the CSDA conditions: SLA and FPR at seed 42 and over 50 seeds | `python3 run_tigcdo_eval.py` -> `tigcdo_eval_results.json` (`csda_comparison`); 50-seed bands: `python3 run_followup_analyses.py` -> `followup_analyses.json` (`C_nseed_dispersion`) | **Verified** |
| 10 | BIM detection by drift rate, 20-seed Monte Carlo | `python3 calibrate_bim_js_cusum.py` -> `BIM_JS_CUSUM_CALIBRATION.json` | **Verified** |
| 11 | CLCS sensitivity to beta | `generate_paper_figures.py` (`fig3_beta_sensitivity()`), from `A(TCS) = 1 + beta(1 - TCS)` | **Verified** |
| 12 | FDCE detection, representative rows of the 30-scenario grid; FDCE SLA by configuration | `python3 write_fdce_results.py` -> `FDCE_RULE_ENGINE_RESULTS.json`; aggregates in `tigcdo_eval_results.json` (`fdce_comparison`) | **Verified** |
| 13 | Headline metrics, Gaussian model versus real latency distributions | `python3 calibrate_latency_from_real_data.py` -> `latency_calibration.json` and `python3 run_followup_analyses.py` (section A); both need the external RCAEval / Alibaba data under `DDOS_RAW_DATA_ROOT` | **Verified** (with external data present) |
| S1, S2 | Threshold register; worked Phase-1 CLCS trajectory | Design values; Table S2 computed with the CLCS formula | Design |
| S3 | ACS-GUARD integration projection | `baselines-cross-dataset/acs-guard-simulation.py` (companion-survey baseline) | Archived |
| S4 | Cross-dataset F1 of inline classifiers | `baselines-cross-dataset/*.py` (one script per public dataset, each needs that dataset locally) | Archived |

**CSDA comparison grid (1.2.0).** The comparison depends only on whether an
attack is active and on its intensity (attack share 10%, 25% or 45%). It has
4 distinct conditions per configuration, run as 39 replicate runs (3 without
attack, 12 per intensity). Versions up to 1.1.0 labeled these runs with CSDA
phases and TPS tiers and printed "270 scenarios"; neither label entered the
computation. The run order is unchanged, so every seed-42 SLA value is
identical to 1.1.0.

**FPR (1.2.0).** The false-positive rate is the share of legitimate
transactions blocked, over the legitimate transactions offered. Versions up to
1.1.0 used a denominator that subtracted blocked attack transactions, which
inflated the FPR (TIG-CDO 0.130% at seed 42, against 0.057% now). The
configurations apply false positives only while an attack is active, so
`tigcdo_eval_results.json` reports the FPR over all 39 runs, over the 36 attack
runs, and pooled over the attack runs with an exact (Clopper-Pearson) 95%
interval. The sampled FPR reproduces the configured base probabilities.

## Clean-copy verification (1.2.0)

From a fresh clone of the release commit, with Python 3.11 and the pinned
requirements, the following were re-run and compared with the checked-in
files: `run_tigcdo_eval.py`, `trace_bim_phase2.py`, `write_fdce_results.py`,
`generate_paper_figures.py`, `run_followup_analyses.py`,
`calibrate_bim_js_cusum.py`, `calibrate_fdce_from_real_data.py` and (with the
external data present) `calibrate_latency_from_real_data.py`. JSON outputs
matched exactly; figures are compared by their plotted data, since PDF bytes
carry a creation timestamp. `shasum -a 256 -c SHA256SUMS` passes on the clean
copy.

## Earlier numbering (Empirical Software Engineering version, 2026-08)

| ESE item | JCP item |
|---|---|
| Table X | Table 8 |
| Table XI | Table 9 |
| Table XIII | Table 10 |
| Table XVI | Table 11 |
| Table XVIII, XIX | Table 12 and Section 5.5 |
| Table XX | Table 13 |
| Tables VII, XIV ("component latency measurements") | Table 6, now stated as design targets; there was never a measurement |
| Table XV (TCS threshold sweep) | Removed: no script in any version produces it |
| Fig. 5 (configuration heatmap) | Removed |

---

## Empirical grounding calibrations (JCP Sections 4.9 and 5.5 to 5.7)

These scripts ground specific paper constants in real third-party data. Two
(`calibrate_fdce_from_real_data.py`, `calibrate_applayer_from_real_data.py`)
run out of the box against data bundled in / fetched into this package. The
other five need a bulk public dataset that is **not** bundled here (see
"Public datasets used, not bundled" in README.md) — point `DDOS_RAW_DATA_ROOT`
at your local copy, or place it under `./raw-data/<n>-<name>/...` matching
the path printed near the top of each script.

| Script | Grounds | Dataset | Bundled? |
|---|---|---|---|
| `calibrate_fdce_from_real_data.py` | Section 5.5 FDCE / R-11 threshold (synthetic card dataset; see its dataset card) | Nigerian Banking Card Transactions | **Yes** (`data/ng-card-auth/`) |
| `calibrate_applayer_from_real_data.py` | Section 4.9 arrival-model / IAT separation | APA-DDoS | Fetched by `download_apa_ddos.py` (not redistributed; see README.md) |
| `calibrate_bim_js_cusum.py` | Tables 8 and 10 (BIM JS-CUSUM parameters) | Synthetic Monte Carlo (organic seasonality model); no external dataset | N/A |
| `calibrate_drift_from_real_data.py` | BIM organic-drift bound (gap G4) | CESNET-TLS-Year22 (Zenodo doi:10.5281/zenodo.10608607) | No (external) |
| `calibrate_edos_from_real_data.py` | Anti-EDoS / Vector E (gap G6) | Mendeley Denial-of-Wallet (doi:10.17632/g8g9vdxyvn.1) | No (external) |
| `calibrate_scale_from_real_data.py` | PSRG per-source-rate premise (gap G5) | IoT-23 | No (external) |
| `calibrate_tcs_from_real_data.py` | TCS organic/attack separation (gap G1) | Retailrocket | No (external) |
| `calibrate_latency_from_real_data.py` | Section 5.6, Table 13 (latency distributions) | RCAEval RE2-TT, microservices-ddos, Alibaba cluster-trace-v2021 | No (external) |

Each of these five prints exactly which real-data file it could not find and
where it expected it, rather than failing silently or falling back to
fabricated numbers.

**Checked-in outputs (since v1.1.0).** Every calibration script's output JSON is
checked in at the repository root, so the numbers the paper cites can be
inspected without fetching any external dataset: `fdce_calibration.json`,
`applayer_calibration.json`, `latency_calibration.json`, `tcs_calibration.json`
(TCS 0.943 / 0.065), `drift_calibration.json` (deseasonalized secular drift
0.98 %/day), `edos_calibration.json` (Vector E separability), and
`scale_calibration.json` (IoT-23 per-source rate). Re-running a script against
the external dataset overwrites its JSON in place. `data/manifests/` records,
per external dataset, which file and which fields each script reads and which
paper constant it grounds.

---

## Testbed and scenario definitions

| Path | What it is |
|---|---|
| `scenarios/csda-test-scenarios.yaml` | CSDA kill-chain phase definitions (Phase 1 recon → Phase 4 persistence), with per-phase traffic parameters and the protocol rules (R-xx, CF-xx) each phase is expected to trigger |
| `scenarios/payment-protocol-state-machine.md` | The payment-protocol state machine (ISO 8583 / 3-D Secure 2.x causal ordering) that the TCS conformance check encodes |
| `k8s-testbed/k8s/*.yaml` | Kubernetes manifests (namespace, deployments, services, HPA, network policy, configmap) for the payment-microservices testbed |
| `k8s-testbed/docker/*/` | Container sources for the testbed services: payment gateway, auth, ACS, BIN lookup, rate limiter, metrics collector, load generator (Locust), attack generator |
| `k8s-testbed/docker-compose.yaml`, `local-test.py` | Single-host variant of the same testbed; `local-test-results.md` is a sample run |

The testbed is provided so the service topology can be inspected and stood
up; the paper's reported Section VI numbers come from the Python harness
above (`run_tigcdo_eval.py`), not from a live testbed run.

## What this package does NOT reproduce

Per the manuscript's own Data Availability Statement: the CSDA comparison's
per-configuration attack block rates, base false-positive probabilities and
detection latencies (outside FDCE, whose block rate and detection latency are
detector outputs) are **configured inputs with Monte Carlo sampling noise**, not
independent measurements — `run_tigcdo_eval.py` says this explicitly in its
own module docstring. Three items are specified in the paper but not
implemented in this package: cluster-level (rather than per-merchant) R-12
blocking, the PSRG stale-cache fail-open policy, and the cold-start standby
instance. The adversarial FDCE run (`simulate_fdce_adversarial_spread`)
still evaluates R-12 only until the first detection, so its block rate is a
harness artifact (planned fix: see CHANGELOG.md, "Known open items").
