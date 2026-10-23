# REPRODUCTION.md

Maps every result table and figure of *"Transaction Intent Graph: Semantic
Cross-Layer Defense Orchestration for Payment Transaction Systems"* to the
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

## Version 1.3.0 map (round-3 revision of the JCP manuscript)

Every experiment has one driver; `results/v1.3.0/RUNS.md` names the recorded
run (paper ledger id) and commit that produced each output. Run from the
repository root with Python 3.11; drivers write to `$RESULTS_DIR` (default
`results/v1.3.0/`); `N_PROC` sets the worker count.

| Manuscript item | Command | Output |
|-|-|-|
| Section 5.1 (Phase 1 to 3), Table S6 seed 42 | `python3 run_tigcdo_eval.py` | `tigcdo_eval_results.json` |
| Figure 2, Table S7 | `python3 trace_bim_phase2.py` | `BIM_PHASE2_TRACE.json` |
| Table 10, BIM N re-derivation, Page-Hinkley | `python3 experiments/exp_bim.py` | `bim_rows.json` |
| Section 5.3, real data (needs CESNET-TLS-Year22 under `DDOS_RAW_DATA_ROOT`) | `python3 experiments/exp_cesnet_replay.py` | `bim_cesnet_replay.json` |
| Table 11 | `python3 experiments/exp_vantage.py` | `vantage_table11.json` |
| Table 12 | `python3 experiments/exp_d0b_fusion.py` | `d0b_fusion.json` |
| Table 13, Table S8 | `python3 experiments/exp_fdce_replication.py`, `exp_fdce_rate_sweep.py`, `exp_fdce_dilution.py`, `exp_composed_adversary.py` (after `exp_bim.py`) | `fdce_*.json`, `composed_adversary.json` |
| Organic false alarms | `python3 calibrate_r11_multilook.py`, `experiments/exp_r12_flows.py`, `experiments/exp_organic_population.py` | `R11_MULTILOOK_CALIBRATION.json`, `r12_flows_organic.json`, `organic_population.json` |
| Table 14 (needs RCAEval and Alibaba data) | `python3 experiments/exp_table13.py` | `table13_like_for_like.json` |
| Table S6, 50-seed bands (needs the latency data) | `python3 run_followup_analyses.py` | `followup_analyses.json` |
| STC cost (Section 4.2) | `python3 experiments/exp_stc_timing.py` | `stc_timing.json` (machine dependent) |
| Figures 2 to 4 | `python3 write_fdce_results.py; python3 generate_paper_figures.py` | `FDCE_RULE_ENGINE_RESULTS.json`, `figures/` |
| Unit tests | `python3 -m pytest tests/` | 30 tests |

Design values (Tables 1 to 6, 8) have no command. Section 5.7 calibrations are
the archived v1.2 outputs listed below.

## Clean-copy verification (1.3.0)

See the section of the same name at the end of this file once the release is
verified.

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

The configured comparison (manuscript Table S6) consumes per-configuration block
rates, base false-positive probabilities and latency parameters as configured
inputs; its outputs are Monte Carlo sampling around them. Items specified in the
manuscript but not implemented are listed in manuscript Supplementary Materials
S1, Section S1.7 (implementation status); among them R-09, cross-merchant R-12
aggregation, the PSRG stale-cache policy, the standby STC, BIM model rollback and
real peer comparison, and the wiring of the components into one pipeline.
