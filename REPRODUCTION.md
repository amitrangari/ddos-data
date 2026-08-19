# REPRODUCTION.md

Maps every results table and figure in Section VI (and the relevant parts of
Section VII) of *"Transaction Intent Graph: Semantic Cross-Layer Defense
Orchestration for Microservices Payment Systems"* to the exact command that
regenerates it from this package. Table/figure numbers match the current
manuscript (`main_v2.md`, `latex/body.tex`).

Setup (once):
```bash
pip install -r requirements.txt
# or: docker build -t tig-cdo-repro . && docker run --rm -it -v "$PWD:/repro" tig-cdo-repro bash
```
All scripts are deterministic (seed 42) and self-contained — run them from the
repository root exactly as shown.

## Confidence key
- **Verified** — re-run in this package during assembly; output matches the
  paper's cited values exactly (see command output below each entry).
- **Traced** — the source script/function is identified from the code and the
  paper's own text/comments, but was not re-executed end-to-end during
  assembly (e.g. because it needs a large external dataset not bundled here).
- **Design/analytic** — the table is a worked example or a configured design
  parameter, not harness output; no script reproduces it because none is
  supposed to (the paper says so explicitly in the table caption).

---

## Figures

| Figure | What it shows | Command | Confidence |
|---|---|---|---|
| Fig. 1 | TIG-CDO architecture diagram | Hand-authored SVG, rendered to vector PDF: `weasyprint` on an HTML wrapper of `figures/fig1-architecture.svg`-equivalent content (no computed data; diagram only) | N/A (illustration) |
| Fig. 2 | BIM JS-divergence CUSUM trajectory (Table X) | `python3 generate_paper_figures.py` → `figures/fig2-bim-cusum-trajectory.pdf`. Values are Table X's own harness output (see Table X below), reproduced by `calibrate_bim_js_cusum.py`. | **Verified** (script runs, writes figure) |
| Fig. 3 | CLCS sensitivity to β (Table XVI) | `python3 generate_paper_figures.py` → `figures/fig3-beta-sensitivity.pdf`. Computed live from the amplification formula in `clcs/clcs.py` — not read from a JSON. | **Verified** |
| Fig. 4 | FDCE block-rate heatmap, 30-scenario grid | `python3 generate_paper_figures.py` → `figures/fig4-fdce-heatmap.pdf`, reading `FDCE_RULE_ENGINE_RESULTS.json`'s `main_grid_30_scenarios`. | **Verified** |
| Fig. 5 | Defense-configuration comparison heatmap (Table XI) | `python3 generate_paper_figures.py` → `figures/fig5-defense-config-heatmap.pdf`. | **Verified** |

Run once — `generate_paper_figures.py` regenerates all four data figures together and writes them to `figures/`.

## Tables

| Table | Content | Command | Confidence |
|---|---|---|---|
| I | Protocol-derived anomaly rules | Descriptive (design specification, not measured) | Design |
| II | TCS signature by CSDA vector | Descriptive | Design |
| III | CLCS signal sources | Descriptive | Design |
| IV | CLCS base weights | Descriptive (design constants consumed by `clcs/clcs.py`) | Design |
| V | PSRG vs. per-IP rate limiting, 500K-source CSDA | Component-model projection, explicitly labeled "not a measurement" in its own caption | Design |
| VI | PADO defense bundle taxonomy | Descriptive | Design |
| VII | TIG-CDO component overhead vs. latency budget | `python3 run_tigcdo_eval.py` (component-latency section of stdout) | Traced |
| VIII | Consolidated threshold register | Descriptive summary of constants defined across `bim/`, `clcs/`, `fdce/`, `pado/`, `psrg/`, `stc/` | Design |
| IX | CSDA Phase 1 worked CLCS trajectory | Worked example, explicitly labeled "design scenario, not harness output" in its own caption | Design |
| X | CSDA Phase 2 realized JS-divergence CUSUM trajectory (seed 42) | `python3 calibrate_bim_js_cusum.py` → `BIM_JS_CUSUM_CALIBRATION.json` (`table_iv_verification` / trajectory fields) | **Verified** |
| XI | Defense-configuration comparison, 39 CSDA scenarios × 4 configs | `python3 run_tigcdo_eval.py` (`run_270_scenario_evaluation()`, printed as "Table II" in the script's own older internal numbering — see note below) | Traced |
| XII | Legitimate acceptance under ACS attack modes | `python3 baselines-cross-dataset/acs-guard-simulation.py` (component-model projection; ACS-GUARD figures are the companion-survey baseline, ref. [9]) | Traced |
| XIII | BIM detection behavior by drift rate, 20-seed Monte Carlo | `python3 calibrate_bim_js_cusum.py` (caption cites this script explicitly) | **Verified** |
| XIV | Component latency measurements (n=1000) | `python3 run_tigcdo_eval.py` (component-latency section of stdout) | Traced |
| XV | TCS threshold sweep (n=400 legitimate transactions/scenario) | `python3 run_tigcdo_eval.py` | Traced |
| XVI | CLCS sensitivity to β | `python3 generate_paper_figures.py` (`fig3_beta_sensitivity()`, computed live from `clcs/clcs.py`'s amplification formula `A(TCS) = 1 + β(1-TCS)`) | **Verified** |
| XVII | BIM drift threshold sweep (analytic) | Analytic, from `bim/bim.py`'s CUSUM calibration formula against the stationary-traffic model; not a Monte Carlo run | Design/analytic |
| XVIII | FDCE detection by configuration (real R-11/R-12 output) | `python3 run_tigcdo_eval.py` (`run_fdce_evaluation()`, drives `fdce/scenario.py`'s `simulate_fdce_scenario` — real detector, not a constant). The exact checked-in `FDCE_RULE_ENGINE_RESULTS.json` (full 30-scenario grid, representative rows shown in the table) is the authoritative harness output; see note below. | **Verified** (aggregate SLA/block-rate reproduced; see `FDCE_RULE_ENGINE_REPORT.md`) |
| XIX | Adversarial decline-code spreading (R-11 evasion) | `fdce/scenario.py`'s `simulate_fdce_adversarial_spread()`; checked-in output is `FDCE_RULE_ENGINE_RESULTS.json`'s `adversarial_grid` | Traced |
| XX | Headline metrics: calibrated model vs. real-distribution re-run | The FDCE half: `python3 calibrate_fdce_from_real_data.py` → `fdce_calibration.json` (**Verified**, runs against bundled data). The latency/SLA half: `python3 run_followup_analyses.py` → `followup_analyses.json` (needs `calibrate_latency_from_real_data.py`'s RCAEval/microservices-ddos/Alibaba inputs — **fails without `DDOS_RAW_DATA_ROOT`/`raw-data/` populated**; confirmed during package assembly) | Mixed — see note |
| XXI | Cross-dataset F1 for inline classifiers | `python3 baselines-cross-dataset/real-dataset-evaluation.py`, `baselines-cross-dataset/lbmd-unsw-nb15-crossval.py`, `baselines-cross-dataset/ctu13-csda-analysis.py`, `baselines-cross-dataset/bccc-tigcdo-analysis.py`, `baselines-cross-dataset/calibrate_from_cicdddos2019.py` (one script per dataset; each needs its own public dataset downloaded locally — see README.md) | Traced |

**Note on Table VII/XIV/XV and Table XI's script comments:** `run_tigcdo_eval.py`
was written and incrementally extended across paper revisions; its own inline
comments still refer to an earlier internal "Table I / Table II" numbering that
predates the current manuscript's Table I–XXI numbering. Running
`python3 run_tigcdo_eval.py` executes all three of its evaluation passes
(270-scenario CSDA comparison, 30-scenario FDCE sub-variant, phase-detection
test) in one invocation and prints every section to stdout in order; match
sections by content (column headers, metric names) rather than by the
script's own printed table label.

---

## Empirical grounding calibrations (Section VII.D)

These scripts ground specific paper constants in real third-party data. Two
(`calibrate_fdce_from_real_data.py`, `calibrate_applayer_from_real_data.py`)
run out of the box against data bundled in / fetched into this package. The
other five need a bulk public dataset that is **not** bundled here (see
"Public datasets used, not bundled" in README.md) — point `DDOS_RAW_DATA_ROOT`
at your local copy, or place it under `./raw-data/<n>-<name>/...` matching
the path printed near the top of each script.

| Script | Grounds | Dataset | Bundled? |
|---|---|---|---|
| `calibrate_fdce_from_real_data.py` | §VI.I FDCE / R-11 threshold, Table XX | Nigerian Banking Card Transactions | **Yes** (`data/ng-card-auth/`) |
| `calibrate_applayer_from_real_data.py` | §VI.A arrival-model / IAT separation | APA-DDoS | Fetched by `download_apa_ddos.py` (not redistributed — see README.md) |
| `calibrate_bim_js_cusum.py` | Table X, Table XIII (BIM JS-CUSUM) | Synthetic Monte Carlo (organic seasonality model) — no external dataset | N/A |
| `calibrate_drift_from_real_data.py` | BIM organic-drift bound (gap G4) | CESNET-TLS-Year22 (Zenodo doi:10.5281/zenodo.10608607) | No — external |
| `calibrate_edos_from_real_data.py` | Anti-EDoS / Vector E (gap G6) | Mendeley Denial-of-Wallet (doi:10.17632/g8g9vdxyvn.1) | No — external |
| `calibrate_scale_from_real_data.py` | PSRG per-source-rate premise (gap G5) | IoT-23 | No — external |
| `calibrate_tcs_from_real_data.py` | TCS organic/attack separation (gap G1) | Retailrocket | No — external |
| `calibrate_latency_from_real_data.py` | Service-latency/saturation constants (§VI.J) | RCAEval RE2-TT, microservices-ddos, Alibaba cluster-trace-v2021 | No — external |

Each of these five prints exactly which real-data file it could not find and
where it expected it, rather than failing silently or falling back to
fabricated numbers.

---

## What this package does NOT reproduce

Per the manuscript's own Data Availability Statement: the main 270-scenario
evaluation's per-configuration attack block rates, base false-positive
probabilities, and detection latencies (outside FDCE, which is real as of
v2) are **calibrated design targets with Monte Carlo sampling noise**, not
independent measurements — `run_tigcdo_eval.py` says this explicitly in its
own module docstring. Three items are specified in the paper but not
implemented in this package: cluster-level (rather than per-merchant) R-12
blocking, the PSRG stale-cache fail-open policy, and the cold-start standby
instance.
