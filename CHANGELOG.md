# Changelog

## v1.2.0 (2026-10, release date set by the GitHub release)

Accompanies the MDPI *Journal of Cybersecurity and Privacy* version of the
manuscript. Seed-42 SLA values, the FDCE results and every calibration output
are unchanged; the false-positive rates and the scenario description change.

Fixed

- `run_tigcdo_eval.py`: the false-positive rate used the denominator
  `n_processed - n_attack_total + n_legit_rejected`, which subtracts blocked
  attack transactions and counts rejected legitimate transactions twice. It is
  now `n_legit_rejected / n_legit_total`. TIG-CDO seed-42 FPR: 0.130% (old)
  to 0.057% (pooled over attack runs, exact 95% CI 0.021% to 0.123%); the
  50-seed mean is 0.078% against the configured 0.08%. (Review R1-009.)
- `run_tigcdo_eval.py`: the CSDA comparison ignored the TPS tier and the CSDA
  phase; only "attack active" and the intensity entered the computation. The
  grid is now described as what it computes: 4 distinct conditions per
  configuration run as 39 replicate runs (3 no-attack, 12 per intensity). The
  v1.1.0 run order is kept, so seed-42 SLA values are identical. The stale
  "270 scenarios" label is gone; `run_270_scenario_evaluation` remains as an
  alias of `run_csda_evaluation`. (Review R1-008.)
- `psrg/psrg.py`: the 1.2 ms P99 was described as "measured in Envoy WASM
  production"; no WASM filter was built or measured. Relabeled as a design target.
- `pado/pado.py`: the 340 ms "mean activation latency" is the configured
  sampling mean, not a measurement; docstring and self-test labels corrected.
- `generate_paper_figures.py`: Figure 2 was drawn from hard-coded values with
  two wrong C+ cells (days 8 and 10: 0.00086 and 0.00045; correct 0.00000 and
  0.00008). It now plots `BIM_PHASE2_TRACE.json`. The configuration heatmap
  (old Figure 5), which hard-coded the defective FPRs and a throughput value
  with a configured capacity bonus, is removed.
- `followup_analyses.json`: the checked-in file held an FDCE 50-seed band from
  an older FDCE model (mean 93.856); regenerated (mean 98.624, range 98.4 to
  98.8). FPR bands now use the corrected denominator.
- `requirements.txt`: `pyarrow>=14,<16`, because pyarrow 16 needs NumPy 2,
  which the NumPy pin excludes.
- `REPRODUCTION.md`: rewritten for the JCP numbering. The old entries that
  mapped "component latency measurements" (Tables VII/XIV) and a TCS threshold
  sweep (Table XV) to `run_tigcdo_eval.py` were wrong: the script prints
  neither. The latencies are design targets; the sweep is removed.

Added

- `tigcdo_eval_results.json`: machine-readable harness output (SLA, FPR over
  all runs, over attack runs, pooled with exact CI, per-condition breakdown).
- `trace_bim_phase2.py` and `BIM_PHASE2_TRACE.json`.
- `write_fdce_results.py`: writer for `FDCE_RULE_ENGINE_RESULTS.json`; it
  reproduces the v1.1.0 file byte for byte.
- `FOLLOWUP_OUT`, `TIGCDO_RESULTS_OUT`, `TRACE_OUT`, `FDCE_RESULTS_OUT`,
  `FIG_OUT` environment overrides, so a re-run can write outside the archived files.

Known open items (not fixed in v1.2.0)

- `fdce/scenario.py` `simulate_fdce_adversarial_spread` evaluates R-12 only
  until the first detection, so at most one merchant is blocked; its block
  rate is a harness artifact (review R1-006).
- `stc/stc.py` computes the structural TCS term only; the distributional term
  and the declined-terminal exemption are not implemented (review R1-003).
- `calibrate_fdce_from_real_data.py` and `data/manifests/` still describe the
  card dataset as real; its own dataset card says it is synthetic, and the R-11
  statistic should be computed as the detector does (review R1-001, R1-002).

## v1.1.0 (2026-10-10)

Card-authorization dataset moved off Git LFS into four ordinary parquet parts,
so the Zenodo archive holds the data (v1.0.0 held only an LFS pointer). Added
`k8s-testbed/`, `scenarios/`, `data/manifests/`, the remaining calibration
outputs, `.zenodo.json` and `SHA256SUMS`. Version DOI 10.5281/zenodo.23290076.

## v1.0.0 (2026-08-19)

Initial archived release (10.5281/zenodo.22005892).
