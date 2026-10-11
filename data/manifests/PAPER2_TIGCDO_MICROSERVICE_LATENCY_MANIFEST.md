# TIG-CDO (paper2) — Microservice Latency & DDoS-in-Microservices Data

**Paper:** `research-papers/ddos/paper2-solution/mainv2.md` — *Transaction Intent Graph:
Semantic Cross-Layer Defense Orchestration for Microservices Payment Systems* (IEEE TNSM, rev v7)
**Added:** 2026-06-19 · **Dir:** `research-data/ddos-data/11-microservice-latency/`

---

## Why this data was needed (the gap these fill)

The v5–v7 cross-venue reviews' systemic finding is that the **entire evaluation is
simulator-projected from configured constants**, not measurement. Prior calibration work grounded
two layers:

- **Network-IAT layer** → CICDDoS2019 (Cohen's *d* = 0.71). [`01-benchmark/cic-ddos2019/`]
- **Payment-authorization layer** → `ng-card-auth` FDCE decline mix. [`10-payment-fraud/`]

The layer that was *still* 100% fabricated is the **service-latency-under-attack model** in
`implementation/run_tigcdo_eval.py` — the load-bearing driver of the headline 98.3% SLA:

| Constant in `run_tigcdo_eval.py` | What it is now | What these datasets ground it with |
|---|---|---|
| `_LATENCY_PARAMS` (legit 27 ms → attack 73 ms) | back-calculated from target SLA | **real per-container service latency / RT under DDoS vs. idle** |
| `SATURATION_THRESHOLD` (0.05) + saturation interpolation | hand-set model | real resource-saturation curves (CPUThrottling, PacketsDropped) vs. load |
| `_ATTACK_BLOCK` (tig_cdo 0.95) | configured | labeled benign/malicious flow under 4 DDoS types (detectability ceiling) |
| `_DET_LATENCY` (tig_cdo 1.8 s) | "from Table I/II" | **5-second attack-onset labels** → measurable time-to-detect |
| STC graph `O(k log n)` @ 260k events/s (§IV.C) | design target | real production call-graph fan-out + update rate (Alibaba) |

These are realism/calibration anchors, not production ground truth — see caveats per dataset.

---

## Datasets added

### 1. `microservices-ddos/` — ⭐ primary: DDoS *against a microservice payment system*
`github.com/iotresearchunisa/MicroservicesDDoS` (Ficco et al., **ICNC 2025**, doc 10994136) · ~39 MB
Projects: SERICS / FLEGREA / uDEVOPS (H2020 MSCA 871342). **License: not stated in repo — research
use, cite the ICNC 2025 paper; confirm reuse terms before redistribution.**

**Why it is the best topical fit in the whole archive:** collected on the **TrainTicket** microservice
benchmark — the captured pods include `ts-inside-payment-service`, `ts-voucher-service`,
`ts-gateway-service`, etc. i.e. **payment microservices under live DDoS**, which is exactly TIG-CDO's
subject (cross-layer DDoS defense for microservices payment systems). Same TrainTicket system as
RCAEval below, so the two are mergeable.

Structure: 4 attack scenarios + baseline, each in `Idle/` and `Load/` conditions —
`Classic DDoS/`, `Slow DDoS/`, `SYN Flood/`, `GET Flood/`, `No attacks/`. Per-scenario CAdvisor +
kube-state metric CSVs (wide format, one column-pair per container, ~5 s cadence):
`NetworkIO`, `PacketsDropped`, `CPUUsage`, `CPUThrottling`, `MemoryUsage`, `ContainerUsage`,
`ResourceLimits`, `PodReady`, `Restarts`. Plus `labels.csv` (`Timestamp; ClassificationValue` 0/1 at
5 s) and `PreprocessedData.zip` (aggregated ML-ready table).

Maps to paper concepts:
- `NetworkIO` + `PacketsDropped` under Load vs. No-attacks → real **saturation curve** → replace the
  hand-set `SATURATION_THRESHOLD`/interpolation; derive residual-load → degradation mapping (§V.B).
- `CPUThrottling` / `CPUUsage` divergence attack-vs-baseline → service-degradation proxy for
  `_LATENCY_PARAMS` (no direct per-request RT here — use Alibaba/RCAEval for RT distributions).
- `labels.csv` 5 s onset labels → **measurable detection latency** to sanity-check `_DET_LATENCY` 1.8 s.
- Four distinct DDoS types (volumetric Classic/SYN/GET vs. low-rate Slow) → per-vector blocking /
  detectability spread to replace the single `_ATTACK_BLOCK` constant with a per-vector range.

**Caveat:** metrics are container/resource time series, not per-transaction latency; Slow DDoS is
low-rate (different signal than volumetric). Single TrainTicket deployment on minikube.

### 2. `rcaeval/` — microservice telemetry under network faults (latency-under-degradation)
Zenodo **14590730** (RCAEval, WWW 2025 companion) · CC-BY-4.0 · ~5.1 GB (9 zips: RE1/RE2/RE3 ×
OB/SS/TT). Online Boutique (OB), Sock Shop (SS), **Train Ticket (TT)**; 735 failure cases over 11
fault types including **network delay** and **packet loss** — the closest open analogue to
DDoS-induced latency. Metrics + traces give real per-service **response-time distributions** under a
network-degradation fault vs. normal.

Use: fit legit-vs-degraded RT distributions (mean/std/tail) from TT (payment-relevant) to replace the
back-calculated `_LATENCY_PARAMS` (27 ms → 73 ms) and the Gaussian saturation model with a
trace-driven one; report headline-SLA sensitivity to real vs. assumed latency curves.

**Caveat:** faults are injected RCA scenarios (network delay/packet-loss), not adversarial DDoS;
use for the *latency-degradation shape*, pair with `microservices-ddos/` for the attack semantics.

### 3. `alibaba-microservices-v2021/` — production call-graph + RPC response-time (graph scale)
`alibaba/clusterdata` v2021 microservices trace · OSS `aliopentrace.oss-cn-beijing` · **slice, not full
61 GB** — `MSRTQps_{0,1}` (RPC/HTTP/MQ response-time + call-rate), `MSCallGraph_0` (per-call `rt` +
directed `um`→`dm` edges), `MSResource_0` (container CPU/mem), `Node_0`.

Use: real production **RPC response-time** distribution → independent anchor for `_LATENCY_PARAMS`
legit baseline; `MSCallGraph` directed `um→dm` multigraph at ~17k+ microservices → stress-test STC
graph construction / `O(k log n)` update cost and the 260k-events/s throughput target (§IV.C, §VII.A),
analogous to how `ibm-aml-graph/` grounds the payment-graph side.

**Caveat:** general Alibaba microservices (not payment-specific, not under attack); use for RT-baseline
realism and graph-scale, not attack semantics. Slice = a few time windows, not the full 13-day trace.

---

## Suggested next analysis steps
1. From `microservices-ddos/`, compute NetworkIO/PacketsDropped/CPUThrottling deltas (Load attack vs.
   No-attacks) per DDoS type → real saturation curve + per-vector detectability; replace
   `SATURATION_THRESHOLD` and give `_ATTACK_BLOCK` a measured per-vector range.
2. From `rcaeval/` TT, fit benign-vs-network-fault RT distributions → trace-driven `_LATENCY_PARAMS`;
   re-run the N=50-seed eval, report SLA sensitivity (mirrors the FDCE calibration pattern).
3. From `microservices-ddos/labels.csv`, derive time-from-onset-to-detectable-shift → empirical bound
   on `_DET_LATENCY` (1.8 s).
4. From `alibaba-microservices-v2021/MSCallGraph_0`, benchmark real STC graph-update throughput vs. the
   260k-events/s design target.

All loadable with `pandas`/`pyarrow`. Seed 42 per paper convention.

## Calibration run (2026-06-19) — latency layer grounded
Script `paper2-solution/implementation/calibrate_latency_from_real_data.py` →
artifact `latency_calibration.json` (this dir); report
`paper2-solution/implementation/LATENCY_CALIBRATION_REPORT.md`.

Headline results:
- **Alibaba production RPC RT mean = 29.6 ms validates the simulator's 27 ms legit constant** (real
  independent anchor, n=2.35M).
- **Real degradation under network fault = 1.97× (RCAEval) < simulator's assumed 2.71×** → the sim is
  conservative on per-hop slowdown; the headline is not built on an inflated number.
- **Per-vector saturation (real NetworkIO):** Classic DDoS ×114.7, Slow DDoS ×62.1, SYN ×4.75,
  GET ×1.32 vs no-attack baseline → grounds the saturation model + per-vector ordering.
- **SLA re-run on the real heavy-tailed RT distribution:** TIG-CDO 88.1% vs no-defense 80.9%
  (ordering holds); the 98.3% headline is **load-bearing on the 50 ms-budget / tight-Gaussian
  assumption**, not the block rate — must be stated in §V.A.
- **Detection:** 5 s label cadence cannot validate the 1.8 s `_DET_LATENCY` claim (present as design target).
- **Graph scale:** real call-graph fan-out 2.24 edges/node, 20k events/s slice (260k/s target = 13× headroom).

Honest scope: block rates are TIG-CDO design targets, NOT measured; only the latency distribution was
swapped to real values. Pre-existing paper-vs-artifact gap (93.8% vs 96.1% FDCE SLA) still to reconcile.

## Citations to add
- Ficco, Fusco, Guerriero, Pietrantuono, Russo, Palmieri, Russo. *A Benchmark for DDoS Attacks
  Detection in Microservice Architectures.* ICNC 2025, pp. 345–349. DOI 10.1109/ICNC64010.2025.10994136.
- Pham et al. *RCAEval: A Benchmark for Root Cause Analysis of Microservice Systems with Telemetry
  Data.* WWW 2025 Companion. Zenodo 10.5281/zenodo.14590730 (CC-BY-4.0).
- Alibaba *cluster-trace-microservices-v2021*, `github.com/alibaba/clusterdata`.
