# Manuscript Inserts — Real-Data Latency Calibration (v8)

Paste-ready text for `mainv2.md`, in the paper's voice/notation. Each insert states its exact
placement. Backed by `implementation/calibrate_latency_from_real_data.py` →
`research-data/ddos-data/11-microservice-latency/latency_calibration.json` and
`LATENCY_CALIBRATION_REPORT.md`. New references assigned: **[79]** (MicroservicesDDoS / Ficco ICNC 2025),
**[80]** (RCAEval / WWW 2025), **[81]** (Alibaba cluster-trace-microservices-v2021).

Core requested inserts are §IV.C, §V.A, §VI.H. Inserts 4–7 (§VIII, Data Availability, References) are
required so the new claims are citable and internally consistent.

---

## INSERT 1 — §IV.C STC, Complexity paragraph
**Placement:** append to the end of the **Complexity** paragraph (after line 344, "...approximately 260,000 events per second.").

> This $O(k \log n)$ design target is consistent with real production call-graph density. On a slice of
> the Alibaba 2021 microservices trace [81] (6.0 M call-graph events across 7,377 microservice nodes), the
> directed call graph exhibits a fan-out of 2.24 edges per node, i.e. $k$ in the 2--8 range assumed above,
> confirming that the per-event update touches a small, bounded neighbourhood rather than a dense graph.
> The measured slice sustains $\approx$20{,}000 call events/s; the 260{,}000 events/s STC target therefore
> sits $\approx$13$\times$ above this real-production rate, a head-room that the asynchronous, index-backed
> update path is designed to absorb (production-scale throughput validation remains future work, Section VIII).

---

## INSERT 2 — §V.A Calibration sources
**Placement (2a):** replace the **Calibration sources** table (lines 589--596) with the version below — the
last three rows are new and the "Type" column now distinguishes parameters that have gained an independent
real-data anchor.

> | Parameter | Source | Type |
> |---|---|---|
> | STC latency (3.1 ms / 8.4 ms P99) | TAADA microbenchmarks in [1] | Design target |
> | PSRG inline overhead (0.9 ms / 1.2 ms P99) | Envoy WASM literature; TAADA budget | Design target |
> | XGBoost inline (0.079 ms / 0.170 ms P99) | LBMD measurement in [1] | Microbenchmark |
> | Per-configuration block efficiency | Component-model derivation | Derived |
> | Per-configuration mean legit latency (`_LATENCY_PARAMS`) | Solved to match block efficiency; **triangulated against real production RPC RT [81]** | Back-derived + trace-anchored |
> | Per-configuration attack/degraded latency multiplier | Solved to match block efficiency; **bounded against real network-fault degradation [80]** | Back-derived + trace-anchored |
> | Network saturation model (`SATURATION_THRESHOLD`, residual-load → degradation) | Component model; **per-vector severity from DDoS-on-microservices telemetry [79]** | Derived + trace-anchored |
> | STC call-graph fan-out / throughput ($O(k\log n)$, 260k events/s) | Design analysis; **anchored to real call-graph density [81]** | Design target + trace-anchored |
> | FPR per configuration | Calibration target from companion paper [1] | Configured |

**Placement (2b):** insert the following paragraph immediately **after** the "What the simulation can and
cannot show" paragraph (after line 600), as a new bolded paragraph in §V.A.

> **Trace-calibration against real microservice telemetry.** To reduce the reliance of the latency layer on
> back-derived constants, three public real-microservice datasets were used as out-of-sample anchors
> (calibration scripts and the derived JSON are in the replication package; seed 42). (1) *Legitimate per-hop
> latency.* The Alibaba 2021 production microservices trace [81] yields a mean per-RPC response time of
> 29.6 ms (n = 2.35 M; p50 = 9.9 ms, p95 = 105.7 ms), which brackets the simulator's 27 ms `_LATENCY_PARAMS`
> legit constant — an independent production anchor for a value that was previously only back-solved.
> (2) *Degradation under network stress.* On TrainTicket traces from the RCAEval benchmark [80] under
> injected network-delay and packet-loss faults (10 scenarios, 58 K root spans), end-to-end request latency
> degrades by a factor of 1.97$\times$; the simulator's assumed attack/legit ratio (73.3/27.0 = 2.71$\times$)
> is therefore *more pessimistic* than this real injected-fault reference, so the headline does not depend on
> an inflated slowdown. (3) *Per-vector saturation.* On a DDoS-on-microservices benchmark collected on the
> same TrainTicket payment system [79], system-wide inbound network volume under attack relative to a
> no-attack baseline is 114.7$\times$ (classic volumetric DDoS), 62.1$\times$ (slow DDoS), 4.75$\times$ (SYN
> flood), and 1.32$\times$ (GET flood), grounding the residual-load → degradation saturation model and its
> per-vector ordering. These anchors corroborate the *direction and order of magnitude* of the latency layer;
> they do not convert the simulation into an end-to-end production measurement, and the boundary stated above
> continues to apply.

---

## INSERT 3 — §VI.H Sensitivity Analysis, new subsection
**Placement:** insert after the **BIM Drift Threshold Sweep** table (after line 878), before §VI.I.

> **Latency-Distribution Sensitivity (Real-Trace Re-run).** The headline SLA figures use Gaussian
> `_LATENCY_PARAMS`. To test their dependence on that distributional assumption, the SLA computation was
> re-run on a *real* per-hop latency distribution: legitimate latencies are bootstrap-sampled from the
> Alibaba production RPC response-time distribution [81] and scaled, under the simulator's saturation model,
> by the real 1.97$\times$ network-fault degradation factor from RCAEval [80] (block rate held at the 0.95
> design target; only the latency distribution is swapped).
>
> | Latency model | TIG-CDO SLA | No-defense SLA | TIG-CDO advantage |
> |---|---|---|---|
> | Simulator Gaussian (`_LATENCY_PARAMS`) | 100.0% | 44.9% | +55.1 pp |
> | Real production RT distribution [80], [81] | 88.1% | 80.9% | +7.2 pp |
>
> Two findings follow. First, the TIG-CDO $>$ no-defense ordering is preserved on the real distribution,
> because effective blocking keeps residual attack load below the saturation threshold. Second, real
> production RPC latency is heavy-tailed (p95 = 105.7 ms $\gg$ the 50 ms budget), so the achievable SLA at a
> 50 ms budget is $\approx$88% even with near-perfect blocking. The 98.3% headline is therefore load-bearing
> on the tight-Gaussian / 50 ms-budget modelling assumption rather than on the block rate; production
> deployments with heavier-tailed latency should expect a lower absolute SLA at the same budget and are
> advised to monitor the P95/P99 latency distribution shape (Section VIII-C, T-CV3) alongside the
> single-threshold SLA metric.

---

## INSERT 4 — §VIII.C T-CV3, quantify the heavy-tail caveat
**Placement:** append to the end of **T-CV3** (after line 1103, "...directional lower bound on real-system FPR.").

> This thin-tail limitation is now quantified: re-running the SLA computation on a real, heavy-tailed
> production RPC latency distribution [81] (Section VI-H) yields a projected TIG-CDO SLA of 88.1% versus the
> 98.3% Gaussian projection, while preserving the TIG-CDO-over-no-defense ordering. The absolute SLA
> percentages should accordingly be read as upper bounds attainable under a tight-tailed latency regime; the
> *relative* defense ordering is the more transportable result.

---

## INSERT 5 — §VIII.B External Validity, new threat
**Placement:** insert as a new item after **T-EV5** (after line 1087).

> **T-EV6: Latency / detection constants calibrated against non-payment and injected-fault traces.** The
> service-latency layer is triangulated against three real-microservice datasets (Section V-A): production
> RPC response time [81], injected network-fault degradation on TrainTicket [80], and DDoS-on-microservices
> telemetry on TrainTicket [79]. These corroborate the legit-latency magnitude (29.6 ms vs. the 27 ms
> constant) and bound the degradation factor (real 1.97$\times$ vs. assumed 2.71$\times$), but none is a
> production card-payment trace under a real adversarial DDoS: [80] uses injected RCA faults rather than
> adversarial attacks, [81] is general (non-payment, no-attack) production traffic, and [79] captures
> container/resource telemetry rather than per-request authorization latency. Moreover, the detection-latency
> constant `_DET_LATENCY` (1.8 s for full Phase 3; 44--62 s for FDCE) remains a *design target*: the labelled
> DDoS-on-microservices data [79] is sampled at a 5 s cadence and can confirm only that the attack is
> detectable within one sample, not sub-second detection timing. *Mitigation:* the constants are reported as
> trace-anchored where a real anchor exists and as design targets otherwise; an end-to-end measurement on a
> payment-representative testbed under adversarial DDoS is named as future work.

---

## INSERT 6 — Data Availability Statement
**Placement:** append to the end of the Data Availability paragraph (line 1174, before the closing period or as a new sentence).

> The latency-layer trace-calibration adds three public datasets and two scripts to the replication package:
> the DDoS-on-microservices benchmark [79], the RCAEval microservice-telemetry benchmark [80] (CC-BY-4.0),
> and a slice of the Alibaba 2021 microservices trace [81], together with
> `calibrate_latency_from_real_data.py` (and the existing `calibrate_fdce_from_real_data.py`) and their
> derived calibration JSON. No real or semi-real cardholder data is used by any of these datasets.

---

## INSERT 7 — References
**Placement:** append after [78] (line 1334).

> [79] M. Ficco, P. Fusco, A. Guerriero, R. Pietrantuono, M. Russo, F. Palmieri, and S. Russo, "A benchmark
> for DDoS attacks detection in microservice architectures," in *Proc. Int. Conf. Comput. Netw. Commun.
> (ICNC)*, 2025, pp. 345--349, doi: 10.1109/ICNC64010.2025.10994136. Dataset:
> https://github.com/iotresearchunisa/MicroservicesDDoS
>
> [80] L. Pham, H. Ha, and H. Zhang, "RCAEval: A benchmark for root cause analysis of microservice systems
> with telemetry data," in *Companion Proc. ACM Web Conf. (WWW)*, 2025. Dataset: Zenodo, doi:
> 10.5281/zenodo.14590730 (CC-BY-4.0).
>
> [81] Alibaba Group, "cluster-trace-microservices-v2021," GitHub repository, 2022. [Online]. Available:
> https://github.com/alibaba/clusterdata ; see also S. Luo et al., "Characterizing microservice dependency
> and performance: Alibaba trace analysis," in *Proc. ACM Symp. Cloud Comput. (SoCC)*, 2021.

---

## One-line abstract/headline note (optional)
If the abstract or §I.D contribution 5 restates 98.3% without qualification, prepend the existing
"simulator-projected under stated modelling assumptions" qualifier with: "...and validated for legit-latency
magnitude and degradation factor against real microservice traces [79]--[81] (Section V-A), with a real
heavy-tailed-distribution SLA sensitivity of 88.1% reported in Section VI-H." Keep it to one clause to respect
the IEEE TNSM ~250-word abstract target.

## Consistency note (pre-existing, unaffected)
These inserts do not touch the separate, still-open 93.8%-artifact-vs-96.1%-text FDCE SLA discrepancy
(§VI.I) flagged in the FDCE calibration; reconcile that independently.
