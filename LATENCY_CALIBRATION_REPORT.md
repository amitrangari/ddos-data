# Service-Latency-Under-Attack Calibration from Real Microservice Data — Report

**Date:** 2026-06-19 · **Script:** `calibrate_latency_from_real_data.py` · **Seed:** 42
**Artifact:** `research-data/ddos-data/11-microservice-latency/latency_calibration.json`
**Data:** `research-data/ddos-data/11-microservice-latency/` (RCAEval RE2-TT, MicroservicesDDoS, Alibaba v2021 slice)

## Purpose
Ground the service-latency / saturation / detection constants in `run_tigcdo_eval.py`
(`_LATENCY_PARAMS` legit 27 ms → attack 73.3 ms, `SATURATION_THRESHOLD` 0.05, `_DET_LATENCY`,
`_ATTACK_BLOCK`) that drive the headline 98.3% SLA, replacing back-calculated constants with real
measured distributions. Companion to the network-IAT (CICDDoS2019) and FDCE (`ng-card-auth`)
calibrations — this closes the third, previously-fabricated layer.

## Findings

**1. Real per-hop legit latency validates the 27 ms constant.** Alibaba v2021 production RPC
response-time (n = 2.35 M `*_RT` records): **mean 29.6 ms** (p50 9.9, p95 105.7). The simulator's
`_LATENCY_PARAMS` legit constant (27.0 ms) sits squarely inside the real production per-hop RT
distribution — an independent anchor, not a back-calculation.

**2. Real degradation under network stress is *milder* than assumed (sim is conservative).** RCAEval
TrainTicket end-to-end request latency under injected network-delay + packet-loss faults (10
scenarios, 58 K root spans): legit mean **286.8 ms** → degraded mean **564.0 ms**, a **1.97× slowdown**
(Cohen's *d* = 0.46). The simulator assumes attack/legit = 73.3/27.0 = **2.71×**. So the configured
degradation is *more pessimistic* than the real injected-fault data — the headline does not rely on an
inflated slowdown. (RCAEval root spans are end-to-end multi-hop, so only the *ratio* is portable to the
simulator's per-hop frame, not the absolute ms.)

**3. Per-vector saturation severity (real).** MicroservicesDDoS, system-wide NetworkIO under attack-Load
vs No-attack-Load on TrainTicket:

| DDoS vector | NetworkIO severity | Note |
|---|---|---|
| Classic DDoS | **×114.7** | volumetric — dominant network saturation |
| Slow DDoS    | ×62.1 | low-rate but sustained inbound |
| SYN Flood    | ×4.75 | handshake-level |
| GET Flood    | ×1.32 | application-level, low byte-volume |

This grounds the *saturation model* (residual-load → degradation) and gives a real per-vector ordering
to replace the single hand-set `_ATTACK_BLOCK`/saturation constant with a measured range. CPUThrottling
was *lower* under attack than under the no-attack load baseline (0.5–0.71×) — not a clean saturation
signal here; PacketsDropped did not register at pod level (≈0). NetworkIO is the load-bearing signal.

**4. Detection-latency claim is below the data's resolution (honest scope).** MicroservicesDDoS labels
are at **5 s cadence** (3,587 samples, 79.9% attack). This **cannot validate** the paper's 1.8 s
`_DET_LATENCY` claim; it confirms only that the attack is detectable within one sample (NetworkIO ≫
baseline). The sub-2 s detection claim should be presented as a design target, not a measured value.

**5. Graph scale (real production fan-out).** Alibaba MSCallGraph slice: 6 M call events over 300 s =
**20 k events/s**; 7,377 microservice nodes, 16,524 directed `um→dm` edges, **fan-out 2.24 edges/node**.
The 260 k-events/s STC design target is **13× above** this real production slice — anchors the
`O(k log n)` STC update-cost claim against real call-graph density rather than a synthetic generator.

**6. SLA re-run on the real per-hop distribution.** Bootstrapping the real Alibaba RT distribution and
scaling by the real RCAEval 1.97× degradation under the simulator's saturation model (50 ms budget,
TIG-CDO block 0.95 held as design target):

| | TIG-CDO SLA | No-defense SLA | Advantage |
|---|---|---|---|
| Real RT distribution | **88.1%** | 80.9% | +7.2 pp |
| Sim Gaussian constants | 100.0% | 44.9% | +55.1 pp |
| Paper headline | 98.3% | — | — |

The TIG-CDO > no-defense ordering **holds** on real data. But real production RT is **heavy-tailed**
(p95 = 105 ms ≫ 50 ms budget), so the achievable SLA at a 50 ms budget is ~88% even with near-perfect
blocking — i.e. **the 98.3% headline is load-bearing on the tight-Gaussian (std 6 ms) / 50 ms-budget
assumption**, not on the block rate. This should be stated explicitly in §V.A / §VI.

## What to change in the manuscript
- §IV/§V: cite Alibaba RT (29.6 ms) as the real anchor for the 27 ms legit latency; cite RCAEval 1.97×
  as a (conservative) real degradation reference vs. the assumed 2.71×.
- §V.A: state that the headline SLA assumes a tight per-hop latency distribution and a 50 ms budget;
  acknowledge real production RT is heavy-tailed and report the real-distribution SLA (~88%) as a
  sensitivity point.
- §VI: present `_DET_LATENCY` (1.8 s) as a design target; the available labeled DDoS-on-microservices
  data resolves detection only to its 5 s sampling cadence.
- §IV.C/§VII.A: anchor the 260 k-events/s STC throughput / `O(k log n)` claim to the real Alibaba
  call-graph density (2.24 edges/node), noting the 13× headroom over the measured slice.

## Caveats
RCAEval faults are injected network delay/packet-loss (RCA scenarios), not adversarial DDoS — used for
the latency-degradation *shape/ratio*, paired with MicroservicesDDoS for attack semantics.
MicroservicesDDoS is container/resource telemetry, not per-request latency, at 5 s cadence (no stated
license — cite ICNC 2025). Alibaba is general (non-payment, no-attack) production microservices — used
for RT-baseline realism and graph scale only; a few time-windows scanned (6 M-row cap). **Block rates
are TIG-CDO design targets and are NOT measured here**; the SLA re-run swaps only the latency
distribution to real values.

## Reproduce
```
cd implementation && python3 calibrate_latency_from_real_data.py
```
