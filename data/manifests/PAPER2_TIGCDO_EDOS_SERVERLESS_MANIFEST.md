# TIG-CDO (paper2) — EDoS / Denial-of-Wallet (autoscaling-abuse) Anchor

**Paper:** `research-papers/ddos/paper2-solution/mainv4.md` / `ddos/paper2-solution/main.md`
**Added:** 2026-07-28 · **Dir:** `research-data/ddos-data/14-edos-serverless/`
**Gap closed:** **G6** (from `DATA_GROUNDING_REVIEW.md`) — **Vector E (Anti-EDoS / HPA sawtooth)** was described in the paper but **not evaluated** against any data. This grounds autoscaling-under-attack behavior.

## Why this data was needed
TIG-CDO's Vector E targets Economic Denial of Sustainability (EDoS): attackers abuse elastic autoscaling to inflate cost rather than deny service. The paper's anti-scaling policy had no data behind it — `11-microservice-latency/microservices-ddos` has resource metrics but **no autoscaling/invocation dynamics**. This dataset measures function invocation + concurrency directly.

## Dataset added
### `mendeley-dow/dataset.csv` — DoW attack detection in serverless
Mendeley Data `g8g9vdxyvn/1` (Ortega-Candel et al., Univ. Alacant) · **CC-BY-4.0** · Data-in-Brief peer-reviewed · **187,087 rows × 19 cols · 34.6 MB**
Direct: https://data.mendeley.com/datasets/g8g9vdxyvn/1

Schema: `Id, IP, bot, FunctionId, functionTrigger, timestamp, SubmitTime, RTT, InvocationDelay, ResponseDelay, FunctionDuration, ActiveFunctionsAtRequest, ActiveFunctionsAtResponse, maxcpu, avgcpu, p95maxcpu, vmcategory, vmcorecountbucket, vmmemorybucket`

- **Label `bot`:** True 131,072 (70.1%) / False 56,015 (29.9%).
- **functionTrigger:** notification 58,199 · sql 44,176 · http 32,293 · storage 31,064 · stream 21,355.
- **ActiveFunctionsAtRequest/Response:** concurrency 2–50 → the autoscaling signal.

**Maps to paper concepts:** `ActiveFunctionsAtRequest → ActiveFunctionsAtResponse` deltas + `InvocationDelay/ResponseDelay` under `bot=True` directly measure the **autoscaling sawtooth** Vector E abuses; grounds the anti-EDoS / HPA-throttle policy and lets us evaluate (not just describe) Vector E.

**Caveat (honest framing):** **fully synthetic** (simulator-generated invocation logs), and serverless FaaS — not the paper's K8s-HPA pod-scaling stack. Anchors the *cost/concurrency dynamics* of autoscaling abuse, not a specific orchestrator. For a reproducible K8s-HPA testbed, the review also flags SIGMETRICS'25 TeaStore/jMeter/Prometheus (build-your-own, no data released).

## Calibration run (2026-07-30)
Script `ddos/paper2-solution/implementation/calibrate_edos_from_real_data.py` → artifact `edos_calibration.json` (this dir). Seed 42.

Headline results (Vector E now **evaluated**, not just described):

| Signal | Result | What it grounds |
|---|---|---|
| **Per-request separability** | best feature `ActiveFunctionsAtRequest` Cohen's *d* = **0.64**; RTT/InvocationDelay/Duration *d* ≈ **0.04–0.15** (near-zero) | **Confirms the paper's thesis**: EDoS is weakly separable per-request → per-request detection fails → aggregate/economic defense required |
| **Source concentration** | bot **100 IPs → 1,311 invocations each** vs benign **7,487 IPs → 7.5 each** = **175× ratio** | Grounds **PSRG** transaction-context limits over per-IP limits |
| **Autoscaling sawtooth** | active functions scale **26 → 996** per request (**38.2×** amplification, bot) | The concurrency blow-up the **anti-EDoS cap** must bound |
| **Denial-of-Wallet cost** | bot drives **70% of total compute**; **174× cost-per-IP** vs benign | Quantifies the economic damage the policy prevents |

**Key reading:** the near-zero per-request *d* values are the point — they empirically validate the paper's claim (Table §IV.B) that Vector E "produces no correlated transaction state" and evades per-request thresholds. The attack is only visible in the **aggregate** (175× source concentration, 70% cost share on 100 IPs), which is exactly the layer PSRG + the anti-EDoS cap operate on.

## Recommended paper use (G6)
Replace "Vector E described but unevaluated" with these measured numbers: report the near-zero per-request separability as motivation, then the 175× source-concentration and 70% DoW cost-share as the empirical basis for PSRG + the anti-EDoS cap. Flag the synthetic + FaaS-vs-K8s caveat in Threats-to-Validity.

## Citation
- Ortega-Candel, J.M., Mora, H., Mora-Gimeno, F.J. *Generation of a dataset for DoW attack detection in serverless architectures.* Mendeley Data V1, 2023. doi:10.17632/g8g9vdxyvn.1 (CC-BY-4.0).
