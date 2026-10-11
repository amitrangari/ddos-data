# Local Test Results

**Generated:** 2026-03-19 01:02:48 UTC

**Configuration:** attack=bin_enumeration, intensity=medium, TAADA=enabled

## Results

```
===================================================================
=== DDoS Defense Testbed Results (local-test.py) ===
Duration: 120s | Attack: bin_enumeration | Intensity: medium
===================================================================

BASELINE (no attack):
  Legitimate TPS:  100.0
  Mean Latency:    20.8ms
  P99 Latency:     27.4ms
  SLA Compliance:  100.0%

UNDER ATTACK (TAADA enabled):
  Legitimate TPS:  100.0
  Mean Latency:    25.6ms
  P99 Latency:     32.4ms
  SLA Compliance:  100.0%
  Defense Bundle:  [ebpf_xdp + bin_watch + rate_limit_per_bin + waf]
  Delta_budget:    17.1ms remaining
  TAADA activation latency: 0.0s
  BIN-WATCH:       F1=0.889 | Precision=0.800 | Recall=1.000 | FPR=0.500

RECOVERY (post-attack):
  Legitimate TPS:  100.0
  SLA Compliance:  100.0%

TAADA EFFECTIVENESS: SLA compliance 100.0% -> 100.0% under attack
===================================================================
```

## TAADA Impact Analysis

| Scenario | SLA Compliance | Mean Latency | P99 Latency |
|----------|---------------|-------------|-------------|
| Baseline (no attack) | 100.0% | 20.8ms | 27.4ms |
| Under Attack + TAADA | 100.0% | 25.6ms | 32.4ms |

## Defense Details

**TAADA Defense Bundle:** ['ebpf_xdp', 'bin_watch', 'rate_limit_per_bin', 'waf']

**Delta_budget remaining:** 17.1ms

**TAADA Activation Latency:** 0.0s

## BIN-WATCH Detection Metrics

| Metric | Value |
|--------|-------|
| F1 Score | 0.889 |
| Precision | 0.800 |
| Recall | 1.000 |
| False Positive Rate | 0.500 |
| True Positives | 120 |
| False Positives | 30 |
| False Negatives | 0 |
| True Negatives | 30 |

## Raw Results JSON

```json
{
  "config": {
    "attack_type": "bin_enumeration",
    "intensity": "medium",
    "taada_enabled": true,
    "bin_watch_enabled": true,
    "acs_guard_enabled": true,
    "baseline_s": 30,
    "attack_s": 120,
    "recovery_s": 30
  },
  "phases": {
    "baseline": {
      "mean_latency_ms": 20.83,
      "p99_latency_ms": 27.44,
      "sla_compliance_rate": 1.0,
      "mean_legit_tps": 100.0,
      "mean_bes": 3.887,
      "max_bes": 4.093,
      "ticks": 30
    },
    "attack_no_defense": {},
    "attack_with_defense": {},
    "recovery": {
      "mean_latency_ms": 19.8,
      "p99_latency_ms": 26.99,
      "sla_compliance_rate": 1.0,
      "mean_legit_tps": 100.0,
      "mean_bes": 7.598,
      "max_bes": 7.685,
      "ticks": 30
    },
    "attack": {
      "mean_latency_ms": 25.63,
      "p99_latency_ms": 32.44,
      "sla_compliance_rate": 1.0,
      "mean_legit_tps": 100.0,
      "mean_bes": 7.486,
      "max_bes": 8.008,
      "ticks": 120
    }
  },
  "bin_watch": {
    "f1_score": 0.889,
    "precision": 0.8,
    "recall": 1.0,
    "false_positive_rate": 0.5,
    "tp": 120,
    "fp": 30,
    "fn": 0,
    "tn": 30
  },
  "taada": {
    "defense_bundle": [
      "ebpf_xdp",
      "bin_watch",
      "rate_limit_per_bin",
      "waf"
    ],
    "delta_budget_ms": 17.1,
    "activation_latency_s": 0.0,
    "bundle_activations": 1
  }
}
```
