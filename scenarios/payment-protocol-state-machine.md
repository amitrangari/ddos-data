# Payment Protocol State Machine

**Shared resource for Paper 1 (Survey) and Paper 2 (TIG-CDO Solution)**

This document defines the ISO 8583 + EMVCo 3DS payment protocol state machine that the
Transaction Intent Graph (TIG) uses as its semantic layer for anomaly detection and
Cross-Layer Defense Orchestration (CDO).

---

## 1. ISO 8583 Message Flow

### 1.1 Normal Authorization Flow

```
Merchant/POS                Acquirer                    Issuer
    |                          |                           |
    |--- 0100 AuthReq -------->|                           |
    |                          |--- 0100 AuthReq --------->|
    |                          |<-- 0110 AuthResp ---------|
    |<-- 0110 AuthResp --------|                           |
    |                          |                           |
    |--- 0200 Completion ----->|                           |
    |                          |--- 0200 Completion ------>|
    |                          |<-- 0210 CompletionResp ---|
    |<-- 0210 CompletionResp --|                           |
```

### 1.2 Reversal Flow (triggered on timeout or merchant cancellation)

```
Merchant/POS                Acquirer                    Issuer
    |                          |                           |
    |--- 0400 Reversal ------->|                           |
    |                          |--- 0400 Reversal -------->|
    |                          |<-- 0410 ReversalResp -----|
    |<-- 0410 ReversalResp ----|                           |
```

### 1.3 Message Types and Timing Constraints

| MTI  | Name                  | Direction            | Expected Window        |
|------|-----------------------|----------------------|------------------------|
| 0100 | Authorization Request | POS → Acquirer       | T=0 (baseline)         |
| 0110 | Authorization Response| Acquirer → POS       | T+0 to T+2s (normal)  |
| 0200 | Financial Request     | POS → Acquirer       | T+0s to T+60s          |
| 0210 | Financial Response    | Acquirer → POS       | T(0200)+0 to T(0200)+2s|
| 0400 | Reversal Request      | POS → Acquirer       | T+0s to T+86400s       |
| 0410 | Reversal Response     | Acquirer → POS       | T(0400)+0 to T(0400)+2s|

**Anomaly signal:** 0100 with no subsequent 0200 or 0400 within 120s → orphaned auth (BIN probe indicator).

---

## 2. EMVCo 3DS 2.x Flow

### 2.1 Message Sequence

```
Cardholder/Browser         3DS Requestor             ACS (Issuer)
    |                          |                           |
    |                          |--- AReq (AuthReq) ------->|
    |                          |<-- ARes (AuthResp) --------|
    |                          |                           |
    |<-- Challenge UI ---------|                           |
    |--- CReq (Challenge) ---->|                           |
    |                          |--- CReq (Challenge) ----->|
    |                          |<-- CRes (ChallengeResp) --|
    |<-- Auth Result ----------|                           |
    |                          |                           |
    |--- ISO 8583 0100 ------->| (with 3DS data in DE48)  |
```

### 2.2 3DS Message Types and Timing Constraints

| Message | Name                       | Expected Window           |
|---------|----------------------------|---------------------------|
| AReq    | Authentication Request     | T=0 (baseline)            |
| ARes    | Authentication Response    | T+0 to T+3s (frictionless)|
| CReq    | Challenge Request          | T(ARes)+0 to T(ARes)+300s |
| CRes    | Challenge Response         | T(CReq)+0 to T(CReq)+120s|
| Result  | Authentication Result      | Embedded in ISO 8583 0100 |

**Anomaly signal:** AReq with no CReq and no subsequent ISO 8583 0100 within 600s → abandoned session.
**Anomaly signal:** Multiple AReq from same BIN within 10s without CReq → frictionless probing.

---

## 3. Tokenization Flow (EMVCo / Network Tokens)

### 3.1 Token Provisioning

```
Merchant / Wallet           Token Service Provider (TSP)    HSM
    |                               |                         |
    |--- Token Request ------------>|                         |
    |                               |--- HSM Token Gen ------>|
    |                               |<-- Token + Cryptogram --|
    |<-- Token Response ------------|                         |
    |    (Token PAN, expiry,        |                         |
    |     TAVV/CAVV cryptogram)     |                         |
```

### 3.2 Token-Based Authorization

```
Merchant                   Acquirer                    Network / Issuer
    |                          |                              |
    |--- 0100 (Token PAN) ---->|                              |
    |                          |--- Detokenization + 0100 --->|
    |                          |                              |
    |                          |<-- 0110 (Real PAN masked) ---|
    |<-- 0110 -----------------|                              |
```

### 3.3 Timing Constraints

| Step             | Expected Window                                   |
|------------------|---------------------------------------------------|
| Token Provision  | Async; valid for token lifetime (days to years)   |
| Token → 0100     | TAVV cryptogram window: ≤30s from generation      |
| 0100 → 0110      | T+0 to T+2s (same as standard auth)               |

**Anomaly signal:** TAVV cryptogram used in multiple 0100 messages → token replay attack.
**Anomaly signal:** Token PAN with mismatched BIN prefix vs. expected network range → forged token.

---

## 4. Coherence Rules: Protocol-Valid vs. Anomalous Sequences

### 4.1 Valid State Transitions

```
[IDLE] ---(0100 received)---> [AUTH_PENDING]
[AUTH_PENDING] ---(0110 approve)---> [AUTH_APPROVED]
[AUTH_PENDING] ---(0110 decline)---> [AUTH_DECLINED]
[AUTH_APPROVED] ---(0200 within 60s)---> [COMPLETION_PENDING]
[COMPLETION_PENDING] ---(0210)---> [COMPLETED]
[AUTH_APPROVED] ---(0400 before 0200)---> [REVERSAL_PENDING]
[REVERSAL_PENDING] ---(0410)---> [REVERSED]
[AUTH_DECLINED] ---(no further messages)---> [TERMINAL]
```

### 4.2 Anomalous Sequences (CSDA Indicators)

| Rule ID | Anomaly                                      | TIG Signal                |
|---------|----------------------------------------------|---------------------------|
| R-01    | 0100 with no 0110 within 5s                  | Acquirer timeout / flood  |
| R-02    | 0100 with no 0200/0400 within 120s           | Orphaned auth / BIN probe |
| R-03    | >10 0100 from same BIN within 1s             | BIN enumeration burst     |
| R-04    | 0200 before 0110                             | Protocol violation        |
| R-05    | 0400 referencing unknown STAN                | Reversal injection        |
| R-06    | AReq without subsequent 0100 within 600s     | 3DS session abandonment   |
| R-07    | Multiple AReq from same BIN, no CReq, <10s  | Frictionless 3DS probing  |
| R-08    | TAVV reused across multiple 0100             | Token replay              |
| R-09    | Token BIN mismatch vs. network range         | Forged token injection    |
| R-10    | 0100 amount=0.00 or amount=0.01 (micro-auth) | Baseline poisoning probe  |

---

## 5. Full State Machine Diagram (ASCII)

```
                            ┌──────────────────────────────────────────────┐
                            │              ISO 8583 Session FSM             │
                            └──────────────────────────────────────────────┘

                                         ┌────────┐
                                         │  IDLE  │
                                         └───┬────┘
                                             │ recv 0100
                                             ▼
                                    ┌─────────────────┐
                                    │  AUTH_PENDING   │◄─────────────────────┐
                                    └────────┬────────┘                      │
                              0110/approve   │  0110/decline              [R-01] timeout
                         ┌──────────────────┼─────────────────┐             │
                         ▼                  │                  ▼             │
                ┌────────────────┐          │         ┌─────────────────┐   │
                │ AUTH_APPROVED  │          │         │  AUTH_DECLINED  │   │
                └────────┬───────┘          │         └────────┬────────┘   │
                         │                  │                  │             │
          recv 0200 ─────┤ recv 0400        │           [TERMINAL]          │
                         │                  ▼                                │
                         │          ┌───────────────┐                        │
                         │          │   [ANOMALY]   │ ◄── R-02, R-03, ...   │
                         │          │  (TIG alert)  │                        │
                         │          └───────────────┘                        │
                ┌────────┼─────────────────┐
                ▼                          ▼
    ┌───────────────────────┐   ┌──────────────────────┐
    │  COMPLETION_PENDING   │   │   REVERSAL_PENDING   │
    └──────────┬────────────┘   └──────────┬───────────┘
               │ recv 0210                  │ recv 0410
               ▼                            ▼
          ┌──────────┐               ┌──────────────┐
          │ COMPLETED│               │   REVERSED   │
          └──────────┘               └──────────────┘


                            ┌──────────────────────────────────────────────┐
                            │             EMVCo 3DS 2.x Session FSM        │
                            └──────────────────────────────────────────────┘

                                         ┌────────┐
                                         │  IDLE  │
                                         └───┬────┘
                                             │ recv AReq
                                             ▼
                                    ┌─────────────────┐
                                    │   AREQ_SENT     │
                                    └────────┬────────┘
                                             │ recv ARes
                                             ▼
                                    ┌─────────────────┐
                              ┌─────┤   ARES_RECV     ├──────┐
                              │     └─────────────────┘      │
                              │ frictionless                   │ challenge
                              ▼                               ▼
                    ┌──────────────────┐         ┌──────────────────────┐
                    │  AUTH_COMPLETE   │         │    CHALLENGE_SENT    │
                    │ (→ ISO 8583)     │         └──────────┬───────────┘
                    └──────────────────┘                    │ recv CRes
                                                            ▼
                                                 ┌──────────────────────┐
                                                 │    AUTH_COMPLETE     │
                                                 │   (→ ISO 8583)       │
                                                 └──────────────────────┘
```

---

## 6. TIG Semantic Correlation Rules

The Transaction Intent Graph correlates events across all three flows (ISO 8583, 3DS, Tokenization)
using a shared session key derived from: `{BIN prefix, terminal_id, timestamp_window, amount_bucket}`.

### 6.1 Cross-Flow Coherence Checks

| Check ID | Flows Joined         | Invariant                                          |
|----------|----------------------|----------------------------------------------------|
| CF-01    | 3DS + ISO8583        | AReq must precede 0100 by ≤600s for 3DS-enrolled cards |
| CF-02    | Token + ISO8583      | TAVV in DE48 must match token provisioning record  |
| CF-03    | 3DS + Token + ISO8583| CRes authentication value must match DE48 CAVV    |
| CF-04    | ISO8583 sequence     | STAN must be monotonically increasing per terminal |
| CF-05    | Multi-BIN            | >5 distinct BINs from same IP within 60s → recon  |

### 6.2 Timing Windows Used by TIG-CDO

| Window Name          | Duration  | Used For                                   |
|----------------------|-----------|--------------------------------------------|
| BIN burst window     | 1s        | R-03 BIN enumeration detection             |
| Auth orphan window   | 120s      | R-02 orphaned auth / BIN probe             |
| 3DS session window   | 600s      | R-06 abandoned 3DS sessions                |
| Token TAVV window    | 30s       | R-08 token replay detection                |
| CSDA recon window    | 300s      | Phase 1 reconnaissance detection          |
| Baseline poison window | 3600s  | Phase 2 slow baseline poisoning            |

---

*This document is a shared resource. Do not duplicate into paper1-survey/ or paper2-solution/ — reference from here.*
