#!/usr/bin/env python3
"""
calibrate_tcs_from_real_data.py  (Paper 2 TIG-CDO — gap G1)

Grounds the Transaction Coherence Score (TCS) — the paper's core novelty —
against REAL e-commerce funnel data (Retailrocket, 2.76M events).

The paper assumes TCS = 0.92 (organic baseline) vs 0.23 (attack). Those two
numbers were never measured. This script reconstructs per-visitor sessions,
builds each session's intent-graph (view -> addtocart -> transaction), and
computes a per-session COHERENCE SCORE that is the behavioral analog of TCS.

Coherence-score definition (documented, deterministic):
  A session is a Transaction Intent Graph. For each terminal intent event we
  check whether its expected causal antecedent is present AND time-ordered:
    - transaction  needs a preceding addtocart (same session, earlier ts) -> the
                   'purchase is backed by an add-to-cart' edge
    - addtocart    needs a preceding view       (same session, earlier ts) -> the
                   'cart is backed by a browse'      edge
  Per-session coherence = (satisfied causal edges) / (required causal edges),
  in [0,1]. Sessions with no cart/txn intent (pure browsing) are excluded from
  the intent-graph populations (no transaction semantics to score).

Two populations, mirroring the paper's baseline-vs-attack contrast:
  ORGANIC  : sessions that contain >=1 transaction   (real buyers)
  ORPHAN   : sessions whose transaction/cart events LACK their antecedent, i.e.
             direct-to-purchase / cart-without-browse -- the clickstream analog
             of a scripted payment attack that fires auth without the funnel.

Cross-domain caveat (reported in the manifest): Retailrocket is web clickstream,
not ISO-8583. This grounds the SHAPE and SEPARATION of coherence, not the
literal payment protocol. Sessionization = 30-min inactivity gap per visitorid.
"""
import json
import os
import numpy as np
import pandas as pd

SEED = 42
SESSION_GAP_MS = 30 * 60 * 1000  # 30-minute inactivity gap
HERE = os.path.dirname(os.path.abspath(__file__))
# Point this at your local copy of Retailrocket (Kaggle retailrocket/ecommerce-dataset)
# via DDOS_RAW_DATA_ROOT, or place it at ./raw-data/13-ecommerce-funnel/retailrocket/events.csv.
DATA_ROOT = os.environ.get("DDOS_RAW_DATA_ROOT", os.path.join(HERE, "raw-data"))
SRC = os.path.join(DATA_ROOT, "13-ecommerce-funnel", "retailrocket", "events.csv")
OUT = os.path.join(HERE, "tcs_calibration.json")

np.random.seed(SEED)
RANK = {"view": 0, "addtocart": 1, "transaction": 2}

print("Loading events...")
df = pd.read_csv(SRC, usecols=["timestamp", "visitorid", "event", "itemid"])
df = df.sort_values(["visitorid", "timestamp"], kind="stable").reset_index(drop=True)
n_events = len(df)

# --- sessionize: new session when same visitor idle > gap ---
gap = df.groupby("visitorid")["timestamp"].diff()
new_sess = (gap.isna()) | (gap > SESSION_GAP_MS)
df["session"] = new_sess.groupby(df["visitorid"]).cumsum()
df["sid"] = df["visitorid"].astype(str) + "-" + df["session"].astype(str)

n_sessions = df["sid"].nunique()
print(f"events={n_events:,}  sessions={n_sessions:,}")

# --- per-session aggregation ---
g = df.groupby("sid")
has_view = g["event"].agg(lambda s: (s == "view").any())
has_cart = g["event"].agg(lambda s: (s == "addtocart").any())
has_txn = g["event"].agg(lambda s: (s == "transaction").any())

# earliest timestamp of each event type per session (for causal ordering)
def first_ts(evt):
    m = df[df["event"] == evt].groupby("sid")["timestamp"].min()
    return m
tv = first_ts("view")
tc = first_ts("addtocart")
tt = first_ts("transaction")

sess = pd.DataFrame({"has_view": has_view, "has_cart": has_cart, "has_txn": has_txn})
sess["tv"] = tv
sess["tc"] = tc
sess["tt"] = tt

# causal edges (antecedent present AND strictly/nonstrictly earlier)
sess["cart_backed_by_view"] = sess["has_cart"] & sess["has_view"] & (sess["tv"] <= sess["tc"])
sess["txn_backed_by_cart"] = sess["has_txn"] & sess["has_cart"] & (sess["tc"] <= sess["tt"])

# per-session coherence = satisfied / required causal edges
req = sess["has_cart"].astype(int) + sess["has_txn"].astype(int)
sat = sess["cart_backed_by_view"].astype(int) + sess["txn_backed_by_cart"].astype(int)
intent = req > 0
sess = sess[intent].copy()
sess["coherence"] = sat[intent] / req[intent]

# --- funnel rates ---
n_intent = len(sess)
carts = int(sess["has_cart"].sum())
txns = int(sess["has_txn"].sum())
completed = int((sess["has_cart"] & sess["has_txn"]).sum())
cart_to_purchase = completed / carts if carts else float("nan")
abandonment = 1 - cart_to_purchase
# orphan transaction = purchase in a session with NO add-to-cart at all
orphan_txn = int((sess["has_txn"] & ~sess["has_cart"]).sum())
orphan_txn_rate = orphan_txn / txns if txns else float("nan")

# --- two populations ---
organic = sess[sess["has_txn"] & sess["txn_backed_by_cart"]]  # buyer, funnel-backed
orphan = sess[(sess["has_txn"] & ~sess["has_cart"]) | (sess["has_cart"] & ~sess["cart_backed_by_view"])]

def cohens_d(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    na, nb = len(a), len(b)
    sp = np.sqrt(((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2))
    return float((a.mean() - b.mean()) / sp) if sp > 0 else float("nan")

tcs_organic_mean = float(organic["coherence"].mean())
tcs_orphan_mean = float(orphan["coherence"].mean())
d = cohens_d(organic["coherence"], orphan["coherence"])

result = {
    "dataset": "Retailrocket e-commerce (Kaggle retailrocket/ecommerce-dataset)",
    "purpose": "Gap G1 — ground the Transaction Coherence Score (TCS) against real funnel data",
    "seed": SEED,
    "sessionization": "30-min inactivity gap per visitorid",
    "n_events": int(n_events),
    "n_sessions_total": int(n_sessions),
    "n_intent_sessions": int(n_intent),
    "funnel_rates": {
        "sessions_with_cart": carts,
        "sessions_with_transaction": txns,
        "cart_to_purchase_completion_rate": round(cart_to_purchase, 4),
        "cart_abandonment_rate": round(abandonment, 4),
        "orphan_transaction_rate": round(orphan_txn_rate, 4),
        "note": "orphan_transaction = purchase in a session with no add-to-cart (incoherent buy)",
    },
    "tcs_grounding": {
        "coherence_definition": "satisfied causal edges / required causal edges per session, in [0,1]",
        "organic_population": "sessions with a funnel-backed transaction (view->cart->txn ordered)",
        "orphan_population": "transaction w/o cart, or cart w/o preceding view (attack analog)",
        "n_organic": int(len(organic)),
        "n_orphan": int(len(orphan)),
        "TCS_organic_mean": round(tcs_organic_mean, 4),
        "TCS_orphan_mean": round(tcs_orphan_mean, 4),
        "cohens_d_organic_vs_orphan": round(d, 3),
        "paper_assumed_TCS_baseline": 0.92,
        "paper_assumed_TCS_attack": 0.23,
    },
    "coherence_quantiles_organic": {
        q: round(float(organic["coherence"].quantile(v)), 4)
        for q, v in {"p10": .1, "p50": .5, "p90": .9}.items()
    },
    "coherence_quantiles_orphan": {
        q: round(float(orphan["coherence"].quantile(v)), 4)
        for q, v in {"p10": .1, "p50": .5, "p90": .9}.items()
    },
}

with open(OUT, "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
print(f"\nWrote {OUT}")
