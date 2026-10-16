"""
Generate the result figures of the paper from computed TIG-CDO data. Every
number plotted here is either (a) read from a result JSON written by a script
in this package (BIM_PHASE2_TRACE.json from trace_bim_phase2.py;
FDCE_RULE_ENGINE_RESULTS.json from write_fdce_results.py), or (b) computed live
from the CLCS formula used by clcs/clcs.py (beta sweep). Nothing is hand-entered.

v1.2.0: Figure 2 is plotted from BIM_PHASE2_TRACE.json instead of hard-coded
values (two C+ cells were wrong in v1.1.0). The former Figure 5 (configuration
heatmap) is removed: it hard-coded harness FPRs computed with the defective
v1.1.0 denominator and a legitimate-TPS value that includes a configured
capacity bonus, and the paper no longer uses it.

Outputs (vector PDF):
  figures/fig2-bim-cusum-trajectory.pdf
  figures/fig3-beta-sensitivity.pdf
  figures/fig4-fdce-heatmap.pdf

Run: python3 trace_bim_phase2.py && python3 generate_paper_figures.py
     (FIG_OUT=<dir> writes the PDFs elsewhere)
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get("FIG_OUT", os.path.join(HERE, "figures"))
TRACE_JSON = os.environ.get("BIM_TRACE", os.path.join(HERE, "BIM_PHASE2_TRACE.json"))
os.makedirs(OUT_DIR, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "legend.fontsize": 7.5,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "pdf.fonttype": 42,
    "axes.edgecolor": "black",
    "axes.linewidth": 0.8,
})

ACCENT = "#c0392b"   # alarm / attack-point red
BASE = "#2c3e50"     # baseline / organic navy
GRID = "#dddddd"


# ---------------------------------------------------------------------------
# Figure 2: BIM JS-divergence CUSUM detection trajectory (CSDA Phase 2)
# Source: BIM_PHASE2_TRACE.json, written by trace_bim_phase2.py from
# run_tigcdo_eval.run_phase_detection_test() (seed 42, simulated traffic).
# ---------------------------------------------------------------------------
def fig2_bim_cusum_trajectory():
    with open(TRACE_JSON) as f:
        trace = json.load(f)
    rows = trace["rows"]
    days = [r["day"] for r in rows]
    js = [r["js"] for r in rows]
    c_plus = [r["c_plus"] for r in rows]
    mu0_js = trace["mu0_js"]
    h = trace["h"]

    fig, ax = plt.subplots(figsize=(3.4, 2.6))

    ax.plot(days, js, marker="o", ms=4, lw=1.3, color=BASE,
            label=r"JS divergence $D_{JS}(t)$")
    ax.axhline(mu0_js, ls=":", lw=1.0, color=BASE, alpha=0.6)
    ax.text(13.9, mu0_js + 0.0003, r"$\mu_0^{JS}$", color=BASE, fontsize=7.5,
             va="bottom", ha="right")

    ax.plot(days, c_plus, marker="s", ms=4, lw=1.5, color=ACCENT,
            label=r"CUSUM statistic $C_t^+$")
    ax.axhline(h, ls="--", lw=1.1, color=ACCENT, alpha=0.85)
    ax.text(13.9, h + 0.0003, rf"$h$ = {h:.5f}", color=ACCENT, fontsize=7.5,
             va="bottom", ha="right")

    alarm_idx = next(i for i, r in enumerate(rows) if r["alarm"])
    alarm_day, alarm_c = days[alarm_idx], c_plus[alarm_idx]
    ax.scatter([alarm_day], [alarm_c], s=55, facecolor="none", edgecolor=ACCENT,
               linewidth=1.6, zorder=5)
    ax.annotate(f"Alarm\n(Day {alarm_day})", xy=(alarm_day, alarm_c), xytext=(12.35, 0.0122),
                fontsize=7.5, color=ACCENT, ha="center",
                arrowprops=dict(arrowstyle="->", color=ACCENT, lw=0.9))

    ax.set_xlabel("Day (CSDA Phase 2 onset = Day 8)")
    ax.set_ylabel("Divergence / CUSUM value")
    ax.set_xticks(days)
    ax.set_ylim(0, 0.0135)
    ax.grid(True, axis="y", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.legend(loc="upper left", frameon=False, handlelength=1.6)

    fig.tight_layout(pad=0.4)
    out = os.path.join(OUT_DIR, "fig2-bim-cusum-trajectory.pdf")
    fig.savefig(out)
    plt.close(fig)
    print("wrote", out)


# ---------------------------------------------------------------------------
# Figure 3: CLCS beta sensitivity sweep (Table XVI)
# Computed live from the real amplification formula in clcs/clcs.py:
#   A(TCS) = 1 + beta * (1 - TCS);  CLCS = min(1, W * A(TCS))
# Attack point: W=0.1960, TCS_b=0.23 (CSDA Phase 3, Table IX/verified Sec VI.B)
# Organic point: W=0.070, TCS_b=0.92 (Section VII.D-1)
# ---------------------------------------------------------------------------
def compute_amplification(tcs, beta):
    return 1.0 + beta * (1.0 - tcs)


def compute_clcs(w, tcs, beta):
    return min(1.0, w * compute_amplification(tcs, beta))


def fig3_beta_sensitivity():
    W_ATTACK, TCS_ATTACK = 0.1960, 0.23
    W_ORGANIC, TCS_ORGANIC = 0.070, 0.92
    THETA_CLCS = 0.75
    SELECTED_BETA = 4.5

    betas = np.linspace(1.5, 7.5, 300)
    clcs_attack = [compute_clcs(W_ATTACK, TCS_ATTACK, b) for b in betas]
    clcs_organic = [compute_clcs(W_ORGANIC, TCS_ORGANIC, b) for b in betas]

    # Grid-observed detection boundary from Table XVI itself (beta=3.5 does not
    # detect, beta=4.0 does): report the coarse-grid value the manuscript states,
    # not a continuous root the table never tested.
    GRID_BOUNDARY_BETA = 4.0

    fig, ax = plt.subplots(figsize=(3.6, 2.9))

    ax.plot(betas, clcs_attack, lw=1.6, color=ACCENT)
    ax.plot(betas, clcs_organic, lw=1.6, color=BASE)

    # Direct line labels instead of a legend box (frees the plot interior).
    ax.text(6.3, 1.015, "CSDA Phase-3 point\n(W=0.196, $TCS_b$=0.23)",
             fontsize=6.8, color=ACCENT, ha="left", va="bottom")
    ax.text(6.3, 0.155, "Organic point\n(W=0.070, $TCS_b$=0.92)",
             fontsize=6.8, color=BASE, ha="left", va="bottom")

    ax.axhline(THETA_CLCS, ls="--", lw=1.0, color="black", alpha=0.7)
    ax.text(1.6, THETA_CLCS + 0.025, r"$\theta_{CLCS}$ = 0.75", fontsize=7.5,
             va="bottom", ha="left")

    ax.axvline(SELECTED_BETA, ls=":", lw=1.0, color=ACCENT, alpha=0.7)
    ax.scatter([SELECTED_BETA], [compute_clcs(W_ATTACK, TCS_ATTACK, SELECTED_BETA)],
               s=45, facecolor=ACCENT, edgecolor="black", linewidth=0.6, zorder=5)
    ax.annotate("selected $\\beta$=4.5\nCLCS=0.875", xy=(SELECTED_BETA, 0.875),
                xytext=(4.9, 0.42), fontsize=7.3, color=ACCENT, ha="left",
                arrowprops=dict(arrowstyle="->", color=ACCENT, lw=0.9))

    ax.scatter([GRID_BOUNDARY_BETA], [compute_clcs(W_ATTACK, TCS_ATTACK, GRID_BOUNDARY_BETA)],
               s=32, facecolor="white", edgecolor="black", linewidth=1.0, zorder=5)
    ax.annotate("Table 11 grid\nboundary: $\\beta$=4.0", xy=(GRID_BOUNDARY_BETA, 0.80),
                xytext=(1.7, 0.97), fontsize=7.3, color="black", ha="left",
                arrowprops=dict(arrowstyle="->", color="black", lw=0.8))

    ax.set_xlabel(r"Amplification coefficient $\beta$")
    ax.set_ylabel("CLCS")
    ax.set_ylim(0, 1.12)
    ax.set_xlim(1.5, 7.9)
    ax.grid(True, axis="y", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    fig.tight_layout(pad=0.4)
    out = os.path.join(OUT_DIR, "fig3-beta-sensitivity.pdf")
    fig.savefig(out)
    plt.close(fig)
    print("wrote", out)


# ---------------------------------------------------------------------------
# Figure 4: FDCE 30-scenario detection grid (real Monte Carlo output)
# Source: FDCE_RULE_ENGINE_RESULTS.json -> main_grid_30_scenarios
# ---------------------------------------------------------------------------
def fig4_fdce_heatmap():
    with open(os.path.join(HERE, "FDCE_RULE_ENGINE_RESULTS.json")) as f:
        data = json.load(f)["main_grid_30_scenarios"]

    clusters = [50, 200, 500]
    intensities = [0.2, 0.4, 0.6, 0.8, 1.0]
    card_types = ["expired_only", "mixed"]
    titles = {"expired_only": "Card type: expired-only (R-11 driven)",
              "mixed": "Card type: mixed (R-11/R-12 driven)"}

    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.7))

    for ax, ct in zip(axes, card_types):
        grid = np.full((len(clusters), len(intensities)), np.nan)
        rule_grid = [["" for _ in intensities] for _ in clusters]
        for row in data:
            if row["card_type"] != ct:
                continue
            i = clusters.index(row["cluster"])
            j = intensities.index(row["intensity"])
            grid[i, j] = row["block_rate"] * 100.0
            rule_grid[i][j] = row["rule"]

        im = ax.imshow(grid, cmap="viridis", vmin=85, vmax=100, aspect="auto")
        ax.set_xticks(range(len(intensities)))
        ax.set_xticklabels([f"{v:.1f}" for v in intensities])
        ax.set_yticks(range(len(clusters)))
        ax.set_yticklabels([str(c) for c in clusters])
        ax.set_xlabel("Attack intensity (fraction of max bot rate)")
        if ct == "expired_only":
            ax.set_ylabel("Bot cluster size")
        ax.set_title(titles[ct], fontsize=8)

        for i in range(len(clusters)):
            for j in range(len(intensities)):
                val = grid[i, j]
                color = "white" if val < 92.5 else "black"
                ax.text(j, i, f"{val:.1f}\n{rule_grid[i][j]}", ha="center", va="center",
                        fontsize=6.3, color=color)

    cbar = fig.colorbar(im, ax=axes, fraction=0.035, pad=0.02)
    cbar.set_label("Block rate (%)", fontsize=8)
    cbar.ax.tick_params(labelsize=7)

    fig.suptitle("", fontsize=0)
    out = os.path.join(OUT_DIR, "fig4-fdce-heatmap.pdf")
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    fig2_bim_cusum_trajectory()
    fig3_beta_sensitivity()
    fig4_fdce_heatmap()
    print(f"\nAll figures written to: {OUT_DIR}")
