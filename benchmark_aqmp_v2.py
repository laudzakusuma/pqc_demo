#!/usr/bin/env python3
"""Empirical Benchmark Suite for AQMP v2.0 (Adaptive Quantum Migration Protocol).

Generates exact mathematical byte-footprint datasets (CSV) and 300 DPI
publication-ready figures (PNG) for three models:
  - Model A: Execution Layer (EL) & Consensus Layer (CL) ZK-Aggregation Break-Even
  - Model B: Temporal Decoupling Network Replication Cost (Dual-Commit XOR vs. FORS+C)
  - Model C: Formal Quantum Threat Oracle & Fukuda Migration Deadline (Delta*)
"""

from __future__ import annotations

from fractions import Fraction
import math
from pathlib import Path
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Protocol & Cryptographic Byte Constants
# ---------------------------------------------------------------------------
ECDSA_PK_BYTES = 32
ECDSA_SIG_BYTES = 64
ECDSA_TOTAL_BYTES = ECDSA_PK_BYTES + ECDSA_SIG_BYTES  # 96 B

MLDSA65_PK_BYTES = 1952
MLDSA65_SIG_BYTES = 3309
MLDSA65_TOTAL_BYTES = MLDSA65_PK_BYTES + MLDSA65_SIG_BYTES  # 5261 B

FALCON_PK_BYTES = 897          # p
FALCON_SALT_BYTES = 40         # R
FALCON_SIG_STD_BYTES = 626     # S
FALCON_SIG_KR_BYTES = 650      # S_tilde (key-recovery signature)
KEY_REGISTRY_IDX_BYTES = 4     # idx

LABRADOR_EL_BASE_BYTES = 51200  # 50 KiB base proof overhead
LABRADOR_EL_LOG_COEFF = 128
LABRADOR_CL_FIXED_BYTES = 71680  # 70 KiB consensus-layer fixed overhead
PLONKY3_PROOF_BYTES = 300        # BabyBear recursive proof

DUAL_COMMIT_TX1_BYTES = 32
DUAL_COMMIT_TX2_BYTES = 64
DUAL_COMMIT_TOTAL_BYTES = DUAL_COMMIT_TX1_BYTES + DUAL_COMMIT_TX2_BYTES  # 96 B

FORS_C_SIG_BYTES = 2336
FORS_C_COMMIT_UPDATE_BYTES = 20
FORS_C_TOTAL_BYTES = FORS_C_SIG_BYTES + FORS_C_COMMIT_UPDATE_BYTES  # 2356 B

M_NODES = 15_000
MAX_TX_PER_BLOCK = 1000
BYTES_PER_KIB = 1024.0
BYTES_PER_KB_DEC = 1000.0
BYTES_PER_MB_DEC = 1_000_000.0
BYTES_PER_MIB = float(1024 ** 2)


def configure_plot_style() -> None:
    """Configure consistent, clean academic publication styling for Matplotlib."""
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 11.5,
            "axes.titleweight": "bold",
            "axes.labelsize": 10.5,
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 9.5,
            "legend.fontsize": 8.5,
            "figure.titlesize": 13,
            "figure.titleweight": "bold",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.28,
            "grid.linestyle": "--",
            "savefig.dpi": 300,
        }
    )


def compute_labrador_el_overhead(n_values: np.ndarray) -> np.ndarray:
    """Compute a_{N,EL} = 51200 + floor(128 * log2(max(N, 2))) cleanly."""
    overheads = np.empty_like(n_values, dtype=np.int64)
    for i, n in enumerate(n_values):
        m = max(int(n), 2)
        if (m & (m - 1)) == 0:
            # Exact power of 2 avoids any floating-point rounding drift.
            log2_term = 128 * (m.bit_length() - 1)
        else:
            log2_term = math.floor(LABRADOR_EL_LOG_COEFF * math.log2(m))
        overheads[i] = LABRADOR_EL_BASE_BYTES + log2_term
    return overheads


def first_breakeven_n(
    n_values: np.ndarray, candidate_bytes: np.ndarray, baseline_bytes: np.ndarray
) -> int | None:
    """Return smallest N where candidate_bytes < baseline_bytes, or None."""
    mask = candidate_bytes < baseline_bytes
    if not np.any(mask):
        return None
    return int(n_values[int(np.argmax(mask))])


def run_model_a(data_dir: Path, fig_dir: Path) -> tuple[pd.DataFrame, dict[str, int | None]]:
    """Model A: EL & CL ZK-Aggregation Break-Even Analysis."""
    n = np.arange(1, MAX_TX_PER_BLOCK + 1, dtype=np.int64)

    ecdsa_bytes = n * ECDSA_TOTAL_BYTES
    mldsa65_bytes = n * MLDSA65_TOTAL_BYTES
    el_case1_bytes = n * (FALCON_SIG_KR_BYTES + FALCON_SALT_BYTES)
    el_case2_bytes = n * (FALCON_PK_BYTES + FALCON_SIG_STD_BYTES + FALCON_SALT_BYTES)

    a_n_el_bytes = compute_labrador_el_overhead(n)
    el_case3a_bytes = n * (FALCON_PK_BYTES + FALCON_SALT_BYTES) + a_n_el_bytes
    el_case3b_bytes = a_n_el_bytes + n * (FALCON_SALT_BYTES + KEY_REGISTRY_IDX_BYTES)
    cl_case3_bytes = LABRADOR_CL_FIXED_BYTES + n * (
        FALCON_SALT_BYTES + KEY_REGISTRY_IDX_BYTES
    )
    aqmp_v2_plonky3_bytes = np.minimum(
        el_case1_bytes,
        PLONKY3_PROOF_BYTES + n * (FALCON_SALT_BYTES + KEY_REGISTRY_IDX_BYTES),
    )

    series_bytes = {
        "ecdsa": ecdsa_bytes,
        "mldsa65": mldsa65_bytes,
        "el_case1": el_case1_bytes,
        "el_case2": el_case2_bytes,
        "a_n_el": a_n_el_bytes,
        "el_case3a": el_case3a_bytes,
        "el_case3b": el_case3b_bytes,
        "cl_case3": cl_case3_bytes,
        "aqmp_v2_plonky3": aqmp_v2_plonky3_bytes,
    }

    df = pd.DataFrame({"N": n})
    for name, arr in series_bytes.items():
        df[f"{name}_bytes"] = arr
        df[f"{name}_kb"] = arr / BYTES_PER_KIB
        df[f"{name}_kb_dec"] = arr / BYTES_PER_KB_DEC

    csv_path = data_dir / "breakeven_analysis.csv"
    df.to_csv(csv_path, index=False, float_format="%.6f")

    breakevens = {
        "el_case3b_vs_el_case1": first_breakeven_n(n, el_case3b_bytes, el_case1_bytes),
        "el_case3b_vs_el_case2": first_breakeven_n(n, el_case3b_bytes, el_case2_bytes),
        "cl_case3_vs_el_case1": first_breakeven_n(n, cl_case3_bytes, el_case1_bytes),
        "cl_case3_vs_el_case2": first_breakeven_n(n, cl_case3_bytes, el_case2_bytes),
        "aqmp_plonky3_vs_el_case1": first_breakeven_n(
            n, aqmp_v2_plonky3_bytes, el_case1_bytes
        ),
        "aqmp_plonky3_vs_ecdsa": first_breakeven_n(
            n, aqmp_v2_plonky3_bytes, ecdsa_bytes
        ),
    }

    # --- Plot Figure 1 ---
    fig, (ax_full, ax_zoom) = plt.subplots(1, 2, figsize=(14.5, 6.0))

    curve_specs = [
        ("mldsa65_kb", "Naive ML-DSA-65 (5,261 B/tx)", "#7f1d1d", "-", 1.8),
        ("el_case2_kb", "EL Case 2: FALCON Std (1,563 B/tx)", "#dc2626", "--", 1.8),
        ("el_case3a_kb", "EL Case 3a: LaBRADOR Full PK", "#ea580c", "-.", 1.8),
        ("el_case1_kb", "EL Case 1: FALCON Key-Recovery (690 B/tx)", "#d97706", "-", 2.1),
        ("cl_case3_kb", "CL Case 3: LaBRADOR 70 KiB + KeyRegistry", "#2563eb", "-", 2.1),
        ("el_case3b_kb", "EL Case 3b: LaBRADOR 50 KiB+log + KeyRegistry", "#0284c7", "-", 2.2),
        ("ecdsa_kb", "Classical ECDSA Baseline (96 B/tx)", "#374151", ":", 2.0),
        ("aqmp_v2_plonky3_kb", "AQMP v2.0 Adaptive + Plonky3 (300B + KeyRegistry)", "#059669", "-", 2.5),
    ]

    for col, label, color, ls, lw in curve_specs:
        ax_full.plot(df["N"], df[col], label=label, color=color, linestyle=ls, linewidth=lw)

    ax_full.set_yscale("log")
    ax_full.set_xlim(1, 1000)
    ax_full.set_ylim(0.1, 10_000)
    ax_full.set_title("(a) Full-Block Payload Scaling (Log Scale, N = 1..1,000)")
    ax_full.set_xlabel("Transactions per Block (N)")
    ax_full.set_ylabel("Signature + Proof Payload (KiB, log scale)")
    ax_full.legend(loc="lower right", frameon=True, framealpha=0.92)

    # Panel (b): Linear zoom into break-even crossover zone
    zoom_max_n = 250
    zoom_df = df[df["N"] <= zoom_max_n]
    zoom_cols = {
        "el_case2_kb",
        "el_case1_kb",
        "cl_case3_kb",
        "el_case3b_kb",
        "ecdsa_kb",
        "aqmp_v2_plonky3_kb",
    }
    for col, label, color, ls, lw in curve_specs:
        if col in zoom_cols:
            ax_zoom.plot(
                zoom_df["N"],
                zoom_df[col],
                label=label,
                color=color,
                linestyle=ls,
                linewidth=lw,
            )

    n_el = breakevens["el_case3b_vs_el_case1"]
    n_cl = breakevens["cl_case3_vs_el_case1"]
    assert n_el is not None and n_cl is not None

    y_el = float(df.loc[df["N"] == n_el, "el_case3b_kb"].iloc[0])
    y_cl = float(df.loc[df["N"] == n_cl, "cl_case3_kb"].iloc[0])

    ax_zoom.axvline(n_el, color="#0284c7", linestyle="--", linewidth=1.2, alpha=0.8)
    ax_zoom.axvline(n_cl, color="#2563eb", linestyle="--", linewidth=1.2, alpha=0.8)
    ax_zoom.scatter([n_el, n_cl], [y_el, y_cl], color=["#0284c7", "#2563eb"], zorder=6, s=55)

    ax_zoom.annotate(
        f"EL Break-Even\n$N^*_{{EL}} = {n_el}$ ({y_el:.2f} KiB)",
        xy=(n_el, y_el),
        xytext=(n_el + 20, y_el - 26),
        arrowprops={"arrowstyle": "->", "color": "#0284c7", "lw": 1.2},
        fontsize=8.8,
        fontweight="bold",
        color="#0369a1",
        bbox={"boxstyle": "round,pad=0.3", "fc": "#f0f9ff", "ec": "#0284c7", "alpha": 0.95},
    )
    ax_zoom.annotate(
        f"CL Break-Even\n$N^*_{{CL}} = {n_cl}$ ({y_cl:.2f} KiB)",
        xy=(n_cl, y_cl),
        xytext=(n_cl + 24, y_cl + 28),
        arrowprops={"arrowstyle": "->", "color": "#2563eb", "lw": 1.2},
        fontsize=8.8,
        fontweight="bold",
        color="#1d4ed8",
        bbox={"boxstyle": "round,pad=0.3", "fc": "#eff6ff", "ec": "#2563eb", "alpha": 0.95},
    )

    ax_zoom.set_xlim(1, zoom_max_n)
    ax_zoom.set_ylim(0, 210)
    ax_zoom.set_title("(b) ZK-Aggregation Break-Even Regime (N = 1..250)")
    ax_zoom.set_xlabel("Transactions per Block (N)")
    ax_zoom.set_ylabel("Signature + Proof Payload (KiB)")
    ax_zoom.legend(loc="upper left", frameon=True, framealpha=0.92, fontsize=8.0)

    fig.suptitle("Model A: Execution & Consensus Layer ZK-Aggregation Break-Even Analysis")
    fig.tight_layout()
    fig.savefig(fig_dir / "fig1_breakeven_curve.png", dpi=300, bbox_inches="tight")
    plt.close(fig)

    return df, breakevens


def run_model_b(data_dir: Path, fig_dir: Path) -> pd.DataFrame:
    """Model B: Temporal Decoupling Network Replication Cost (M = 15,000 nodes)."""
    n = np.arange(1, MAX_TX_PER_BLOCK + 1, dtype=np.int64)

    schemes = {
        "aqmp_dual_commit_xor": DUAL_COMMIT_TOTAL_BYTES,
        "erc4337_fors_c": FORS_C_TOTAL_BYTES,
        "naive_mldsa65": MLDSA65_TOTAL_BYTES,
        "classical_ecdsa": ECDSA_TOTAL_BYTES,
    }

    df = pd.DataFrame({"N": n, "m_nodes": np.full_like(n, M_NODES)})
    for name, per_tx_bytes in schemes.items():
        block_bytes = n * per_tx_bytes
        net_bytes = block_bytes * M_NODES
        df[f"{name}_block_bytes"] = block_bytes
        df[f"{name}_net_bytes"] = net_bytes
        df[f"{name}_net_mb"] = net_bytes / BYTES_PER_MB_DEC
        df[f"{name}_net_mib"] = net_bytes / BYTES_PER_MIB

    csv_path = data_dir / "temporal_decoupling_cost.csv"
    df.to_csv(csv_path, index=False, float_format="%.6f")

    # --- Plot Figure 2 ---
    fig, (ax_line, ax_bar) = plt.subplots(
        1, 2, figsize=(14.5, 6.0), gridspec_kw={"width_ratios": [1.35, 1.0]}
    )

    ax_line.plot(
        df["N"],
        df["naive_mldsa65_net_mb"],
        label="Naive ML-DSA-65 (5,261 B/tx)",
        color="#991b1b",
        linewidth=2.2,
    )
    ax_line.plot(
        df["N"],
        df["erc4337_fors_c_net_mb"],
        label="ERC-4337 Ephemeral FORS+C (2,356 B/tx)",
        color="#d97706",
        linewidth=2.2,
    )
    ax_line.plot(
        df["N"],
        df["aqmp_dual_commit_xor_net_mb"],
        label="AQMP v2.0 Dual-Commit XOR (96 B/tx)",
        color="#059669",
        linewidth=3.0,
    )
    ax_line.plot(
        df["N"],
        df["classical_ecdsa_net_mb"],
        label="Classical ECDSA Baseline (96 B/tx, Parity)",
        color="#111827",
        linestyle="--",
        linewidth=1.8,
    )

    ax_line.fill_between(
        df["N"],
        df["aqmp_dual_commit_xor_net_mb"],
        df["erc4337_fors_c_net_mb"],
        color="#10b981",
        alpha=0.10,
        label="Bandwidth Saved vs. FORS+C (95.93%)",
    )
    ax_line.fill_between(
        df["N"],
        df["erc4337_fors_c_net_mb"],
        df["naive_mldsa65_net_mb"],
        color="#ef4444",
        alpha=0.07,
        label="Additional Overhead of ML-DSA-65",
    )

    # Annotate N = 1000 savings
    y_mldsa_1000 = float(df.loc[df["N"] == 1000, "naive_mldsa65_net_mb"].iloc[0])
    y_forsc_1000 = float(df.loc[df["N"] == 1000, "erc4337_fors_c_net_mb"].iloc[0])
    y_aqmp_1000 = float(df.loc[df["N"] == 1000, "aqmp_dual_commit_xor_net_mb"].iloc[0])

    ax_line.annotate(
        f"78,915 MB\n(N=1,000)",
        xy=(1000, y_mldsa_1000),
        xytext=(780, y_mldsa_1000 * 0.90),
        arrowprops={"arrowstyle": "->", "color": "#991b1b"},
        fontsize=8.5,
        fontweight="bold",
        color="#991b1b",
    )
    ax_line.annotate(
        f"35,340 MB",
        xy=(1000, y_forsc_1000),
        xytext=(815, y_forsc_1000 + 5000),
        arrowprops={"arrowstyle": "->", "color": "#d97706"},
        fontsize=8.5,
        fontweight="bold",
        color="#b45309",
    )
    ax_line.annotate(
        f"1,440 MB (-98.18% vs ML-DSA-65)",
        xy=(1000, y_aqmp_1000),
        xytext=(540, 8500),
        arrowprops={"arrowstyle": "->", "color": "#059669"},
        fontsize=8.5,
        fontweight="bold",
        color="#047857",
        bbox={"boxstyle": "round,pad=0.25", "fc": "#ecfdf5", "ec": "#059669"},
    )

    ax_line.set_xlim(1, 1000)
    ax_line.set_ylim(0, 85_000)
    ax_line.set_title("(a) Per-Block Network Replication Cost (M = 15,000 Full Nodes)")
    ax_line.set_xlabel("Transactions per Block (N)")
    ax_line.set_ylabel("Network-Wide Bandwidth per Block (MB)")
    ax_line.legend(loc="upper left", frameon=True, framealpha=0.92, fontsize=8.2)

    # Panel (b): Side-by-side comparison at N = 250 tx/block (log scale)
    row_250 = df.loc[df["N"] == 250].iloc[0]
    bar_labels = [
        "Classical\nECDSA",
        "AQMP v2.0\nDual-Commit XOR",
        "ERC-4337\nFORS+C",
        "Naive\nML-DSA-65",
    ]
    bar_vals = [
        float(row_250["classical_ecdsa_net_mb"]),
        float(row_250["aqmp_dual_commit_xor_net_mb"]),
        float(row_250["erc4337_fors_c_net_mb"]),
        float(row_250["naive_mldsa65_net_mb"]),
    ]
    bar_colors = ["#374151", "#059669", "#d97706", "#991b1b"]
    bars = ax_bar.bar(bar_labels, bar_vals, color=bar_colors, width=0.58, edgecolor="#1f2937")
    ax_bar.set_yscale("log")
    ax_bar.set_ylim(100, 60_000)
    ax_bar.set_title("(b) Network Cost at N = 250 Tx/Block (Log Scale)")
    ax_bar.set_ylabel("Network-Wide Bandwidth (MB, log scale)")

    for bar, val in zip(bars, bar_vals):
        ratio = val / bar_vals[1]
        ax_bar.text(
            bar.get_x() + bar.get_width() / 2.0,
            val * 1.15,
            f"{val:,.0f} MB\n({ratio:.1f}x)",
            ha="center",
            va="bottom",
            fontsize=8.5,
            fontweight="bold",
        )

    fig.suptitle(
        "Model B: Temporal Decoupling Bandwidth Amplification (M = 15,000 Nodes)"
    )
    fig.tight_layout()
    fig.savefig(
        fig_dir / "fig2_network_cost_amplification.png", dpi=300, bbox_inches="tight"
    )
    plt.close(fig)

    return df


def run_model_c(data_dir: Path, fig_dir: Path) -> pd.DataFrame:
    """Model C: Formal Quantum Threat Oracle & Fukuda Migration Deadline (Delta*)."""
    eps_decimals = [Fraction(i, 100) for i in range(1, 96)]  # 0.01 .. 0.95
    eps_float = [float(e) for e in eps_decimals]
    delta_star = [math.ceil(Fraction(4, 1) / (Fraction(1, 1) - e)) for e in eps_decimals]
    raw_ratio = [float(Fraction(4, 1) / (Fraction(1, 1) - e)) for e in eps_decimals]

    df = pd.DataFrame(
        {
            "epsilon": eps_float,
            "one_minus_epsilon": [float(Fraction(1, 1) - e) for e in eps_decimals],
            "exact_bound_4_over_1_minus_eps": raw_ratio,
            "delta_star_blocks": delta_star,
        }
    )

    csv_path = data_dir / "oracle_migration_deadline.csv"
    df.to_csv(csv_path, index=False, float_format="%.6f")

    # --- Plot Figure 3 ---
    fig, ax = plt.subplots(figsize=(10.0, 6.0))

    y_max = 90
    ax.fill_between(
        df["epsilon"],
        df["delta_star_blocks"],
        y_max,
        step="post",
        color="#10b981",
        alpha=0.18,
        label=r"Safe Migration Region ($\Delta \geq \Delta^* = \lceil 4/(1-\epsilon) \rceil$)",
    )
    ax.fill_between(
        df["epsilon"],
        0,
        df["delta_star_blocks"],
        step="post",
        color="#ef4444",
        alpha=0.16,
        label=r"Quantum-Vulnerable Region ($\Delta < \Delta^*$)",
    )
    ax.step(
        df["epsilon"],
        df["delta_star_blocks"],
        where="post",
        color="#1d4ed8",
        linewidth=2.5,
        label=r"Fukuda Deadline Boundary $\Delta^*(\epsilon)$",
    )

    highlight_eps = [0.10, 0.25, 0.50, 0.75, 0.90]
    offsets = {
        0.10: (0.02, 8),
        0.25: (0.02, 10),
        0.50: (0.02, 11),
        0.75: (-0.11, 11),
        0.90: (-0.17, 7),
    }
    for eps_val in highlight_eps:
        row = df.loc[np.isclose(df["epsilon"], eps_val)].iloc[0]
        d_val = int(row["delta_star_blocks"])
        ax.scatter([eps_val], [d_val], color="#1e3a8a", zorder=6, s=60)
        dx, dy = offsets[eps_val]
        ax.annotate(
            rf"$\epsilon={eps_val:.2f} \rightarrow \Delta^*={d_val}$",
            xy=(eps_val, d_val),
            xytext=(eps_val + dx, d_val + dy),
            arrowprops={"arrowstyle": "->", "color": "#1e3a8a", "lw": 1.1},
            fontsize=9.0,
            fontweight="bold",
            color="#1e3a8a",
            bbox={"boxstyle": "round,pad=0.25", "fc": "white", "ec": "#1e3a8a", "alpha": 0.92},
        )

    ax.text(
        0.22,
        62,
        "SAFE ZONE\nSufficient Confirmation Window\n" + r"($\Delta \geq \Delta^*$)",
        fontsize=10.5,
        fontweight="bold",
        color="#065f46",
        ha="center",
        bbox={"boxstyle": "round,pad=0.4", "fc": "#ecfdf5", "ec": "#059669", "alpha": 0.9},
    )
    ax.text(
        0.72,
        6,
        r"VULNERABLE ZONE ($\Delta < \Delta^*$)",
        fontsize=10.0,
        fontweight="bold",
        color="#991b1b",
        ha="center",
        bbox={"boxstyle": "round,pad=0.35", "fc": "#fef2f2", "ec": "#dc2626", "alpha": 0.9},
    )

    ax.set_xlim(0.01, 0.95)
    ax.set_ylim(0, y_max)
    ax.set_title(
        r"Model C: Formal Quantum Threat Oracle & Fukuda Migration Deadline ($\Delta^*$)"
    )
    ax.set_xlabel(r"Quantum / Adversarial Advantage Parameter ($\epsilon$)")
    ax.set_ylabel(r"Minimum Confirmation Window $\Delta^*$ (Blocks / Rounds)")
    ax.legend(loc="upper left", frameon=True, framealpha=0.95)

    fig.tight_layout()
    fig.savefig(
        fig_dir / "fig3_oracle_deadline_boundary.png", dpi=300, bbox_inches="tight"
    )
    plt.close(fig)

    return df


def render_directory_tree(root: Path, skip_dirs: set[str]) -> list[str]:
    """Build a clean ASCII directory tree of root, collapsing heavy build/venv dirs."""
    lines = [f"{root.name}/"]

    def _walk(current: Path, prefix: str) -> None:
        entries = sorted(
            current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
        )
        for idx, entry in enumerate(entries):
            is_last = idx == len(entries) - 1
            connector = "`-- " if is_last else "|-- "
            if entry.is_dir():
                if entry.name in skip_dirs:
                    lines.append(f"{prefix}{connector}{entry.name}/ [collapsed]")
                else:
                    lines.append(f"{prefix}{connector}{entry.name}/")
                    child_prefix = prefix + ("    " if is_last else "|   ")
                    _walk(entry, child_prefix)
            else:
                lines.append(f"{prefix}{connector}{entry.name}")

    _walk(root, "")
    return lines


def print_terminal_summary(
    repo_root: Path,
    df_a: pd.DataFrame,
    breakevens: dict[str, int | None],
    df_b: pd.DataFrame,
    df_c: pd.DataFrame,
) -> None:
    """Print Step 3 terminal summary report."""
    sep = "=" * 78
    print(sep)
    print("AQMP v2.0 EMPIRICAL BENCHMARK SUITE - SUMMARY REPORT")
    print(sep)

    print("\n1. CURRENT DIRECTORY TREE (pqc_demo):")
    for line in render_directory_tree(
        repo_root, skip_dirs={".git", "target", "venv", "build"}
    ):
        print(f"   {line}")

    print("\n2. EXACT BREAK-EVEN TRANSACTION COUNTS (N*):")
    print(
        f"   - N*_EL (EL Case 3b < EL Case 1, Key-Recovery 690 B/tx) : "
        f"{breakevens['el_case3b_vs_el_case1']} tx/block"
    )
    print(
        f"   - N*_EL (EL Case 3b < EL Case 2, Standard 1,563 B/tx)   : "
        f"{breakevens['el_case3b_vs_el_case2']} tx/block"
    )
    print(
        f"   - N*_CL (CL Case 3 < EL Case 1, Key-Recovery 690 B/tx)  : "
        f"{breakevens['cl_case3_vs_el_case1']} tx/block"
    )
    print(
        f"   - N*_CL (CL Case 3 < EL Case 2, Standard 1,563 B/tx)    : "
        f"{breakevens['cl_case3_vs_el_case2']} tx/block"
    )
    print(
        f"   - N*_AQMP (AQMP v2.0 + Plonky3 < EL Case 1)             : "
        f"{breakevens['aqmp_plonky3_vs_el_case1']} tx/block"
    )
    print(
        f"   - N*_AQMP (AQMP v2.0 + Plonky3 < Classical ECDSA)       : "
        f"{breakevens['aqmp_plonky3_vs_ecdsa']} tx/block"
    )

    print("\n3. PAYLOAD COMPARISON AT N = 250 TRANSACTIONS PER BLOCK:")
    row_a = df_a.loc[df_a["N"] == 250].iloc[0]
    row_b = df_b.loc[df_b["N"] == 250].iloc[0]
    print("   [Model A - Block Cryptographic Payload]")
    model_a_items = [
        ("Classical ECDSA Baseline", "ecdsa"),
        ("Naive ML-DSA-65 (Dilithium)", "mldsa65"),
        ("EL Case 1 (FALCON Key-Recovery)", "el_case1"),
        ("EL Case 2 (FALCON Standard)", "el_case2"),
        ("EL Case 3a (LaBRADOR Full PK)", "el_case3a"),
        ("EL Case 3b (LaBRADOR + KeyRegistry)", "el_case3b"),
        ("CL Case 3 (LaBRADOR 70 KiB + KeyRegistry)", "cl_case3"),
        ("AQMP v2.0 + Plonky3 (300B + KeyRegistry)", "aqmp_v2_plonky3"),
    ]
    for label, key in model_a_items:
        b_val = int(row_a[f"{key}_bytes"])
        kib_val = float(row_a[f"{key}_kb"])
        kb_dec_val = float(row_a[f"{key}_kb_dec"])
        print(f"   - {label:<42}: {b_val:>10,} B | {kib_val:>8.2f} KiB ({kb_dec_val:>8.2f} KB)")

    print(f"\n   [Model B - Network Replication Bandwidth @ N = 250, M = {M_NODES:,} Nodes]")
    model_b_items = [
        ("AQMP v2.0 Dual-Commit XOR (96 B/tx)", "aqmp_dual_commit_xor"),
        ("Classical ECDSA Baseline (96 B/tx)", "classical_ecdsa"),
        ("ERC-4337 Ephemeral FORS+C (2,356 B/tx)", "erc4337_fors_c"),
        ("Naive ML-DSA-65 (5,261 B/tx)", "naive_mldsa65"),
    ]
    for label, key in model_b_items:
        blk_b = int(row_b[f"{key}_block_bytes"])
        net_mb = float(row_b[f"{key}_net_mb"])
        net_mib = float(row_b[f"{key}_net_mib"])
        print(
            f"   - {label:<42}: {blk_b:>10,} B/blk | {net_mb:>10,.2f} MB ({net_mib:>10,.2f} MiB)"
        )

    print("\n4. FUKUDA MIGRATION DEADLINE CONFIRMATION WINDOW (Delta*):")
    for eps_target in [0.10, 0.25, 0.50, 0.75, 0.90]:
        row_c = df_c.loc[np.isclose(df_c["epsilon"], eps_target)].iloc[0]
        print(
            f"   - epsilon = {eps_target:.2f} -> 4/(1-epsilon) = "
            f"{row_c['exact_bound_4_over_1_minus_eps']:>6.2f} -> Delta* = "
            f"{int(row_c['delta_star_blocks']):>2d} blocks"
        )
    print(sep)


def main() -> int:
    repo_root = Path(__file__).resolve().parent
    data_dir = repo_root / "paper" / "data"
    fig_dir = repo_root / "paper" / "figures"
    data_dir.mkdir(parents=True, exist_ok=True)
    fig_dir.mkdir(parents=True, exist_ok=True)

    configure_plot_style()
    df_a, breakevens = run_model_a(data_dir, fig_dir)
    df_b = run_model_b(data_dir, fig_dir)
    df_c = run_model_c(data_dir, fig_dir)

    print_terminal_summary(repo_root, df_a, breakevens, df_b, df_c)
    return 0


if __name__ == "__main__":
    sys.exit(main())
