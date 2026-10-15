#!/usr/bin/env python3
"""Render measured runs, not projected throughput. Requires matplotlib 3.10+."""
import argparse
import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    runs = json.loads(args.input.read_text())["runs"]
    sizes = sorted({r["packets"] for r in runs})
    groups = [[r for r in runs if r["packets"] == size] for size in sizes]
    medians = [statistics.median(r["wall_seconds"] for r in group) for group in groups]
    low = [median - min(r["wall_seconds"] for r in group) for median, group in zip(medians, groups)]
    high = [max(r["wall_seconds"] for r in group) - median for median, group in zip(medians, groups)]
    memory = [max(r["peak_rss_kib"] for r in group) / 1024 for group in groups]
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    labels = [f"{size:,}" for size in sizes]
    axes[0].bar(labels, medians, color="#287e89", width=.55, yerr=[low, high], capsize=5)
    axes[0].set_ylabel("Wall time (seconds)")
    axes[0].set_title("Complete CLI + JSON/HTML export", loc="left", fontweight="bold", fontsize=11)
    axes[1].bar(labels, memory, color="#426c9d", width=.55)
    axes[1].set_ylabel("Peak resident memory (MiB)")
    axes[1].set_title("Largest per-child RSS in each group", loc="left", fontweight="bold", fontsize=11)
    for axis, values in zip(axes, [medians, memory]):
        axis.set_xlabel("Synthetic packets · 100 UDP conversations")
        axis.set_ylim(0, max(values) * 1.2)
        axis.set_axisbelow(True)
        axis.grid(axis="y", color="#dce3e8", linewidth=.7)
        for index, value in enumerate(values):
            axis.text(index, value + max(values) * .055, f"{value:.3f}" if axis is axes[0] else f"{value:.1f}", ha="center", fontsize=9)
    fig.suptitle("TraceTrust · measured synthetic workload", x=.06, ha="left", fontsize=14, fontweight="bold")
    fig.text(.06, .02, "3 measured runs per size after one warm-up. Error bars: observed min–max, not confidence intervals. Shared Linux container.", fontsize=8, color="#475569")
    fig.tight_layout(rect=(0, .07, 1, .91))
    fig.savefig(args.output, dpi=160, facecolor="white")


if __name__ == "__main__":
    main()
