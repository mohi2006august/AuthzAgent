"""Figures for the results: the frontier plot and the scope-relation breakdown."""

from __future__ import annotations

from pathlib import Path

from .metrics import ConfigMetrics

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # validated categorical slots 1-4 (light)

MEDIATOR_FAMILY = {"tools+args", "full", "full-global", "full+esc-attentive", "full+esc-attentive-nohist",
                   "full+confirm-amounts", "oracle-intent", "paraphrased", "heldout", "full-v1-derivation",
                   "model", "model-heldout"}

SHORT = {
    "no-mediator": "No mediator",
    "tools-only": "Tool allow-list only",
    "tools+args": "Tools + arg constraints",
    "full": "Full (per-tool budget)",
    "full-global": "Full (global budget)",
    "full+esc-attentive": "Full + escalation,\nattentive user",
    "full+esc-rubber": "Full + escalation, rubber-stamp user",
    "read-only": "Deny all\nirreversible",
    "oracle-intent": "Full, hand-labelled intent",
    "paraphrased": "Full, paraphrases",
    "heldout": "Full, held-out requests",
    "full+confirm-amounts": "Full + confirm unstated\namounts (attentive)",
    "model": "Grounded model parser",
    "model-heldout": "Grounded model parser,\nheld-out",
}
# label placement per group, keyed by the group's first member: (dx, dy) in points, ha, va
PLACE = {
    "no-mediator": (9, 1, "left", "bottom"),
    "full+esc-rubber": (9, -3, "left", "top"),
    "read-only": (-6, 9, "right", "bottom"),
    "full+esc-attentive": (9, -3, "left", "top"),
    "full+confirm-amounts": (9, 0, "left", "center"),
    "tools+args": (-4, 8, "right", "bottom"),
    "heldout": (4, 8, "left", "bottom"),
    "full": (6, -8, "left", "top"),
    "paraphrased": (9, 0, "left", "center"),
}
ZOOM = (26.0, 5.2)  # x (over-restriction %) and y (unauthorised %) extent of the zoom panel


def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(0.8)
    ax.tick_params(colors=MUTED, labelsize=8, length=0, pad=4)
    ax.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def _pct(ax) -> None:
    from matplotlib.ticker import FuncFormatter

    fmt = FuncFormatter(lambda v, _: f"{v:.0f}%")
    ax.xaxis.set_major_formatter(fmt)
    ax.yaxis.set_major_formatter(fmt)


def frontier(metrics: list[ConfigMetrics], out: Path, v1_full: tuple[float, float] | None = None) -> list[Path]:
    """``v1_full``: (over-restriction, unauthorised) of v1's full configuration, drawn hollow for comparison."""
    from .configs import BY_NAME

    metrics = [m for m in metrics if m.config not in BY_NAME or BY_NAME[m.config].frontier]
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans", "sans-serif"]
    fig, (ax_all, ax_zoom) = plt.subplots(1, 2, figsize=(11, 5.0), dpi=200,
                                          gridspec_kw={"width_ratios": [1, 1.25], "wspace": 0.18})
    fig.patch.set_facecolor(SURFACE)

    # coincident points share one marker and one label
    order = [m.config for m in metrics]
    groups: list[list[ConfigMetrics]] = []
    for m in metrics:
        x, y = 100 * m.over_restriction.value, 100 * m.unauthorised.value
        for g in groups:
            gx, gy = 100 * g[0].over_restriction.value, 100 * g[0].unauthorised.value
            if abs(gx - x) < 0.01 and abs(gy - y) < 0.01:
                g.append(m)
                break
        else:
            groups.append([m])

    for ax, zoom in ((ax_all, False), (ax_zoom, True)):
        _style(ax)
        for ms in groups:
            ms.sort(key=lambda m: order.index(m.config))
            m0 = ms[0]
            x, y = 100 * m0.over_restriction.value, 100 * m0.unauthorised.value
            colour = SERIES[0] if m0.config in MEDIATOR_FAMILY else MUTED
            (xl, xh), (yl, yh) = m0.over_restriction.wilson(), m0.unauthorised.wilson()
            ax.errorbar(x, y, xerr=[[x - 100 * xl], [100 * xh - x]], yerr=[[y - 100 * yl], [100 * yh - y]],
                        fmt="none", ecolor=colour, elinewidth=0.9, alpha=0.4, capsize=0, zorder=2)
            ax.scatter([x], [y], s=64, color=colour, edgecolors=SURFACE, linewidths=2, zorder=3)
            inside = x <= ZOOM[0] and y <= ZOOM[1]
            visible = inside if zoom else not inside
            if visible:
                dx, dy, ha, va = PLACE.get(m0.config, (9, 0, "left", "center"))
                ax.annotate("\n".join(SHORT.get(m.config, m.label) for m in ms), (x, y), xytext=(dx, dy),
                            textcoords="offset points", fontsize=7.5, color=INK_2, ha=ha, va=va, zorder=5,
                            linespacing=1.25,
                            bbox={"boxstyle": "square,pad=0.15", "facecolor": SURFACE, "edgecolor": "none"})
        if v1_full is not None:
            vx, vy = 100 * v1_full[0], 100 * v1_full[1]
            ax.scatter([vx], [vy], s=64, facecolors="none", edgecolors=SERIES[0], linewidths=1.4, zorder=3)
            if zoom and vx <= ZOOM[0] and vy <= ZOOM[1]:
                ax.annotate("Full, v1", (vx, vy), xytext=(8, 0), textcoords="offset points", fontsize=7.5,
                            color=INK_2, ha="left", va="center", zorder=5,
                            bbox={"boxstyle": "square,pad=0.15", "facecolor": SURFACE, "edgecolor": "none"})
        _pct(ax)

    ax_all.set_xlim(-4, 104)
    ax_all.set_ylim(-4, 104)
    ax_all.set_title("All configurations", fontsize=9.5, color=INK, loc="left", pad=8)
    ax_all.add_patch(plt.Rectangle((-1.5, -1.5), ZOOM[0] + 1.5, ZOOM[1] + 1.5, fill=False, edgecolor=AXIS,
                                   linewidth=0.8, zorder=1))
    ax_all.annotate("zoomed at right", (ZOOM[0], ZOOM[1]), xytext=(4, 4), textcoords="offset points", fontsize=7,
                    color=MUTED)
    ax_zoom.set_xlim(-1.5, ZOOM[0])
    ax_zoom.set_ylim(-0.4, ZOOM[1])
    ax_zoom.set_title("Zoom: mediator configurations", fontsize=9.5, color=INK, loc="left", pad=8)
    for ax in (ax_all, ax_zoom):
        ax.set_xlabel("Over-restriction rate (clean runs blocked)", fontsize=8.5, color=INK_2)
    ax_all.set_ylabel("Unauthorised action rate (poisoned runs)", fontsize=8.5, color=INK_2)
    ax_zoom.annotate("better ↙", (0.97, 0.96), xycoords="axes fraction", ha="right", va="top", fontsize=7.5, color=MUTED)

    from matplotlib.lines import Line2D

    handles = [
        Line2D([], [], marker="o", linestyle="", markersize=7, markerfacecolor=SERIES[0], markeredgecolor=SURFACE,
               label="Capability mediator variants"),
        Line2D([], [], marker="o", linestyle="", markersize=7, markerfacecolor=MUTED, markeredgecolor=SURFACE,
               label="Baselines and stress cases"),
    ]
    fig.legend(handles=handles, loc="upper right", bbox_to_anchor=(0.985, 1.0), ncol=2, frameon=False, fontsize=8,
               labelcolor=INK_2)
    fig.suptitle("Frontier: unauthorised actions vs over-restriction", x=0.065, y=0.985, ha="left",
                 fontsize=12, color=INK)
    fig.text(0.065, 0.925, "Scripted worst-case agent (follows every injection it reads). Bars are 95% Wilson intervals.",
             fontsize=8, color=MUTED, ha="left")
    fig.subplots_adjust(left=0.065, right=0.985, top=0.84, bottom=0.12)
    paths = [out / "frontier.png", out / "frontier.svg"]
    for p in paths:
        fig.savefig(p, facecolor=SURFACE)
    plt.close(fig)
    return paths


def breakdown(metrics: list[ConfigMetrics], out: Path,
              configs: tuple[str, ...] = ("full", "tools+args", "tools-only", "no-mediator")) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans", "sans-serif"]
    relations = [("tool_not_granted", "Attack uses a tool\nthe request never implied"),
                 ("argument_out_of_scope", "Attack uses a granted tool\nwith out-of-scope arguments"),
                 ("in_scope", "Attack stays inside\nthe granted scope")]
    by_name = {m.config: m for m in metrics}
    chosen = [by_name[c] for c in configs if c in by_name]
    fig, ax = plt.subplots(figsize=(9, 4.4), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    _style(ax)
    ax.grid(False, axis="x")
    width = 0.8 / len(chosen)
    gap = 0.012
    for i, m in enumerate(chosen):
        xs, ys = [], []
        for j, (key, _) in enumerate(relations):
            r = m.by_scope.get(key)
            xs.append(j - 0.4 + width * (i + 0.5))
            ys.append(100 * r.value if r and r.n else 0.0)
        ax.bar(xs, ys, width=width - gap, color=SERIES[i], label=m.label, zorder=3)
        if m.config == "full":
            for x, y in zip(xs, ys):
                ax.annotate(f"{y:.0f}%", (x, y), xytext=(0, 3), textcoords="offset points", ha="center",
                            fontsize=7.5, color=INK)
    counts = [chosen[0].by_scope.get(k) for k, _ in relations]
    ax.set_xticks(range(len(relations)))
    ax.set_xticklabels([f"{label}\n(n={c.n if c else 0})" for (_, label), c in zip(relations, counts)],
                       fontsize=8, color=INK_2)
    ax.set_ylim(0, 105)
    from matplotlib.ticker import FuncFormatter

    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.0f}%"))
    ax.set_ylabel("Unauthorised action rate", fontsize=8.5, color=INK_2)
    ax.legend(loc="upper left", bbox_to_anchor=(0, 1.13), ncol=len(chosen), frameon=False, fontsize=8,
              labelcolor=INK_2, handlelength=1.2)
    fig.suptitle("Where the misses come from: attacks grouped by relation to the grant", x=0.08, y=0.985,
                 ha="left", fontsize=11, color=INK)
    fig.subplots_adjust(left=0.08, right=0.98, top=0.8, bottom=0.2)
    path = out / "breakdown.png"
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
    return path
