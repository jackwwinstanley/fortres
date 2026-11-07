"""One chart style for the write-up, the dashboard and the Best Data Visualization entry.

Rules: our model is the only saturated colour (ACCENT); baselines/context are greys; WARN marks a
problem. Titles state the finding, axes are labelled with units, no top/right spines, light grid.
"""
ACCENT = "#2563eb"      # our model / the thing to look at
ACCENT_LIGHT = "#93b4f5"
GREYS = ["#9aa5b1", "#7b8794", "#52606d"]  # baselines, lightest = weakest
WARN = "#d97706"        # large shift / leakage
INK = "#1f2933"
MUTED = "#7b8794"
GRID = "#e4e7eb"
FONT = "DejaVu Sans"


def mpl():
    """Configure matplotlib once and return pyplot."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.family": FONT, "font.size": 10.5, "axes.titlesize": 13, "axes.titleweight": "bold",
        "axes.titlelocation": "left", "axes.titlecolor": INK, "axes.labelcolor": INK,
        "axes.edgecolor": GRID, "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
        "xtick.color": MUTED, "ytick.color": MUTED, "legend.frameon": False,
        "figure.dpi": 100, "savefig.dpi": 200, "savefig.bbox": "tight",
    })
    return plt


def titles(ax, title: str, sub: str = "", size: float = 13):
    """Bold left-aligned title that states the finding, with a grey subtitle line below it."""
    ax.set_title(title, pad=26 if sub else 10, fontsize=size)
    if sub:
        ax.text(0, 1.025, sub, transform=ax.transAxes, color=MUTED, fontsize=9.5, va="bottom")
