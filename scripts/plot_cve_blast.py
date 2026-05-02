import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(16, 9))
fig.patch.set_facecolor("#0D1117")
ax.set_facecolor("#0D1117")
ax.set_xlim(0, 16)
ax.set_ylim(0, 9)
ax.axis("off")

C_CLIENT = "#1A3A52"
C_SERVER = "#1F2D3D"
C_TOOL = "#2980B9"
C_CVE = "#8E44AD"
C_CVE_BG = "#2D1B45"
C_CVE_BD = "#8E44AD"
C_WARN = "#F39C12"
C_HIGH = "#E05252"
C_TEXT = "white"
C_MUTED = "#7F8C8D"
C_EDGE = "#3D4A5C"
C_GLOW = "#A569BD"


def box(x, y, label, fill, w=2.0, h=0.65, fontsize=9, sublabel=None, border="white", lw=1.5):
    bx = FancyBboxPatch(
        (x - w / 2, y - h / 2),
        w,
        h,
        boxstyle="round,pad=0.08",
        facecolor=fill,
        edgecolor=border,
        linewidth=lw,
        zorder=5,
        alpha=0.95,
    )
    ax.add_patch(bx)
    dy = 0.10 if sublabel else 0
    ax.text(x, y + dy, label, ha="center", va="center", fontsize=fontsize, fontweight="bold", color=C_TEXT, zorder=6)
    if sublabel:
        ax.text(x, y - 0.15, sublabel, ha="center", va="center", fontsize=6.5, color="#95A5A6", zorder=6)


def cve_node(x, y, cve_id, desc, severity, w=3.0, h=1.1):
    for off, al in [(0.12, 0.12), (0.06, 0.22)]:
        bx = FancyBboxPatch(
            (x - w / 2 - off, y - h / 2 - off),
            w + 2 * off,
            h + 2 * off,
            boxstyle="round,pad=0.1",
            facecolor="none",
            edgecolor=C_CVE,
            linewidth=2,
            zorder=4,
            alpha=al,
        )
        ax.add_patch(bx)
    bx = FancyBboxPatch(
        (x - w / 2, y - h / 2),
        w,
        h,
        boxstyle="round,pad=0.09",
        facecolor=C_CVE_BG,
        edgecolor=C_CVE_BD,
        linewidth=2.2,
        zorder=5,
    )
    ax.add_patch(bx)

    sev_color = "#E05252" if severity == "HIGH" else "#E8943A"
    pill = FancyBboxPatch(
        (x - w / 2 + 0.1, y + 0.22),
        0.80,
        0.22,
        boxstyle="round,pad=0.03",
        facecolor=sev_color,
        edgecolor="none",
        zorder=7,
    )
    ax.add_patch(pill)
    ax.text(
        x - w / 2 + 0.50,
        y + 0.33,
        severity,
        ha="center",
        va="center",
        fontsize=6.5,
        fontweight="bold",
        color="white",
        zorder=8,
    )

    ax.text(x, y + 0.03, cve_id, ha="center", va="center", fontsize=11, fontweight="bold", color="#D7BDE2", zorder=6)
    ax.text(x, y - 0.25, desc, ha="center", va="center", fontsize=7, color="#A569BD", zorder=6)
    ax.text(
        x,
        y - 0.44,
        "blast radius: 2 servers",
        ha="center",
        va="center",
        fontsize=6.5,
        color=C_WARN,
        fontweight="bold",
        zorder=6,
    )


def arr(x0, y0, x1, y1, color=C_EDGE, lw=1.4, ls="-", rad=0.0, alpha=1.0):
    ax.annotate(
        "",
        xy=(x1, y1),
        xytext=(x0, y0),
        arrowprops=dict(arrowstyle="->", color=color, lw=lw, linestyle=ls, connectionstyle=f"arc3,rad={rad}"),
        zorder=3,
        alpha=alpha,
    )


def seg(x0, y0, x1, y1, color=C_EDGE, lw=1.0, ls="-"):
    ax.plot([x0, x1], [y0, y1], color=color, lw=lw, linestyle=ls, zorder=2)


# ── column headers ────────────────────────────────────────────────
for lx, lbl in [(2.0, "CLIENT"), (5.5, "SERVERS"), (9.5, "TOOLS"), (13.2, "SHARED CVE")]:
    ax.text(
        lx,
        8.4,
        lbl,
        ha="center",
        fontsize=8.5,
        color=C_MUTED,
        fontweight="bold",
        bbox=dict(facecolor="#0D1117", edgecolor="none", pad=2),
    )

# ── client ────────────────────────────────────────────────────────
box(2.0, 6.2, "ClaudeDesktop", C_CLIENT, w=2.1, sublabel="agent client")

# ── servers ───────────────────────────────────────────────────────
box(5.5, 7.2, "payment-server", "#1A2D1F", w=2.2, h=0.70, sublabel="mcp_server", border="#27AE60", lw=1.3)
box(5.5, 5.2, "http-client-server", C_SERVER, w=2.2, h=0.70, sublabel="mcp_server")

arr(2.0 + 1.05, 6.5, 5.5 - 1.1, 7.2, color="#5D6D7E", lw=1.4, rad=-0.15)
arr(2.0 + 1.05, 5.9, 5.5 - 1.1, 5.2, color="#5D6D7E", lw=1.4, rad=0.15)

# ── tools ─────────────────────────────────────────────────────────
box(9.5, 7.2, "process_payment", "#1A2D1F", w=2.2, sublabel="external_action", border="#27AE60", lw=1.2)
box(9.5, 5.2, "http_request", C_TOOL, w=2.2, sublabel="external_action")

seg(5.5 + 1.1, 7.2, 9.5 - 1.1, 7.2, color=C_EDGE, lw=1.1)
seg(5.5 + 1.1, 5.2, 9.5 - 1.1, 5.2, color=C_EDGE, lw=1.1)

# ── CVE node ──────────────────────────────────────────────────────
CVE_X, CVE_Y = 13.2, 6.2
cve_node(CVE_X, CVE_Y, "CVE-2023-32681", "requests lib  -  CVSS 7.5", "HIGH")

arr(9.5 + 1.1, 7.2, CVE_X - 1.5, CVE_Y + 0.28, color=C_CVE, lw=1.5, ls="dashed", rad=-0.2)
arr(9.5 + 1.1, 5.2, CVE_X - 1.5, CVE_Y - 0.28, color=C_CVE, lw=1.5, ls="dashed", rad=0.2)

# ── blast radius brace ────────────────────────────────────────────
brace_x = 3.4
for y in [7.2, 5.2]:
    seg(brace_x, y, brace_x + 0.3, y, color=C_WARN, lw=1.5)
seg(brace_x + 0.3, 7.2, brace_x + 0.3, 5.2, color=C_WARN, lw=1.5)
seg(brace_x + 0.3, 6.2, brace_x + 0.55, 6.2, color=C_WARN, lw=1.5)
ax.text(brace_x + 0.65, 6.2, "same\nclient", fontsize=6.5, color=C_WARN, va="center", ha="left", fontweight="bold")

# ── annotation ────────────────────────────────────────────────────
ax.text(
    0.3,
    8.0,
    "Single CVE in shared dependency (requests lib) exposes both servers simultaneously.",
    fontsize=8.5,
    color=C_WARN,
    fontweight="bold",
)
ax.text(
    0.3,
    7.65,
    "Patching one server is not enough - blast radius spans the entire client workspace.",
    fontsize=7.5,
    color="#95A5A6",
)

# ── legend ────────────────────────────────────────────────────────
items = [
    mpatches.Patch(facecolor=C_CVE_BG, edgecolor=C_CVE, label="shared CVE node"),
    mpatches.Patch(facecolor="#1A2D1F", edgecolor="#27AE60", label="payment server"),
    mpatches.Patch(facecolor=C_SERVER, edgecolor="white", label="http-client server"),
    plt.Line2D([0], [0], color=C_CVE, lw=1.5, linestyle="--", label="affected_by_cve edge"),
]
ax.legend(
    handles=items,
    loc="lower left",
    facecolor="#161B22",
    labelcolor="white",
    fontsize=8,
    framealpha=0.95,
    edgecolor="#30363D",
    borderpad=0.8,
)

ax.set_title("mcpsafetywarden  |  cross-server CVE blast radius", color="white", fontsize=13, fontweight="bold", pad=10)

plt.tight_layout()
plt.savefig("cve_blast_radius.png", dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
print("saved cve_blast_radius.png")
