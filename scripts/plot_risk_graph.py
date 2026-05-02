import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(22, 13))
fig.patch.set_facecolor("#0D1117")
ax.set_facecolor("#0D1117")
ax.set_xlim(-0.3, 14.3)
ax.set_ylim(-0.8, 10.5)
ax.axis("off")

C_HIGH = "#E05252"
C_MED = "#E8943A"
C_EXT = "#C0392B"
C_READ = "#2980B9"
C_CVE = "#8E44AD"
C_PROBE = "#27AE60"
C_SOURCE = "#2471A3"
C_INFER = "#566573"
C_SERVER = "#1F2D3D"
C_CLIENT = "#1A3A52"
C_BG = "#161B22"
C_WARN = "#F39C12"

# ── helpers ──────────────────────────────────────────────────────


def box(ax, x, y, label, fill, w=1.8, h=0.58, fontsize=8.5, sublabel=None, border="white", lw=1.5):
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
    dy = 0.09 if sublabel else 0
    ax.text(x, y + dy, label, ha="center", va="center", fontsize=fontsize, fontweight="bold", color="white", zorder=6)
    if sublabel:
        ax.text(x, y - 0.14, sublabel, ha="center", va="center", fontsize=6, color="#95A5A6", zorder=6)


def finding(ax, x, y, text, by, conf, risk_color, w=3.2, h=0.58):
    c = {"probe": C_PROBE, "source": C_SOURCE, "inferred": C_INFER}[by]
    lw = {"probe": 2.0, "source": 1.6, "inferred": 0.9}[by]
    ls = {"probe": "-", "source": "-", "inferred": "--"}[by]
    bx = FancyBboxPatch(
        (x - w / 2, y - h / 2),
        w,
        h,
        boxstyle="round,pad=0.07",
        facecolor=C_BG,
        edgecolor=c,
        linewidth=lw,
        linestyle=ls,
        zorder=7,
    )
    ax.add_patch(bx)
    pill = FancyBboxPatch(
        (x - w / 2 + 0.06, y + 0.07),
        0.70,
        0.20,
        boxstyle="round,pad=0.03",
        facecolor=risk_color,
        edgecolor="none",
        zorder=8,
    )
    ax.add_patch(pill)
    rl = "HIGH" if risk_color == C_HIGH else "MEDIUM"
    ax.text(
        x - w / 2 + 0.41,
        y + 0.17,
        rl,
        ha="center",
        va="center",
        fontsize=5.8,
        fontweight="bold",
        color="white",
        zorder=9,
    )
    ax.text(x - w / 2 + 0.88, y + 0.17, text, ha="left", va="center", fontsize=7, color="white", zorder=8)
    ax.text(
        x - w / 2 + 0.10,
        y - 0.18,
        f"{by}  {int(conf * 100)}%",
        ha="left",
        va="center",
        fontsize=6.5,
        color=c,
        fontweight="bold",
        zorder=8,
    )


def cve_node(ax, x, y, cve_id, desc, w=2.6, h=0.80):
    # glowing border
    for off, al in [(0.08, 0.15), (0.04, 0.25)]:
        bx = FancyBboxPatch(
            (x - w / 2 - off, y - h / 2 - off),
            w + 2 * off,
            h + 2 * off,
            boxstyle="round,pad=0.1",
            facecolor="none",
            edgecolor=C_CVE,
            linewidth=2,
            zorder=6,
            alpha=al,
        )
        ax.add_patch(bx)
    bx = FancyBboxPatch(
        (x - w / 2, y - h / 2),
        w,
        h,
        boxstyle="round,pad=0.08",
        facecolor="#2D1B45",
        edgecolor=C_CVE,
        linewidth=2.2,
        zorder=7,
    )
    ax.add_patch(bx)
    ax.text(x, y + 0.15, cve_id, ha="center", va="center", fontsize=9.5, fontweight="bold", color="#D7BDE2", zorder=8)
    ax.text(x, y - 0.16, desc, ha="center", va="center", fontsize=6.5, color="#A569BD", zorder=8)
    ax.text(
        x,
        y - 0.36,
        "SHARED  across servers",
        ha="center",
        va="center",
        fontsize=6,
        color=C_WARN,
        fontweight="bold",
        zorder=8,
        bbox=dict(facecolor="#2D1B45", edgecolor="none", pad=1),
    )


def arr(ax, x0, y0, x1, y1, color="#3D4A5C", lw=1.2, ls="-", rad=0.0, alpha=1.0):
    ax.annotate(
        "",
        xy=(x1, y1),
        xytext=(x0, y0),
        arrowprops=dict(
            arrowstyle="->", color=color, lw=lw, linestyle=ls, connectionstyle=f"arc3,rad={rad}", alpha=alpha
        ),
        zorder=3,
    )


def seg(ax, x0, y0, x1, y1, color="#3D4A5C", lw=1.0, ls="-"):
    ax.plot([x0, x1], [y0, y1], color=color, lw=lw, linestyle=ls, zorder=2)


# ── layout constants ──────────────────────────────────────────────
CX = 1.0  # clients
SX = 3.5  # servers
TX = 6.3  # tools
FX = 11.2  # findings
CVE_X = 11.2  # CVE shared node x (same column as findings)
CVE_Y = 4.75  # between the two server groups

# ── scenario 1 label ─────────────────────────────────────────────
ax.text(
    -0.1,
    9.95,
    "① Multiple clients → shared server  (one compromise = all clients affected)",
    fontsize=9,
    color=C_WARN,
    fontweight="bold",
)
ax.text(
    -0.1,
    4.35,
    "② Same CVE across two servers  (single supply chain vuln, two blast radii)",
    fontsize=9,
    color=C_CVE,
    fontweight="bold",
)

# horizontal divider
ax.axhline(4.55, color="#2A2A3A", lw=1.2, linestyle="--", alpha=0.6)

# ── CLIENTS ───────────────────────────────────────────────────────
box(ax, CX, 8.0, "ClaudeDesktop", C_CLIENT, w=1.7, sublabel="agent client")
box(ax, CX, 6.8, "CursorAI", C_CLIENT, w=1.7, sublabel="agent client")

# shared server risk bracket
brace_x = CX + 1.05
for y in [8.0, 6.8]:
    seg(ax, brace_x, y, brace_x + 0.3, y, color=C_WARN, lw=1.5)
seg(ax, brace_x + 0.3, 8.0, brace_x + 0.3, 6.8, color=C_WARN, lw=1.5)
seg(ax, brace_x + 0.3, 7.4, brace_x + 0.55, 7.4, color=C_WARN, lw=1.5)
ax.text(brace_x + 0.65, 7.4, "shared\nserver", fontsize=6.5, color=C_WARN, va="center", fontweight="bold")

# ── SERVER 1 ──────────────────────────────────────────────────────
box(ax, SX, 7.4, "evil-test-server", C_SERVER, w=2.1, h=0.65, sublabel="mcp_server")
arr(ax, CX + 0.85, 8.0, SX - 1.05, 7.55, color="#5D6D7E", lw=1.4, rad=-0.12)
arr(ax, CX + 0.85, 6.8, SX - 1.05, 7.25, color="#5D6D7E", lw=1.4, rad=0.12)

# tools for server 1
s1_tools = [
    ("read_workspace_file", 9.0, C_READ, "read_only", "path traversal / arb. read", "probe", 0.92, C_HIGH, False),
    ("get_env_var", 7.9, C_READ, "read_only", "env var cred harvesting", "source", 0.85, C_HIGH, False),
    ("send_to_webhook", 6.8, C_EXT, "external_action", "unencrypted exfil endpoint", "inferred", 0.62, C_MED, True),
]
for name, ty, fill, eff, find_txt, by, conf, risk, has_cve in s1_tools:
    box(ax, TX, ty, name, fill, w=2.0, sublabel=eff, fontsize=7.5)
    seg(ax, SX + 1.05, 7.4, TX - 1.0, ty, color="#3D4A5C", lw=1.0)
    if find_txt and not has_cve:
        arr(ax, TX + 1.0, ty, FX - 1.6, ty, color="#3D4A5C", lw=1.0)
        finding(ax, FX, ty, find_txt, by, conf, risk)
    elif has_cve:
        arr(ax, TX + 1.0, ty, CVE_X - 1.3, CVE_Y + 0.25, color=C_CVE, lw=1.3, ls="dashed", rad=-0.2)

# ── CVE SHARED NODE ───────────────────────────────────────────────
cve_node(ax, CVE_X, CVE_Y, "CVE-2023-32681", "requests  -  CVSS 7.5  HIGH")

# ── SERVER 2 ──────────────────────────────────────────────────────
box(ax, SX, 3.5, "payment-server", "#1A2D1F", w=2.1, h=0.65, sublabel="mcp_server", border="#27AE60", lw=1.2)

s2_tools = [
    ("http_request", 4.1, C_EXT, "external_action", "SSRF via user-supplied URL", "probe", 0.88, C_HIGH, True),
    ("process_payment", 3.0, C_EXT, "external_action", "missing auth on payment route", "source", 0.90, C_HIGH, False),
    ("store_credentials", 1.9, C_READ, "read_only", "plaintext cred storage", "probe", 0.95, C_HIGH, False),
]
for name, ty, fill, eff, find_txt, by, conf, risk, has_cve in s2_tools:
    box(ax, TX, ty, name, fill, w=2.0, sublabel=eff, fontsize=7.5)
    seg(ax, SX + 1.05, 3.5, TX - 1.0, ty, color="#3D4A5C", lw=1.0)
    if find_txt and not has_cve:
        arr(ax, TX + 1.0, ty, FX - 1.6, ty, color="#3D4A5C", lw=1.0)
        finding(ax, FX, ty, find_txt, by, conf, risk)
    elif has_cve:
        arr(ax, TX + 1.0, ty, CVE_X - 1.3, CVE_Y - 0.25, color=C_CVE, lw=1.3, ls="dashed", rad=0.2)

# exfil path within server 1 (read -> external, subtle)
arr(ax, TX + 1.0, 9.0, TX + 1.0, 6.8, color=C_HIGH, lw=0.9, ls="dashed", rad=0.4, alpha=0.3)
arr(ax, TX + 1.0, 7.9, TX + 1.0, 6.8, color=C_HIGH, lw=0.9, ls="dashed", rad=0.3, alpha=0.3)
ax.text(TX + 1.55, 7.85, "exfil", fontsize=6, color=C_HIGH, alpha=0.45, style="italic")

# ── column headers ────────────────────────────────────────────────
for lx, lbl in [(CX, "CLIENTS"), (SX, "SERVERS"), (TX, "TOOLS"), (FX, "FINDINGS")]:
    ax.text(
        lx,
        10.15,
        lbl,
        ha="center",
        fontsize=8.5,
        color="#7F8C8D",
        fontweight="bold",
        bbox=dict(facecolor="#0D1117", edgecolor="none", pad=2),
    )

# ── legend ────────────────────────────────────────────────────────
items = [
    mpatches.Patch(facecolor=C_READ, edgecolor="white", label="read_only"),
    mpatches.Patch(facecolor=C_EXT, edgecolor="white", label="external_action"),
    mpatches.Patch(facecolor=C_CVE, edgecolor="white", label="CVE (shared)"),
    mpatches.Patch(facecolor=C_PROBE, edgecolor="white", label="probe confirmed"),
    mpatches.Patch(facecolor=C_SOURCE, edgecolor="white", label="source analysis"),
    mpatches.Patch(facecolor=C_INFER, edgecolor="white", label="inferred"),
    plt.Line2D([0], [0], color=C_HIGH, lw=1.4, linestyle="--", alpha=0.6, label="exfil path"),
    plt.Line2D([0], [0], color=C_CVE, lw=1.4, linestyle="--", label="maps_to CVE"),
]
ax.legend(
    handles=items,
    loc="lower right",
    facecolor="#161B22",
    labelcolor="white",
    fontsize=8,
    framealpha=0.95,
    edgecolor="#30363D",
    ncol=2,
    borderpad=0.8,
    columnspacing=1.0,
)

ax.set_title(
    "mcpsafetywarden  |  multi-client + cross-server CVE blast radius",
    color="white",
    fontsize=13,
    fontweight="bold",
    pad=10,
)
plt.tight_layout()
plt.savefig("evil_server_graph.png", dpi=160, bbox_inches="tight", facecolor=fig.get_facecolor())
print("done")
