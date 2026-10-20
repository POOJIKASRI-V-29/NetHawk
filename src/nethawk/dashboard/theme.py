"""Dark theme palette and shared widget styling for the NetHawk dashboard."""
from __future__ import annotations

BG = "#0b0f16"
PANEL = "#141a24"
PANEL_ALT = "#1b2331"
BORDER = "#26303f"
TEXT = "#e6edf3"
TEXT_DIM = "#8b98a9"
ACCENT = "#22d3ee"
ACCENT_DARK = "#0e7490"

RISK_COLORS = {
    "LOW": "#3ddc84",
    "MEDIUM": "#ffb020",
    "HIGH": "#ff4d5e",
}
OK = "#3ddc84"
WARN = "#ffb020"
DANGER = "#ff4d5e"
INFO = "#22d3ee"

LEVEL_COLORS = {
    "success": OK,
    "warning": WARN,
    "error": DANGER,
    "info": INFO,
}

FONT_FAMILY = "SF Pro Display"
MONO_FAMILY = "Menlo"


def risk_color(level: str) -> str:
    return RISK_COLORS.get(str(level).upper(), TEXT_DIM)


def style_treeview(style) -> None:
    """Make ttk.Treeview match the dark theme (ttk does not follow CTk)."""
    style.theme_use("clam")
    style.configure(
        "NetHawk.Treeview",
        background=PANEL,
        fieldbackground=PANEL,
        foreground=TEXT,
        rowheight=27,
        borderwidth=0,
        font=(MONO_FAMILY, 11),
    )
    style.configure(
        "NetHawk.Treeview.Heading",
        background=PANEL_ALT,
        foreground=TEXT_DIM,
        relief="flat",
        borderwidth=0,
        font=(FONT_FAMILY, 11, "bold"),
    )
    style.map("NetHawk.Treeview.Heading", background=[("active", BORDER)])
    style.map("NetHawk.Treeview",
              background=[("selected", ACCENT_DARK)],
              foreground=[("selected", "#ffffff")])
    style.configure("NetHawk.Vertical.TScrollbar", background=PANEL_ALT,
                    troughcolor=BG, bordercolor=BG, arrowcolor=TEXT_DIM)
