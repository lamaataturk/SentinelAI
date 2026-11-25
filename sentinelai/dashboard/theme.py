"""Visual identity and small UI components for the SentinelAI dashboard.

Every value placed inside custom HTML goes through esc() first, so text from
agent messages (summaries, signatures, recommendations) is always shown as text.
"""
from __future__ import annotations

import html

import streamlit as st

SEVERITY_COLORS = {
    "Critical": "#991B1B",
    "High": "#EF4444",
    "Medium": "#F97316",
    "Low": "#22C55E",
    "Unassessed": "#6B7280",
    None: "#6B7280",
}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unassessed"]
SUPPORT_COLORS = {"strong": "#38BDF8", "weak": "#FBBF24", "unmapped": "#64748B", "no_hypothesis": "#1E293B"}
DECISION_COLORS = {"approved": "#22C55E", "rejected": "#EF4444", "pending": "#FBBF24"}
REF_STATUS = {
    "resolved": ("#22C55E", "resolved"),
    "missing": ("#EF4444", "missing"),
    "outside_incident": ("#F97316", "outside incident"),
    "not_checked": ("#64748B", "not checked"),
    "not_verified": ("#94A3B8", "rule not verified"),
}
CHART_COLORS = ["#38BDF8", "#818CF8", "#34D399", "#F472B6", "#FBBF24", "#A78BFA"]

CSS = """
<style>
:root {
  --sx-bg: #0B1220; --sx-panel: #111A2E; --sx-panel-2: #16223A; --sx-border: #22314F;
  --sx-text: #E2E8F0; --sx-muted: #94A3B8; --sx-accent: #38BDF8;
}
html, body, [class*="css"] { font-family: "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #0A1020 0%, #0E1729 100%);
  border-right: 1px solid var(--sx-border); }
h1, h2, h3 { letter-spacing: -0.01em; }
.sx-brand { display:flex; align-items:center; gap:.6rem; margin:.2rem 0 1rem 0; }
.sx-brand-logo { width:38px; height:38px; border-radius:10px; display:flex; align-items:center;
  justify-content:center; font-weight:800; color:#0B1220;
  background: linear-gradient(135deg, #38BDF8, #6366F1); }
.sx-brand-name { font-size:1.15rem; font-weight:700; color:var(--sx-text); line-height:1.1; }
.sx-brand-sub { font-size:.72rem; color:var(--sx-muted); text-transform:uppercase; letter-spacing:.08em; }
.sx-header { margin-bottom: 1rem; }
.sx-header h1 { font-size:1.65rem; margin:0; color:var(--sx-text); }
.sx-header p { color:var(--sx-muted); margin:.25rem 0 0 0; font-size:.92rem; }
.sx-card { background:var(--sx-panel); border:1px solid var(--sx-border); border-radius:12px;
  padding:1rem 1.1rem; height:100%; }
.sx-metric-label { color:var(--sx-muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.07em; }
.sx-metric-value { color:var(--sx-text); font-size:1.9rem; font-weight:700; margin-top:.15rem; }
.sx-metric-note { color:var(--sx-muted); font-size:.78rem; margin-top:.1rem; }
.sx-accent-bar { height:3px; border-radius:3px; margin-bottom:.7rem; }
.sx-badge { display:inline-block; padding:.12rem .55rem; border-radius:999px; font-size:.74rem;
  font-weight:600; border:1px solid; margin:0 .25rem .2rem 0; white-space:nowrap; }
.sx-chip { display:inline-block; padding:.1rem .45rem; border-radius:6px; font-size:.74rem;
  font-family: Consolas, "Cascadia Mono", monospace; background:#0E1729; border:1px solid var(--sx-border);
  color:var(--sx-text); margin:0 .25rem .25rem 0; }
.sx-banner { border-radius:10px; padding:.65rem .9rem; margin-bottom:1rem; font-size:.88rem;
  border:1px solid; }
.sx-banner-demo { background:rgba(251,191,36,.08); border-color:rgba(251,191,36,.45); color:#FDE68A; }
.sx-banner-info { background:rgba(56,189,248,.07); border-color:rgba(56,189,248,.35); color:#BAE6FD; }
.sx-banner-error { background:rgba(239,68,68,.08); border-color:rgba(239,68,68,.45); color:#FECACA; }
.sx-section { color:var(--sx-text); font-size:1.02rem; font-weight:650; margin:1.2rem 0 .55rem 0;
  padding-left:.55rem; border-left:3px solid var(--sx-accent); }
.sx-muted { color:var(--sx-muted); font-size:.85rem; }
.sx-empty { text-align:center; padding:1.6rem 1rem; color:var(--sx-muted); border:1px dashed var(--sx-border);
  border-radius:12px; background:rgba(17,26,46,.5); }
.sx-kc { display:grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap:.45rem; }
.sx-kc-stage { border-radius:10px; padding:.6rem .55rem; border:1px solid var(--sx-border); min-height:108px; }
.sx-kc-order { font-size:.68rem; color:var(--sx-muted); }
.sx-kc-name { font-size:.84rem; font-weight:650; color:var(--sx-text); margin:.1rem 0 .35rem 0; }
.sx-tl { position:relative; margin-left:.4rem; padding-left:1.1rem; border-left:2px solid var(--sx-border); }
.sx-tl-item { position:relative; margin-bottom:.85rem; }
.sx-tl-dot { position:absolute; left:-1.48rem; top:.3rem; width:.7rem; height:.7rem; border-radius:50%;
  background:var(--sx-accent); box-shadow:0 0 0 3px #0B1220; }
.sx-tl-time { color:var(--sx-muted); font-size:.74rem; font-family: Consolas, monospace; }
.sx-tl-text { color:var(--sx-text); font-size:.9rem; }
.sx-kv { display:grid; grid-template-columns: 160px 1fr; gap:.3rem .8rem; font-size:.86rem; }
.sx-kv dt { color:var(--sx-muted); } .sx-kv dd { margin:0; color:var(--sx-text); word-break:break-word; }
.sx-rec { background:var(--sx-panel-2); border:1px solid var(--sx-border); border-radius:10px;
  padding:.8rem .95rem; margin-bottom:.4rem; }
.sx-rec-action { font-weight:650; color:var(--sx-text); }
.sx-rec-reason { color:var(--sx-muted); font-size:.86rem; margin-top:.2rem; }
.st-key-report-view h1 { font-size:1.55rem !important; }
.st-key-report-view h2 { font-size:1.15rem !important; color:#BAE6FD; border-bottom:1px solid var(--sx-border);
  padding-bottom:.2rem; margin-top:1.1rem; }
.st-key-report-view h3 { font-size:.98rem !important; color:#C7D2FE; }
.st-key-report-view p, .st-key-report-view li { font-size:.9rem; }
.sx-kc { margin-bottom:.4rem; }
@media (max-width: 900px) { .sx-kc { grid-template-columns: repeat(2, minmax(0,1fr)); } }
</style>
"""


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def apply() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def html_block(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def header(title: str, subtitle: str = "") -> None:
    html_block(f'<div class="sx-header"><h1>{esc(title)}</h1>'
               + (f"<p>{esc(subtitle)}</p>" if subtitle else "") + "</div>")


def section(title: str) -> None:
    html_block(f'<div class="sx-section">{esc(title)}</div>')


def badge(text: str, color: str) -> str:
    return (f'<span class="sx-badge" style="color:{color};border-color:{color}66;'
            f'background:{color}1A">{esc(text)}</span>')


def severity_badge(severity: str | None) -> str:
    label = severity or "Unassessed"
    return badge(f"Severity: {label}", SEVERITY_COLORS.get(severity, SEVERITY_COLORS[None]))


def support_badge(support: str) -> str:
    labels = {"strong": "strong support", "weak": "weak support", "unmapped": "unmapped",
              "no_hypothesis": "no hypothesis"}
    return badge(labels.get(support, support), SUPPORT_COLORS.get(support, "#64748B"))


def decision_badge(decision: str) -> str:
    return badge(decision.capitalize(), DECISION_COLORS.get(decision, "#64748B"))


def chip(text: str) -> str:
    return f'<span class="sx-chip">{esc(text)}</span>'


def ref_chip(evidence: dict) -> str:
    color, label = REF_STATUS.get(evidence["status"], ("#64748B", evidence["status"]))
    return (f'<span class="sx-chip" title="{esc(label)}" style="border-color:{color}88">'
            f'<span style="color:{color}">●</span> {esc(evidence["ref"])}'
            f' <span style="color:var(--sx-muted)">· {esc(label)}</span></span>')


def metric(label: str, value, note: str = "", color: str = "#38BDF8") -> None:
    html_block(
        f'<div class="sx-card"><div class="sx-accent-bar" style="background:{color}"></div>'
        f'<div class="sx-metric-label">{esc(label)}</div><div class="sx-metric-value">{esc(value)}</div>'
        + (f'<div class="sx-metric-note">{esc(note)}</div>' if note else "") + "</div>"
    )


def banner(text: str, kind: str = "info") -> None:
    html_block(f'<div class="sx-banner sx-banner-{kind}">{esc(text)}</div>')


def demo_banner(system: dict | None) -> None:
    if system and system.get("is_demo_data"):
        banner("DEMONSTRATION DATA: everything on this page comes from synthetic fixtures "
               "(fixtures/*.json), not from real agent output. Random Forest scores in the fixtures "
               "are hand-written values, not measured model results.", "demo")


def empty(text: str) -> None:
    html_block(f'<div class="sx-empty">{esc(text)}</div>')


def kv(rows: list[tuple[str, str]], raw: bool = False) -> None:
    """Key/value list. Values are escaped unless raw=True (then they must already be safe HTML)."""
    body = "".join(f"<dt>{esc(k)}</dt><dd>{v if raw else esc(v)}</dd>" for k, v in rows)
    html_block(f'<dl class="sx-kv">{body}</dl>')


def fmt_score(score) -> str:
    return "not available" if score is None else f"{float(score):.2f}"


def fmt_ip(value) -> str:
    return "not recorded" if value in (None, "") else str(value)


def fmt_ts(value) -> str:
    """2026-01-10T08:00:00.123Z -> 2026-01-10 08:00:00 UTC"""
    if not value:
        return ""
    text = str(value).replace("T", " ").replace("Z", "")
    return text.split(".")[0] + " UTC"
