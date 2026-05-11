"""
build_weekly.py
Generates docs/weekly.md — a leadership-ready executive briefing
from the master feed, covering the past 7 days.
Runs every Monday at 08:15 UTC via GitHub Actions.
"""
import os
import re
import yaml
import hashlib
import urllib.request
import feedparser
from datetime import datetime, timezone, timedelta
from dateutil import parser as dp

ROOT       = os.path.dirname(os.path.dirname(__file__))
MASTER_CFG = os.path.join(ROOT, "feeds.yaml")
OUT_MD     = os.path.join(ROOT, "docs", "weekly.md")

UA = "Mozilla/5.0 (GitHubActions; it-daily-rss)"


# ── helpers ────────────────────────────────────────────────────────────────

def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()


def parse_date(entry) -> datetime:
    try:
        raw = getattr(entry, "published", "") or getattr(entry, "updated", "")
        return dp.parse(raw).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def stable_key(title: str, link: str) -> str:
    ln = normalize(link)
    if ln and ln != "#":
        return ln
    return "t:" + hashlib.sha1(normalize(title).encode()).hexdigest()


def severity(text: str) -> tuple[str, str]:
    t = normalize(text)
    if any(x in t for x in [
        "actively exploited", "exploited in the wild", "ransomware",
        "breach", "nation-state", "supply chain attack", "zero-click",
        "mass exploitation", "wormable",
    ]):
        return "🔴", "Critical"
    if any(x in t for x in [
        "cve", "zero-day", "0-day", "vulnerability", "patch",
        "incident", "outage", "authentication bypass", "remote code execution",
        "privilege escalation", "security update",
    ]):
        return "🟠", "Important"
    return "🔵", "FYI"


def action(text: str) -> str:
    """Return a short, concrete recommended action for the executive summary."""
    t = normalize(text)
    if "ransomware" in t:
        return "Validate backups, confirm EDR coverage, and brief incident response team."
    if "supply chain" in t:
        return "Audit third-party software dependencies and review vendor access."
    if "nation-state" in t or "apt" in t:
        return "Elevate monitoring posture; brief security team on threat actor TTPs."
    if "breach" in t or "stolen" in t or "data exposure" in t:
        return "Verify no credential overlap; confirm DLP and SIEM alerting is active."
    if "remote code execution" in t or "rce" in t:
        return "Prioritize patching of affected systems; check for internet-exposed attack surface."
    if "authentication bypass" in t:
        return "Review access logs for unauthorized sessions; apply vendor patch immediately."
    if "zero-day" in t or "0-day" in t or "actively exploited" in t:
        return "Apply emergency patch or mitigation now; check vendor advisory for workarounds."
    if "phish" in t or "credential" in t:
        return "Reinforce MFA enforcement and run targeted phishing awareness reminder."
    if "outage" in t or "service disruption" in t:
        return "Prepare user communications; confirm vendor status page and SLA implications."
    if "entra" in t or "conditional access" in t or "azure ad" in t:
        return "Monitor sign-in logs; test Conditional Access policies for unintended changes."
    if "exchange" in t or "mail flow" in t:
        return "Monitor mail flow dashboards; alert helpdesk to watch for user reports."
    if "licens" in t or "pricing" in t or "renewal" in t:
        return "Forward to procurement; confirm budget forecast and renewal timeline."
    if "acquisition" in t or "merger" in t:
        return "Assess vendor roadmap impact; schedule account manager briefing."
    if "compliance" in t or "regulation" in t or "gdpr" in t or "hipaa" in t:
        return "Review applicability to your environment; assign compliance owner."
    if "sonicwall" in t or "aruba" in t or "fortinet" in t or "cisco" in t:
        return "Check installed firmware version against advisory; schedule patching window."
    return "Review and assess impact on your environment."


def why(text: str) -> str:
    t = normalize(text)
    if "ransomware" in t:
        return "Elevated ransomware risk across the sector."
    if "supply chain" in t:
        return "Third-party/software supply chain integrity risk."
    if "nation-state" in t:
        return "Advanced persistent threat activity detected."
    if "breach" in t:
        return "Potential credential or data exposure."
    if "outage" in t:
        return "Service continuity risk to users."
    if "entra" in t or "azure ad" in t:
        return "Possible impact to authentication and sign-in flows."
    if "exchange" in t:
        return "Potential email disruption for users."
    if "licens" in t or "pricing" in t:
        return "Budget and licensing exposure."
    if "acquisition" in t or "merger" in t:
        return "Vendor stability and roadmap risk."
    if "compliance" in t:
        return "Regulatory compliance action may be required."
    return "General awareness item."


def fetch_feed(url: str):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
        return feedparser.parse(data)
    except Exception as e:
        print(f"[WARN] {url}: {e}")
        return None


# ── main ───────────────────────────────────────────────────────────────────

def main():
    with open(MASTER_CFG, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    since = datetime.now(timezone.utc) - timedelta(days=7)
    seen  = set()
    items = []

    for src in cfg.get("sources", []) or []:
        url  = src.get("url")
        name = src.get("name", "Source")
        if not url:
            continue

        feed = fetch_feed(url)
        if not feed:
            continue

        for entry in getattr(feed, "entries", [])[:60]:
            title   = (getattr(entry, "title",   "") or "").strip() or "(No title)"
            link    = (getattr(entry, "link",    "") or "").strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            dt      = parse_date(entry)

            if dt < since:
                continue

            key = stable_key(title, link)
            if key in seen:
                continue
            seen.add(key)

            combined = f"{title} {summary} {name}"
            sev_emoji, sev_label = severity(combined)

            items.append({
                "dt":        dt,
                "sev":       sev_emoji,
                "sev_label": sev_label,
                "title":     title,
                "link":      link,
                "source":    name,
                "why":       why(combined),
                "action":    action(combined),
            })

    items.sort(key=lambda x: x["dt"], reverse=True)

    crit = [x for x in items if x["sev"] == "🔴"]
    imp  = [x for x in items if x["sev"] == "🟠"]
    fyi  = [x for x in items if x["sev"] == "🔵"]

    now_str  = datetime.now(timezone.utc).strftime("%B %d, %Y")
    week_str = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%B %d")

    lines = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        f"# IT Weekly Intelligence Briefing",
        f"**Period:** {week_str} – {now_str}  ",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Items reviewed:** {len(items)}  ",
        "",
    ]

    # ── Top 3 Actions ───────────────────────────────────────────────────────
    lines += ["## ⚡ Top Actions This Week", ""]
    top_actions = (crit + imp)[:3]
    if top_actions:
        for i, x in enumerate(top_actions, 1):
            lines.append(f"{i}. **{x['action']}**  ")
            lines.append(f"   _{x['title']}_  ")
            lines.append(f"   Source: {x['source']}  ")
            lines.append("")
    else:
        lines += ["_No urgent actions this week._", ""]

    # ── Critical ────────────────────────────────────────────────────────────
    lines += ["---", "", "## 🔴 Critical — Immediate Awareness", ""]
    if crit:
        for x in crit[:6]:
            dt_str = x["dt"].strftime("%b %d")
            lines.append(f"### [{x['title']}]({x['link']})")
            lines.append(f"**Source:** {x['source']} &nbsp;·&nbsp; **Date:** {dt_str}  ")
            lines.append(f"**Why it matters:** {x['why']}  ")
            lines.append(f"**Recommended action:** {x['action']}  ")
            lines.append("")
    else:
        lines += ["_No critical items this week._", ""]

    # ── Important ───────────────────────────────────────────────────────────
    lines += ["---", "", "## 🟠 Important — Review This Week", ""]
    if imp:
        for x in imp[:8]:
            dt_str = x["dt"].strftime("%b %d")
            lines.append(f"- [{x['title']}]({x['link']})  ")
            lines.append(f"  **{x['source']}** · {dt_str} · _{x['why']}_  ")
            lines.append("")
    else:
        lines += ["_No important items this week._", ""]

    # ── FYI ─────────────────────────────────────────────────────────────────
    lines += ["---", "", "## 🔵 FYI — General Awareness", ""]
    if fyi:
        for x in fyi[:6]:
            lines.append(f"- [{x['title']}]({x['link']}) — {x['source']}")
    else:
        lines += ["_No FYI items this week._"]

    # ── Footer ──────────────────────────────────────────────────────────────
    lines += [
        "",
        "---",
        "",
        f"_Auto-generated by [it-daily-rss](https://jaf1248.github.io/it-daily-rss/) · "
        f"{len(crit)} critical · {len(imp)} important · {len(fyi)} FYI_",
    ]

    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[WEEKLY] Written: {OUT_MD}  ({len(crit)} crit / {len(imp)} imp / {len(fyi)} fyi)")


if __name__ == "__main__":
    main()
