import os
import re
import yaml
import feedparser
from datetime import datetime, timezone, timedelta
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))
MASTER_CFG = os.path.join(ROOT, "feeds.yaml")
OUT_MD = os.path.join(ROOT, "docs", "weekly.md")

def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()

def parse_date(entry):
    try:
        d = getattr(entry, "published", "") or getattr(entry, "updated", "")
        return dp.parse(d).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def severity(text: str) -> str:
    t = normalize(text)
    if any(x in t for x in ["actively exploited", "exploited in the wild", "ransomware", "data breach", "breach"]):
        return "🔴"
    if any(x in t for x in ["cve", "zero-day", "vulnerability", "patch", "security update", "incident", "outage"]):
        return "🟠"
    return "🔵"

def why(text: str) -> str:
    t = normalize(text)
    if "ransomware" in t:
        return "Validate backups, EDR coverage, and response readiness."
    if "phish" in t or "credential" in t:
        return "Reinforce MFA and user awareness; watch for suspicious sign-ins."
    if "outage" in t or "incident" in t or "service disruption" in t:
        return "Expect potential user impact; prep comms and check vendor status."
    if "entra" in t or "azure ad" in t or "conditional access" in t:
        return "May affect sign-in flows; watch Conditional Access and auth changes."
    if "exchange" in t or "mail flow" in t:
        return "May affect email access/delivery; monitor mail flow and client issues."
    if "licens" in t or "pricing" in t or "renewal" in t:
        return "Potential budget/licensing impact; verify terms and forecast."
    return "Worth awareness; review if it impacts your environment."

def main():
    with open(MASTER_CFG, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    since = datetime.now(timezone.utc) - timedelta(days=7)
    items = []

    for src in cfg.get("sources", []) or []:
        url = src.get("url")
        name = src.get("name", "Source")
        if not url:
            continue

        feed = feedparser.parse(url)
        for entry in getattr(feed, "entries", [])[:60]:
            title = (getattr(entry, "title", "") or "").strip()
            link = (getattr(entry, "link", "") or "").strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            dt = parse_date(entry)
            if dt < since:
                continue

            combined = f"{title} {summary} {name}"
            items.append({
                "dt": dt,
                "sev": severity(combined),
                "title": title or "(No title)",
                "link": link,
                "source": name,
                "why": why(combined),
            })

    items.sort(key=lambda x: x["dt"], reverse=True)

    top_critical = [x for x in items if x["sev"] == "🔴"][:5]
    top_important = [x for x in items if x["sev"] == "🟠"][:7]
    top_fyi = [x for x in items if x["sev"] == "🔵"][:5]

    now = datetime.now(timezone.utc)
    lines = []
    lines.append("# Weekly Executive Summary (last 7 days)")
    lines.append(f"_Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append("## 🔴 Critical (take action / validate exposure)")
    if top_critical:
        for x in top_critical:
            lines.append(f"- {x['sev']} [{x['title']}]({x['link']}) — **{x['source']}**  \n  _Why:_ {x['why']}")
    else:
        lines.append("- (None flagged as critical this week.)")

    lines.append("")
    lines.append("## 🟠 Important (monitor / plan / communicate)")
    if top_important:
        for x in top_important:
            lines.append(f"- {x['sev']} [{x['title']}]({x['link']}) — **{x['source']}**  \n  _Why:_ {x['why']}")
    else:
        lines.append("- (No high-signal items detected.)")

    lines.append("")
    lines.append("## 🔵 FYI (context / backlog reads)")
    if top_fyi:
        for x in top_fyi:
            lines.append(f"- {x['sev']} [{x['title']}]({x['link']}) — **{x['source']}**")
    else:
        lines.append("- (No FYI items captured.)")

    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

if __name__ == "__main__":
    main()
