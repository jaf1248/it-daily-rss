import os
import re
import yaml
import feedparser
from datetime import datetime, timezone, timedelta
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))
MASTER_CFG = os.path.join(ROOT, "feeds.yaml")
OUT_MD = os.path.join(ROOT, "docs", "weekly.md")

def normalize(s):
    return re.sub(r"\s+", " ", (s or "").strip()).lower()

def parse_date(entry):
    try:
        raw = getattr(entry, "published", "") or getattr(entry, "updated", "")
        return dp.parse(raw).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def severity(text):
    t = normalize(text)
    if any(x in t for x in ["actively exploited", "exploited in the wild", "ransomware", "breach"]):
        return "🔴"
    if any(x in t for x in ["cve", "zero-day", "vulnerability", "patch", "incident", "outage"]):
        return "🟠"
    return "🔵"

def why(text):
    t = normalize(text)
    if "ransomware" in t:
        return "Validate backups and EDR."
    if "phish" in t or "credential" in t:
        return "Reinforce MFA and user awareness."
    if "outage" in t:
        return "Prep comms and confirm vendor status."
    if "entra" in t or "azure ad" in t:
        return "Watch sign-in and Conditional Access changes."
    if "exchange" in t:
        return "Monitor mail flow and Outlook access."
    if "licens" in t or "pricing" in t:
        return "Check renewal and budget impact."
    return "General awareness."

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

        try:
            feed = feedparser.parse(
                url,
                request_headers={"User-Agent": "Mozilla/5.0"},
                timeout=20,
            )
        except Exception:
            continue

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

    crit = [x for x in items if x["sev"] == "🔴"][:5]
    imp = [x for x in items if x["sev"] == "🟠"][:7]
    fyi = [x for x in items if x["sev"] == "🔵"][:5]

    lines = []
    lines.append("# Weekly Executive Summary (last 7 days)")
    lines.append(f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")

    lines.append("## 🔴 Critical")
    lines.extend([f"- [{x['title']}]({x['link']}) — {x['why']}" for x in crit] or ["- None"])

    lines.append("")
    lines.append("## 🟠 Important")
    lines.extend([f"- [{x['title']}]({x['link']}) — {x['why']}" for x in imp] or ["- None"])

    lines.append("")
    lines.append("## 🔵 FYI")
    lines.extend([f"- [{x['title']}]({x['link']})" for x in fyi] or ["- None"])

    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    main()