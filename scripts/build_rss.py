import feedparser
import yaml
import hashlib
import html
import os
import re
from datetime import datetime, timezone
from email.utils import format_datetime
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))

CONFIGS = [
    ("feeds-security.yaml", "security.xml", "security"),
    ("feeds-sysadmin.yaml", "sysadmin.xml", "sysadmin"),
    ("feeds-vp.yaml", "vp.xml", "vp"),
    ("feeds-radar.yaml", "radar.xml", "radar"),
    ("feeds.yaml", "rss.xml", "master"),
    ("feeds-archive.yaml", "archive.xml", "archive"),
]


def load_cfg(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalize(s):
    return re.sub(r"\s+", " ", (s or "").strip()).lower()


def keyword_match(cfg, text):
    if not cfg.get("keyword_filter_enabled", False):
        return True
    t = normalize(text)
    return any(k.lower() in t for k in (cfg.get("keywords") or []))


def classify_severity(text):
    t = normalize(text)

    critical = [
        "actively exploited", "exploited in the wild", "ransomware",
        "breach", "data breach", "wormable", "botnet"
    ]
    important = [
        "cve", "vulnerability", "zero-day", "patch",
        "security update", "incident", "outage"
    ]

    if any(x in t for x in critical):
        return "🔴", "Critical"
    if any(x in t for x in important):
        return "🟠", "Important"
    return "🔵", "FYI"


def why_this_matters(text, kind):
    t = normalize(text)

    if "ransomware" in t:
        return "Why this matters: Elevated ransomware risk; validate backups and endpoint defenses."
    if "phish" in t or "credential" in t:
        return "Why this matters: Increased credential/phishing risk; reinforce MFA."
    if "breach" in t:
        return "Why this matters: Possible data exposure; confirm monitoring and response readiness."
    if "outage" in t or "incident" in t:
        return "Why this matters: Possible service disruption; prep communications."

    if kind == "security":
        return "Why this matters: Security-relevant change; confirm exposure."
    if kind == "sysadmin":
        return "Why this matters: Operational impact possible; watch for tickets."
    if kind == "radar":
        return "Why this matters: Early signal from niche sources."
    return "Why this matters: Leadership context for risk and vendors."


def stable_dedupe_key(title, link):
    link_n = normalize(link)
    if link_n and link_n != "#":
        return link_n
    return hashlib.sha1(normalize(title).encode()).hexdigest()


def parse_date(entry):
    try:
        raw = getattr(entry, "published", "") or getattr(entry, "updated", "")
        return dp.parse(raw).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def build_feed(cfg, out_path, kind, global_seen):
    items = []
    local_seen = set()

    for source in cfg.get("sources", []) or []:
        url = source.get("url")
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

        for entry in getattr(feed, "entries", [])[:50]:
            title = (getattr(entry, "title", "") or "").strip() or "(No title)"
            link = (getattr(entry, "link", "") or url).strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            published = parse_date(entry)

            combined = f"{title} {summary} {source.get('name','')}"
            if not keyword_match(cfg, combined):
                continue

            key = stable_dedupe_key(title, link)

            if key in global_seen or key in local_seen:
                continue

            local_seen.add(key)

            sev_emoji, sev_label = classify_severity(combined)
            why = why_this_matters(combined, kind)

            items.append({
                "title": f"{sev_emoji} {title}",
                "link": link,
                "summary": summary,
                "source": source.get("name", "Source"),
                "date": published,
                "severity": sev_label,
                "why": why,
                "dedupe_key": key,
            })

    items.sort(key=lambda x: x["date"], reverse=True)
    items = items[:200]

    for it in items:
        if kind == "security" and it["severity"] in ("Critical", "Important"):
            global_seen.add(it["dedupe_key"])

    rss_items = []

    for it in items:
        desc = f"<b>{html.escape(it['why'])}</b><br/>"
        if it["summary"]:
            desc += f"{it['summary']}<br/>"
        desc += f"<br/><b>Source:</b> {html.escape(it['source'])} <b>Severity:</b> {html.escape(it['severity'])}"

        rss_items.append(f"""
<item>
<title>{html.escape(it['title'])}</title>
<link>{html.escape(it['link'])}</link>
<pubDate>{format_datetime(it['date'])}</pubDate>
<description><![CDATA[{desc}]]></description>
</item>
""")

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>{html.escape(cfg.get('title',''))}</title>
<description>{html.escape(cfg.get('description',''))}</description>
<lastBuildDate>{format_datetime(datetime.now(timezone.utc))}</lastBuildDate>
{''.join(rss_items)}
</channel>
</rss>
"""

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rss)


def main():
    docs_dir = os.path.join(ROOT, "docs")
    global_seen = set()

    for cfg_name, out_name, kind in CONFIGS:
        cfg = load_cfg(os.path.join(ROOT, cfg_name))
        build_feed(cfg, os.path.join(docs_dir, out_name), kind, global_seen)


if __name__ == "__main__":
    main()