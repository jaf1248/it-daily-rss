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

# Priority order matters for cross-feed dedupe:
# items added to earlier feeds won't repeat in later feeds.
CONFIGS = [
    ("feeds-security.yaml", "security.xml", "security"),
    ("feeds-sysadmin.yaml", "sysadmin.xml", "sysadmin"),
    ("feeds-vp.yaml", "vp.xml", "vp"),
    ("feeds-radar.yaml", "radar.xml", "radar"),
]


def load_cfg(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()

def keyword_match(cfg, text):
    if not cfg.get("keyword_filter_enabled", False):
        return True
    t = normalize(text)
    return any(k.lower() in t for k in (cfg.get("keywords") or []))

def classify_severity(text: str):
    """
    Returns (emoji, label) where label is one of: Critical/Important/FYI
    """
    t = normalize(text)

    critical_terms = [
        "actively exploited", "exploited in the wild", "in the wild",
        "ransomware", "mass exploitation", "wormable", "botnet",
        "breach", "data breach", "stolen data"
    ]
    important_terms = [
        "cve-", "cve", "vulnerability", "zero-day", "0-day",
        "patch", "security update", "hotfix", "mitigation",
        "microsoft outage", "service disruption", "incident"
    ]

    if any(x in t for x in critical_terms):
        return "🔴", "Critical"
    if any(x in t for x in important_terms):
        return "🟠", "Important"
    return "🔵", "FYI"

def why_this_matters(text: str, kind: str) -> str:
    """
    Short, exec-friendly one-liner. Heuristic-based (fast + good enough).
    """
    t = normalize(text)

    # common signals
    if "ransomware" in t:
        return "Why this matters: Elevated ransomware risk; validate backups and endpoint defenses."
    if "phish" in t or "credential" in t:
        return "Why this matters: Increased credential/phishing risk for users; reinforce MFA and user awareness."
    if "breach" in t or "stolen" in t:
        return "Why this matters: Potential exposure of credentials/data; check monitoring and incident readiness."
    if "outage" in t or "service disruption" in t or "incident" in t:
        return "Why this matters: Possible service impact; prepare comms and confirm vendor status before troubleshooting internally."

    # Microsoft/identity/mail signals
    if any(x in t for x in ["entra", "azure ad", "conditional access", "mfa", "authentication", "sso"]):
        return "Why this matters: Could impact sign-ins/MFA/Conditional Access; watch for user login issues."
    if any(x in t for x in ["exchange", "outlook", "mail flow"]):
        return "Why this matters: Could impact email access or mail flow; monitor for client/server-side issues."
    if any(x in t for x in ["intune", "mdm", "device compliance"]):
        return "Why this matters: Could affect device enrollment/compliance; watch policy deployment and enrollment errors."
    if "defender" in t or "edr" in t:
        return "Why this matters: Endpoint detection changes can affect alerts/noise; review high-severity detections."

    # VP signals
    if any(x in t for x in ["pricing", "license", "licensing", "renewal"]):
        return "Why this matters: Budget/licensing impact; verify renewal terms and forecast cost changes."
    if any(x in t for x in ["acquisition", "merger", "layoffs"]):
        return "Why this matters: Vendor risk signal; evaluate roadmap/support stability."

    # default by feed kind
    if kind == "security":
        return "Why this matters: Security-relevant change; confirm exposure and patch/mitigation status."
    if kind == "sysadmin":
        return "Why this matters: Operational impact possible; watch for changes that generate tickets."
    return "Why this matters: Leadership context; useful for risk/budget/vendor conversations."

def stable_dedupe_key(title: str, link: str) -> str:
    """
    Prefer link for dedupe; fall back to title hash.
    """
    link_n = normalize(link)
    if link_n and link_n != "#":
        return link_n
    return "title:" + hashlib.sha1(normalize(title).encode("utf-8")).hexdigest()

def parse_date(entry) -> datetime:
    try:
        return dp.parse(getattr(entry, "published", "")).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)

def build_feed(cfg, out_path, kind, global_seen):
    items = []
    local_seen = set()

    for source in cfg.get("sources", []):
        feed = feedparser.parse(source["url"])
        for entry in feed.entries[:50]:
            title = (getattr(entry, "title", "") or "").strip() or "(No title)"
            link = (getattr(entry, "link", "") or source["url"]).strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            published = parse_date(entry)

            combined = f"{title} {summary} {source.get('name','')}"
            if not keyword_match(cfg, combined):
                continue

            # Cross-feed dedupe
            key = stable_dedupe_key(title, link)
            if key in global_seen:
                continue

            # Within-feed dedupe
            if key in local_seen:
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

    # Sort newest first
    items.sort(key=lambda x: x["date"], reverse=True)
    items = items[:200]

    # Mark these as seen globally so later feeds skip them
    for it in items:
        global_seen.add(it["dedupe_key"])

    rss_items = []
    for it in items:
        # Keep description readable in feed readers
        desc = f"<b>{html.escape(it['why'])}</b><br/>"
        if it["summary"]:
            desc += f"{it['summary']}<br/>"
        desc += f"<br/><b>Source:</b> {html.escape(it['source'])} &nbsp; <b>Severity:</b> {html.escape(it['severity'])}"

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
        cfg_path = os.path.join(ROOT, cfg_name)
        out_path = os.path.join(docs_dir, out_name)
        cfg = load_cfg(cfg_path)
        build_feed(cfg, out_path, kind, global_seen)

if __name__ == "__main__":
    main()
