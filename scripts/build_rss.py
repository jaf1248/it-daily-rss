import feedparser
import yaml
import hashlib
import html
import os
import re
import urllib.request
from datetime import datetime, timezone, timedelta
from email.utils import format_datetime
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))

CONFIGS = [
    ("feeds-security.yaml", "security.xml", "security"),
    ("feeds-sysadmin.yaml", "sysadmin.xml", "sysadmin"),
    ("feeds-vp.yaml", "vp.xml", "vp"),
    ("feeds-radar.yaml", "radar.xml", "radar"),
    ("feeds-tech.yaml", "tech.xml", "tech"),
    ("feeds.yaml", "rss.xml", "master"),
    ("feeds-archive.yaml", "archive.xml", "archive"),
]

MIN_ITEMS = {"security": 15, "sysadmin": 15, "vp": 12, "radar": 12, "master": 25, "archive": 40}
MAX_ITEMS = {"security": 80, "sysadmin": 80, "vp": 60, "radar": 60, "master": 120, "archive": 200}
FALLBACK_DAYS = {"security": 7, "sysadmin": 7, "vp": 10, "radar": 14, "master": 7, "archive": 30}

UA = "Mozilla/5.0 (GitHubActions; it-daily-rss)"


def load_cfg(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower()


def stable_dedupe_key(title: str, link: str) -> str:
    link_n = normalize(link)
    if link_n and link_n != "#":
        return link_n
    return "title:" + hashlib.sha1(normalize(title).encode("utf-8")).hexdigest()


def parse_date(entry) -> datetime:
    try:
        raw = getattr(entry, "published", "") or getattr(entry, "updated", "")
        return dp.parse(raw).astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def classify_severity(text: str):
    t = normalize(text)
    critical_terms = [
        "actively exploited", "exploited in the wild", "in the wild",
        "ransomware", "mass exploitation", "wormable", "botnet",
        "breach", "data breach", "stolen data"
    ]
    important_terms = [
        "cve-", "cve", "vulnerability", "zero-day", "0-day",
        "patch", "security update", "hotfix", "mitigation",
        "outage", "service disruption", "incident"
    ]
    if any(x in t for x in critical_terms):
        return "🔴", "Critical"
    if any(x in t for x in important_terms):
        return "🟠", "Important"
    return "🔵", "FYI"


def why_this_matters(text: str, kind: str) -> str:
    t = normalize(text)

    if "ransomware" in t:
        return "Why this matters: Elevated ransomware risk; validate backups and endpoint defenses."
    if "phish" in t or "credential" in t:
        return "Why this matters: Increased credential/phishing risk; reinforce MFA and user awareness."
    if "breach" in t or "stolen" in t:
        return "Why this matters: Potential exposure of credentials/data; check monitoring and incident readiness."
    if "outage" in t or "service disruption" in t or "incident" in t:
        return "Why this matters: Possible service impact; prepare comms and confirm vendor status."

    if any(x in t for x in ["entra", "azure ad", "conditional access", "mfa", "authentication", "sso"]):
        return "Why this matters: Could impact sign-ins/MFA/Conditional Access; watch for login issues."
    if any(x in t for x in ["exchange", "outlook", "mail flow"]):
        return "Why this matters: Could impact email access or mail flow; monitor delivery and client issues."
    if any(x in t for x in ["intune", "mdm", "device compliance"]):
        return "Why this matters: Could affect device enrollment/compliance; watch policy deployment."
    if "defender" in t or "edr" in t:
        return "Why this matters: Endpoint detection changes can affect alerts/noise; review high-severity detections."

    if any(x in t for x in ["pricing", "license", "licensing", "renewal"]):
        return "Why this matters: Budget/licensing impact; verify renewal terms and forecast cost changes."
    if any(x in t for x in ["acquisition", "merger", "layoffs"]):
        return "Why this matters: Vendor risk signal; evaluate roadmap/support stability."

    if kind == "security":
        return "Why this matters: Security-relevant change; confirm exposure and patch/mitigation status."
    if kind == "sysadmin":
        return "Why this matters: Operational impact possible; watch for changes that generate tickets."
    if kind == "radar":
        return "Why this matters: Early signal from niche sources; worth a quick scan."
    return "Why this matters: Leadership context; useful for risk/budget/vendor conversations."


def fetch_url_bytes(url: str, timeout_seconds: int = 20) -> bytes | None:
    """
    Fetch RSS/Atom with a real timeout + User-Agent.
    Using urllib avoids feedparser parameter incompatibilities.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": UA,
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return resp.read()
    except Exception as e:
        print(f"[WARN] Fetch failed: {url} :: {e}")
        return None


def parse_feed(url: str):
    data = fetch_url_bytes(url, timeout_seconds=20)
    if not data:
        return None
    # feedparser can parse bytes directly
    feed = feedparser.parse(data)
    if getattr(feed, "bozo", False):
        # still might have entries; just log it
        print(f"[WARN] Parse bozo: {url} :: {getattr(feed, 'bozo_exception', '')}")
    return feed


def score_item(kind: str, text: str, source_name: str, sev_label: str) -> int:
    t = normalize(text)
    s = 0

    if sev_label == "Critical":
        s += 100
    elif sev_label == "Important":
        s += 60
    else:
        s += 10

    if "cve" in t:
        s += 25
    if "zero-day" in t or "0-day" in t:
        s += 30
    if "exploited" in t or "in the wild" in t:
        s += 35
    if "ransomware" in t:
        s += 40
    if "breach" in t:
        s += 35
    if "outage" in t or "incident" in t or "service disruption" in t:
        s += 25

    if any(x in t for x in ["microsoft", "m365", "entra", "azure ad", "intune", "exchange", "defender"]):
        s += 15

    if kind == "security":
        if any(x in t for x in ["ransomware", "cve", "vulnerability", "zero-day", "breach", "exploited"]):
            s += 25
    elif kind == "sysadmin":
        if any(x in t for x in ["outage", "incident", "degradation", "patch", "update", "release", "breaking change", "deprecation"]):
            s += 25
        if any(x in t for x in ["mail flow", "dns", "certificate", "vpn", "authentication"]):
            s += 15
    elif kind == "vp":
        if any(x in t for x in ["pricing", "license", "licensing", "renewal", "contract", "acquisition", "merger", "layoffs"]):
            s += 35
        if any(x in t for x in ["risk", "compliance", "audit", "regulation"]):
            s += 20

    src = normalize(source_name)
    if "msrc" in src or "microsoft" in src:
        s += 5
    if "sans" in src:
        s += 5

    return s


def collect_candidates(cfg: dict, kind: str, global_seen: set) -> list:
    candidates = []
    local_seen = set()

    for source in cfg.get("sources", []) or []:
        url = source.get("url")
        name = source.get("name", "Source")
        if not url:
            continue

        feed = parse_feed(url)
        if not feed:
            continue

        for entry in getattr(feed, "entries", [])[:80]:
            title = (getattr(entry, "title", "") or "").strip() or "(No title)"
            link = (getattr(entry, "link", "") or url).strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            published = parse_date(entry)

            combined = f"{title} {summary} {name}"
            key = stable_dedupe_key(title, link)

            if key in global_seen:
                continue
            if key in local_seen:
                continue
            local_seen.add(key)

            sev_emoji, sev_label = classify_severity(combined)
            why = why_this_matters(combined, kind)
            score = score_item(kind, combined, name, sev_label)

            candidates.append({
                "title": f"{sev_emoji} {title}",
                "link": link,
                "summary": summary,
                "source": name,
                "date": published,
                "severity": sev_label,
                "why": why,
                "dedupe_key": key,
                "score": score,
            })

    return candidates


def choose_items(kind: str, candidates: list) -> list:
    max_items = MAX_ITEMS.get(kind, 80)
    min_items = MIN_ITEMS.get(kind, 12)
    lookback_days = FALLBACK_DAYS.get(kind, 7)
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    recent = [c for c in candidates if c["date"] >= cutoff]
    if not recent:
        recent = candidates[:]

    # Prefer high score but keep it readable
    recent.sort(key=lambda x: (x["score"], x["date"]), reverse=True)
    chosen = recent[:max_items]

    # Never empty: widen to everything if we still don't have enough
    if len(chosen) < min_items:
        all_sorted = sorted(candidates, key=lambda x: (x["score"], x["date"]), reverse=True)
        for c in all_sorted:
            if c not in chosen:
                chosen.append(c)
            if len(chosen) >= min_items:
                break

    # Final display: newest first
    chosen.sort(key=lambda x: x["date"], reverse=True)
    return chosen[:max_items]


def write_rss(cfg: dict, out_path: str, items: list):
    rss_items = []
    for it in items:
        desc = f"<b>{html.escape(it['why'])}</b><br/>"
        if it["summary"]:
            desc += f"{it['summary']}<br/>"
        desc += (
            f"<br/><b>Source:</b> {html.escape(it['source'])}"
            f" &nbsp; <b>Severity:</b> {html.escape(it['severity'])}"
        )
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


def build_feed(cfg: dict, out_path: str, kind: str, global_seen: set):
    candidates = collect_candidates(cfg, kind, global_seen)

    # If still nothing fetched, create a single diagnostic item so the UI isn't blank
    if not candidates:
        now = datetime.now(timezone.utc)
        items = [{
            "title": "🔵 No items fetched — check GitHub Actions logs for feed fetch warnings",
            "link": cfg.get("homepage", "https://github.com/jaf1248/it-daily-rss/actions"),
            "summary": "",
            "source": "it-daily-rss",
            "date": now,
            "severity": "FYI",
            "why": "Why this matters: Feeds may be blocked or timing out; logs will show which URLs failed.",
            "dedupe_key": "diagnostic:" + kind,
            "score": 0,
        }]
        write_rss(cfg, out_path, items)
        return

    # radar/archive are unfiltered "newest-first"; everything else is scored/curated
    if kind in ("radar", "archive"):
        candidates.sort(key=lambda x: x["date"], reverse=True)
        items = candidates[:MAX_ITEMS.get(kind, 200)]
    else:
        items = choose_items(kind, candidates)

    # Cross-feed suppression: only security critical/important blocks downstream
    if kind == "security":
        for it in items:
            if it["severity"] in ("Critical", "Important"):
                global_seen.add(it["dedupe_key"])

    write_rss(cfg, out_path, items)


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
