import feedparser
import yaml
import hashlib
import html
import os
import re
import json
import urllib.request
from datetime import datetime, timezone, timedelta
from email.utils import format_datetime
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))

CONFIGS = [
    ("feeds-urgent.yaml",       "urgent.xml",      "urgent"),
    ("feeds-security.yaml",     "security.xml",    "security"),
    ("feeds-microsoft.yaml",    "microsoft.xml",   "microsoft"),
    ("feeds-sysadmin.yaml",     "sysadmin.xml",    "sysadmin"),
    ("feeds-network.yaml",      "network.xml",     "network"),
    ("feeds-hospitality.yaml",  "hospitality.xml", "hospitality"),
    ("feeds-vp.yaml",           "vp.xml",          "vp"),
    ("feeds-ai.yaml",           "ai.xml",          "ai"),
    ("feeds-tech.yaml",         "tech.xml",        "tech"),
    ("feeds-radar.yaml",        "radar.xml",       "radar"),
    ("feeds-vendor.yaml",       "vendor.xml",      "vendor"),
    ("feeds-compliance.yaml",   "compliance.xml",  "compliance"),
    ("feeds.yaml",              "rss.xml",         "master"),
    ("feeds-archive.yaml",      "archive.xml",     "archive"),
]

MIN_ITEMS    = {"security": 15, "sysadmin": 15, "vp": 12, "radar": 12, "master": 25, "archive": 40, "vendor": 10, "compliance": 10}
MAX_ITEMS    = {"security": 80, "sysadmin": 80, "vp": 60, "radar": 60, "master": 120, "archive": 200, "urgent": 30, "vendor": 40, "compliance": 40}
FALLBACK_DAYS = {"security": 7, "sysadmin": 7, "vp": 10, "radar": 14, "master": 7, "archive": 30, "vendor": 14, "compliance": 14}

# Per-kind max age in hours (0 = no cap). Override via feeds-X.yaml: max_age_hours: N
DEFAULT_MAX_AGE_HOURS = {
    "urgent":     12,
    "security":   72,
    "microsoft":  72,
    "sysadmin":   72,
    "network":    72,
    "hospitality": 168,
    "vp":         168,
    "ai":         72,
    "tech":       168,
    "radar":      168,
    "vendor":     168,
    "compliance": 336,
    "master":     72,
    "archive":    0,
}

UA = "Mozilla/5.0 (GitHubActions; it-daily-rss)"

# Health tracking — written to docs/feed_health.json after each run
_health: dict = {}


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
        "breach", "data breach", "stolen data", "nation-state",
        "supply chain attack", "zero-click",
    ]
    important_terms = [
        "cve-", "cve", "vulnerability", "zero-day", "0-day",
        "patch", "security update", "hotfix", "mitigation",
        "outage", "service disruption", "incident", "critical severity",
        "high severity", "authentication bypass", "remote code execution",
        "privilege escalation", "data exposure",
    ]
    if any(x in t for x in critical_terms):
        return "🔴", "Critical"
    if any(x in t for x in important_terms):
        return "🟠", "Important"
    return "🔵", "FYI"


def why_this_matters(text: str, kind: str) -> str:
    t = normalize(text)

    if "ransomware" in t:
        return "Why this matters: Elevated ransomware risk — validate backups and endpoint defenses."
    if "supply chain" in t:
        return "Why this matters: Supply chain risk — audit third-party dependencies and vendor access."
    if "nation-state" in t or "apt" in t:
        return "Why this matters: Nation-state threat actor — elevated persistence and lateral movement risk."
    if "phish" in t or "credential" in t:
        return "Why this matters: Credential/phishing risk — reinforce MFA and user awareness training."
    if "breach" in t or "stolen" in t or "data exposure" in t:
        return "Why this matters: Potential data exposure — check monitoring and incident response readiness."
    if "outage" in t or "service disruption" in t or "incident" in t:
        return "Why this matters: Service impact possible — prepare comms and confirm vendor status."
    if "remote code execution" in t or "rce" in t:
        return "Why this matters: RCE vulnerability — patch immediately, check for exposed attack surface."
    if "authentication bypass" in t:
        return "Why this matters: Auth bypass — review access controls and check for unauthorized access."
    if "privilege escalation" in t:
        return "Why this matters: Privilege escalation risk — review local admin exposure and endpoint controls."

    if any(x in t for x in ["entra", "azure ad", "conditional access", "mfa", "authentication", "sso"]):
        return "Why this matters: Could impact sign-ins/MFA/Conditional Access — watch for login issues."
    if any(x in t for x in ["exchange", "outlook", "mail flow"]):
        return "Why this matters: Could impact email access or mail flow — monitor delivery and client issues."
    if any(x in t for x in ["intune", "mdm", "device compliance"]):
        return "Why this matters: Could affect device enrollment/compliance — watch policy deployment."
    if "defender" in t or "edr" in t:
        return "Why this matters: Endpoint detection changes — review high-severity detections and alert noise."
    if any(x in t for x in ["sonicwall", "aruba", "adtran", "fortinet", "cisco", "palo alto"]):
        return "Why this matters: Vendor advisory — check installed firmware/software version and patch status."
    if any(x in t for x in ["pricing", "license", "licensing", "renewal"]):
        return "Why this matters: Budget/licensing impact — verify renewal terms and forecast cost changes."
    if any(x in t for x in ["acquisition", "merger", "layoffs"]):
        return "Why this matters: Vendor risk signal — evaluate roadmap and support stability."
    if any(x in t for x in ["compliance", "regulation", "gdpr", "hipaa", "pci", "nist", "ftc"]):
        return "Why this matters: Regulatory/compliance signal — assess applicability and remediation timeline."
    if any(x in t for x in ["pms", "pос", "pos", "point of sale", "guest", "property management"]):
        return "Why this matters: Hospitality system impact — check guest-facing services and PMS/POS status."

    if kind == "security":
        return "Why this matters: Security-relevant change — confirm exposure and patch/mitigation status."
    if kind == "sysadmin":
        return "Why this matters: Operational impact possible — watch for changes that generate tickets."
    if kind == "vendor":
        return "Why this matters: Vendor security advisory — check your installed version against affected range."
    if kind == "compliance":
        return "Why this matters: Regulatory/compliance context — assess scope and action timeline."
    if kind == "radar":
        return "Why this matters: Early signal from niche sources — worth a quick scan."
    return "Why this matters: Leadership context — useful for risk, budget, and vendor conversations."


def fetch_url_bytes(url: str, timeout_seconds: int = 20) -> bytes | None:
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


def parse_feed(url: str, source_name: str, kind: str):
    """Fetch and parse a feed, recording health status."""
    data = fetch_url_bytes(url, timeout_seconds=20)
    key = f"{kind}::{source_name}"

    if not data:
        _health[key] = {"source": source_name, "url": url, "kind": kind, "status": "fetch_failed", "items": 0, "checked": datetime.now(timezone.utc).isoformat()}
        return None

    feed = feedparser.parse(data)
    entry_count = len(getattr(feed, "entries", []))

    if getattr(feed, "bozo", False):
        print(f"[WARN] Parse bozo: {url} :: {getattr(feed, 'bozo_exception', '')}")
        _health[key] = {"source": source_name, "url": url, "kind": kind, "status": "parse_warning", "items": entry_count, "checked": datetime.now(timezone.utc).isoformat()}
    else:
        _health[key] = {"source": source_name, "url": url, "kind": kind, "status": "ok", "items": entry_count, "checked": datetime.now(timezone.utc).isoformat()}

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

    if "cve" in t:              s += 25
    if "zero-day" in t or "0-day" in t: s += 30
    if "exploited" in t or "in the wild" in t: s += 35
    if "ransomware" in t:       s += 40
    if "breach" in t:           s += 35
    if "rce" in t or "remote code execution" in t: s += 30
    if "authentication bypass" in t: s += 28
    if "outage" in t or "incident" in t or "service disruption" in t: s += 25
    if "supply chain" in t:     s += 30
    if "nation-state" in t or "apt" in t: s += 35

    if any(x in t for x in ["microsoft", "m365", "entra", "azure ad", "intune", "exchange", "defender"]):
        s += 15
    if any(x in t for x in ["sonicwall", "aruba", "adtran", "fortinet"]):
        s += 10

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
    elif kind == "vendor":
        if any(x in t for x in ["advisory", "psirt", "cve", "patch", "firmware", "affected versions"]):
            s += 30
    elif kind == "compliance":
        if any(x in t for x in ["rule", "regulation", "enforcement", "deadline", "fine", "penalty"]):
            s += 25

    src = normalize(source_name)
    if "msrc" in src or "microsoft security" in src: s += 10
    if "cisa" in src:  s += 15
    if "sans" in src:  s += 5
    if "psirt" in src: s += 10

    return s


def collect_candidates(cfg: dict, kind: str, global_seen: set, max_age_hours: int) -> list:
    candidates = []
    local_seen = set()
    age_cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)) if max_age_hours > 0 else None

    for source in cfg.get("sources", []) or []:
        url = source.get("url")
        name = source.get("name", "Source")
        if not url:
            continue

        feed = parse_feed(url, name, kind)
        if not feed:
            continue

        for entry in getattr(feed, "entries", [])[:80]:
            title   = (getattr(entry, "title",   "") or "").strip() or "(No title)"
            link    = (getattr(entry, "link",    "") or url).strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            published = parse_date(entry)

            # Age gate — skip items older than max_age_hours
            if age_cutoff and published < age_cutoff:
                continue

            combined = f"{title} {summary} {name}"
            key = stable_dedupe_key(title, link)

            if key in global_seen:
                continue
            if key in local_seen:
                continue
            local_seen.add(key)

            # Keyword filter (optional, driven by YAML config)
            if cfg.get("keyword_filter_enabled"):
                keywords = [normalize(k) for k in (cfg.get("keywords") or [])]
                if keywords and not any(kw in normalize(combined) for kw in keywords):
                    continue

            sev_emoji, sev_label = classify_severity(combined)
            why = why_this_matters(combined, kind)
            score = score_item(kind, combined, name, sev_label)

            candidates.append({
                "title":      f"{sev_emoji} {title}",
                "link":       link,
                "summary":    summary,
                "source":     name,
                "date":       published,
                "severity":   sev_label,
                "why":        why,
                "dedupe_key": key,
                "score":      score,
            })

    return candidates


def choose_items(kind: str, candidates: list) -> list:
    max_items    = MAX_ITEMS.get(kind, 80)
    min_items    = MIN_ITEMS.get(kind, 12)
    lookback_days = FALLBACK_DAYS.get(kind, 7)
    cutoff       = datetime.now(timezone.utc) - timedelta(days=lookback_days)

    recent = [c for c in candidates if c["date"] >= cutoff]
    if not recent:
        recent = candidates[:]

    recent.sort(key=lambda x: (x["score"], x["date"]), reverse=True)
    chosen = recent[:max_items]

    if len(chosen) < min_items:
        all_sorted = sorted(candidates, key=lambda x: (x["score"], x["date"]), reverse=True)
        for c in all_sorted:
            if c not in chosen:
                chosen.append(c)
            if len(chosen) >= min_items:
                break

    chosen.sort(key=lambda x: x["date"], reverse=True)
    return chosen[:max_items]


def write_rss(cfg: dict, out_path: str, items: list):
    rss_items = []
    for it in items:
        age_label = _age_label(it["date"])
        desc = (
            f"<b>{html.escape(it['why'])}</b><br/>"
            + (f"{it['summary']}<br/>" if it["summary"] else "")
            + f"<br/><b>Source:</b> {html.escape(it['source'])}"
            f" &nbsp;|&nbsp; <b>Severity:</b> {html.escape(it['severity'])}"
            f" &nbsp;|&nbsp; <b>Age:</b> {html.escape(age_label)}"
        )
        rss_items.append(f"""
<item>
  <title>{html.escape(it['title'])}</title>
  <link>{html.escape(it['link'])}</link>
  <pubDate>{format_datetime(it['date'])}</pubDate>
  <source>{html.escape(it['source'])}</source>
  <description><![CDATA[{desc}]]></description>
</item>
""")

    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>{html.escape(cfg.get('title', ''))}</title>
  <description>{html.escape(cfg.get('description', ''))}</description>
  <lastBuildDate>{format_datetime(datetime.now(timezone.utc))}</lastBuildDate>
  {''.join(rss_items)}
</channel>
</rss>
"""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rss)


def _age_label(dt: datetime) -> str:
    delta = datetime.now(timezone.utc) - dt
    hours = int(delta.total_seconds() / 3600)
    if hours < 1:
        return "< 1h ago"
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def build_feed(cfg: dict, out_path: str, kind: str, global_seen: set):
    # Determine max age: YAML override > per-kind default > 0 (no cap)
    max_age_hours = cfg.get("max_age_hours", DEFAULT_MAX_AGE_HOURS.get(kind, 0))

    candidates = collect_candidates(cfg, kind, global_seen, max_age_hours)

    if not candidates:
        now = datetime.now(timezone.utc)
        items = [{
            "title":      "🔵 No items fetched — check GitHub Actions logs for feed fetch warnings",
            "link":       cfg.get("homepage", "https://github.com/jaf1248/it-daily-rss/actions"),
            "summary":    "",
            "source":     "it-daily-rss",
            "date":       now,
            "severity":   "FYI",
            "why":        "Why this matters: Feeds may be blocked or timing out — logs will show which URLs failed.",
            "dedupe_key": "diagnostic:" + kind,
            "score":      0,
        }]
        write_rss(cfg, out_path, items)
        return

    if kind in ("radar", "archive"):
        candidates.sort(key=lambda x: x["date"], reverse=True)
        items = candidates[:MAX_ITEMS.get(kind, 200)]
    else:
        items = choose_items(kind, candidates)

    # Cross-feed dedup: security Critical/Important block downstream feeds
    if kind == "security":
        for it in items:
            if it["severity"] in ("Critical", "Important"):
                global_seen.add(it["dedupe_key"])

    write_rss(cfg, out_path, items)


def write_health_report(docs_dir: str):
    """Write feed_health.json so the dashboard can show source status."""
    out = os.path.join(docs_dir, "feed_health.json")
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "feeds": list(_health.values()),
        "summary": {
            "total":        len(_health),
            "ok":           sum(1 for v in _health.values() if v["status"] == "ok"),
            "parse_warning": sum(1 for v in _health.values() if v["status"] == "parse_warning"),
            "fetch_failed": sum(1 for v in _health.values() if v["status"] == "fetch_failed"),
        }
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Print a summary to Actions log
    s = report["summary"]
    print(f"[HEALTH] {s['ok']} ok / {s['parse_warning']} warnings / {s['fetch_failed']} failed / {s['total']} total")
    if s["fetch_failed"]:
        failed = [v["source"] for v in _health.values() if v["status"] == "fetch_failed"]
        print(f"[HEALTH] Failed sources: {', '.join(failed)}")


def main():
    docs_dir    = os.path.join(ROOT, "docs")
    global_seen = set()

    for cfg_name, out_name, kind in CONFIGS:
        cfg_path = os.path.join(ROOT, cfg_name)
        out_path = os.path.join(docs_dir, out_name)
        if not os.path.exists(cfg_path):
            print(f"[SKIP] {cfg_name} not found")
            continue
        cfg = load_cfg(cfg_path)
        print(f"[BUILD] {cfg_name} → {out_name}")
        build_feed(cfg, out_path, kind, global_seen)

    write_health_report(docs_dir)


if __name__ == "__main__":
    main()
