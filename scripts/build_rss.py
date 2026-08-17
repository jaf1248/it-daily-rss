import feedparser
import yaml
import hashlib
import html
import os
import re
import json
import urllib.request
import urllib.error
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

# Minimum number of articles we'd LIKE each category to contain.
# If the normal freshness window doesn't supply enough, the script
# automatically widens the window using older available articles.
MIN_ITEMS = {
    "urgent": 8,
    "security": 15,
    "microsoft": 15,
    "sysadmin": 15,
    "network": 12,
    "hospitality": 10,
    "vp": 12,
    "ai": 12,
    "tech": 12,
    "radar": 12,
    "vendor": 10,
    "compliance": 8,
    "master": 25,
    "archive": 40,
}

MAX_ITEMS = {
    "urgent": 30,
    "security": 80,
    "microsoft": 80,
    "sysadmin": 80,
    "network": 60,
    "hospitality": 50,
    "vp": 60,
    "ai": 60,
    "tech": 60,
    "radar": 60,
    "vendor": 50,
    "compliance": 40,
    "master": 120,
    "archive": 250,
}

# Preferred freshness window for each dashboard category.
DEFAULT_MAX_AGE_HOURS = {
    "urgent": 48,          # 2 days
    "security": 168,       # 7 days
    "microsoft": 168,      # 7 days
    "sysadmin": 168,       # 7 days
    "network": 168,        # 7 days
    "hospitality": 336,    # 14 days
    "vp": 336,             # 14 days
    "ai": 168,             # 7 days
    "tech": 336,           # 14 days
    "radar": 336,          # 14 days
    "vendor": 336,         # 14 days
    "compliance": 720,     # 30 days
    "master": 168,         # 7 days
    "archive": 0,          # no age limit
}

UA = "Mozilla/5.0 (compatible; JoeITIntelligence/1.0; GitHubActions)"

_health = {}
_feed_counts = {}


def load_cfg(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).lower()


def stable_dedupe_key(title: str, link: str) -> str:
    normalized_link = normalize(link)

    if normalized_link and normalized_link != "#":
        # Remove common tracking parameters so syndicated copies dedupe better.
        normalized_link = re.sub(
            r"([?&])(utm_[^=&]+|fbclid|gclid)=[^&]*",
            "",
            normalized_link,
        )
        normalized_link = normalized_link.rstrip("?&")
        return normalized_link

    return "title:" + hashlib.sha1(
        normalize(title).encode("utf-8")
    ).hexdigest()


def parse_date(entry) -> datetime:
    for field in ("published", "updated", "created"):
        raw = getattr(entry, field, "")
        if not raw:
            continue

        try:
            parsed = dp.parse(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            pass

    return datetime.now(timezone.utc)


def classify_severity(text: str):
    t = normalize(text)

    critical_terms = [
        "actively exploited",
        "exploited in the wild",
        "mass exploitation",
        "ransomware",
        "wormable",
        "zero-click",
        "supply chain attack",
        "authentication bypass",
        "remote code execution",
        "data breach",
        "stolen data",
        "nation-state",
    ]

    important_terms = [
        "cve-",
        "cve",
        "vulnerability",
        "zero-day",
        "0-day",
        "patch",
        "security update",
        "hotfix",
        "mitigation",
        "outage",
        "service disruption",
        "incident",
        "critical severity",
        "high severity",
        "privilege escalation",
        "data exposure",
    ]

    if any(term in t for term in critical_terms):
        return "🔴", "Critical"

    if any(term in t for term in important_terms):
        return "🟠", "Important"

    return "🔵", "FYI"


def why_this_matters(text: str, kind: str) -> str:
    t = normalize(text)

    if "ransomware" in t:
        return (
            "Why this matters: Elevated ransomware risk — validate backups, "
            "endpoint protection, and recovery readiness."
        )

    if "supply chain" in t:
        return (
            "Why this matters: Supply-chain risk — review third-party access "
            "and affected vendor dependencies."
        )

    if "nation-state" in t or " apt " in f" {t} ":
        return (
            "Why this matters: Advanced threat activity — review privileged "
            "access, persistence detection, and lateral-movement controls."
        )

    if "phish" in t or "credential" in t:
        return (
            "Why this matters: Credential/phishing risk — reinforce MFA and "
            "watch for suspicious sign-ins."
        )

    if "breach" in t or "stolen" in t or "data exposure" in t:
        return (
            "Why this matters: Potential data exposure — review monitoring "
            "and incident-response readiness."
        )

    if "remote code execution" in t or " rce " in f" {t} ":
        return (
            "Why this matters: Remote-code-execution risk — assess exposure "
            "and patch or mitigate quickly."
        )

    if "authentication bypass" in t:
        return (
            "Why this matters: Authentication bypass — review access controls "
            "and look for unauthorized access."
        )

    if "privilege escalation" in t:
        return (
            "Why this matters: Privilege-escalation risk — review local admin "
            "and endpoint controls."
        )

    if "outage" in t or "service disruption" in t or "incident" in t:
        return (
            "Why this matters: Service impact is possible — verify vendor "
            "status before troubleshooting internally."
        )

    if any(
        term in t
        for term in [
            "entra",
            "azure ad",
            "conditional access",
            "mfa",
            "authentication",
            "sso",
        ]
    ):
        return (
            "Why this matters: Could affect sign-ins, MFA, or Conditional "
            "Access — watch for authentication issues."
        )

    if any(term in t for term in ["exchange", "outlook", "mail flow"]):
        return (
            "Why this matters: Could affect email access or mail flow — "
            "monitor delivery and Outlook behavior."
        )

    if any(term in t for term in ["intune", "mdm", "device compliance"]):
        return (
            "Why this matters: Could affect device enrollment or compliance — "
            "watch policy deployment."
        )

    if "defender" in t or "edr" in t:
        return (
            "Why this matters: Endpoint-security changes may affect detection "
            "and alerting."
        )

    if any(
        term in t
        for term in ["sonicwall", "aruba", "adtran", "fortinet", "cisco", "palo alto"]
    ):
        return (
            "Why this matters: Infrastructure/vendor signal — compare your "
            "installed versions and support status."
        )

    if any(term in t for term in ["pricing", "license", "licensing", "renewal"]):
        return (
            "Why this matters: Potential budget or licensing impact — verify "
            "renewal terms and forecast changes."
        )

    if any(term in t for term in ["acquisition", "merger", "layoffs"]):
        return (
            "Why this matters: Vendor-risk signal — consider roadmap, support, "
            "and renewal implications."
        )

    if any(
        term in t
        for term in [
            "compliance",
            "regulation",
            "gdpr",
            "hipaa",
            "pci",
            "nist",
            "ftc",
        ]
    ):
        return (
            "Why this matters: Compliance/regulatory signal — determine "
            "applicability and required action."
        )

    if any(
        term in t
        for term in [
            "pms",
            "pos",
            "point of sale",
            "guest",
            "property management system",
        ]
    ):
        return (
            "Why this matters: Hospitality-system impact — consider guest "
            "services, PMS/POS, and property operations."
        )

    defaults = {
        "urgent": (
            "Why this matters: Potentially urgent issue — confirm whether your "
            "environment is exposed."
        ),
        "security": (
            "Why this matters: Security-relevant development — confirm "
            "exposure and mitigation status."
        ),
        "microsoft": (
            "Why this matters: Microsoft-platform change — assess user, "
            "identity, messaging, or administration impact."
        ),
        "sysadmin": (
            "Why this matters: Operational impact is possible — watch for "
            "changes that generate tickets or outages."
        ),
        "network": (
            "Why this matters: Network/infrastructure development — consider "
            "firmware, configuration, and availability impact."
        ),
        "hospitality": (
            "Why this matters: Hospitality-technology development — consider "
            "property operations and guest-facing systems."
        ),
        "vp": (
            "Why this matters: Leadership context — useful for risk, budget, "
            "vendor, and strategic conversations."
        ),
        "ai": (
            "Why this matters: Enterprise-AI development — consider security, "
            "governance, productivity, and infrastructure implications."
        ),
        "tech": (
            "Why this matters: Developing technology — useful for future "
            "infrastructure and purchasing decisions."
        ),
        "radar": (
            "Why this matters: Early technical signal — worth a quick scan for "
            "issues that may become more important."
        ),
        "vendor": (
            "Why this matters: Vendor advisory — compare affected versions "
            "against your environment."
        ),
        "compliance": (
            "Why this matters: Regulatory/compliance context — assess scope "
            "and action timeline."
        ),
    }

    return defaults.get(
        kind,
        "Why this matters: Useful IT context for operational and leadership awareness.",
    )


def fetch_url_bytes(url: str, timeout_seconds: int = 20):
    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": UA,
                "Accept": (
                    "application/rss+xml, application/atom+xml, "
                    "application/xml, text/xml, */*"
                ),
            },
        )

        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.read(), response.getcode()

    except urllib.error.HTTPError as exc:
        print(f"[WARN] Fetch failed: {url} :: HTTP {exc.code}")
        return None, exc.code

    except Exception as exc:
        print(f"[WARN] Fetch failed: {url} :: {exc}")
        return None, None


def parse_feed(url: str, source_name: str, kind: str):
    data, http_status = fetch_url_bytes(url)
    key = f"{kind}::{source_name}"

    checked = datetime.now(timezone.utc).isoformat()

    if not data:
        _health[key] = {
            "source": source_name,
            "url": url,
            "kind": kind,
            "status": "fetch_failed",
            "http_status": http_status,
            "items": 0,
            "checked": checked,
        }
        return None

    feed = feedparser.parse(data)
    entries = getattr(feed, "entries", [])
    entry_count = len(entries)

    if getattr(feed, "bozo", False):
        print(
            f"[WARN] Parse warning: {url} :: "
            f"{getattr(feed, 'bozo_exception', '')}"
        )

        _health[key] = {
            "source": source_name,
            "url": url,
            "kind": kind,
            "status": "parse_warning",
            "http_status": http_status,
            "items": entry_count,
            "checked": checked,
        }
    else:
        _health[key] = {
            "source": source_name,
            "url": url,
            "kind": kind,
            "status": "ok",
            "http_status": http_status,
            "items": entry_count,
            "checked": checked,
        }

    return feed


def configured_keyword_score(cfg: dict, text: str) -> int:
    """
    YAML keywords are ranking signals, NOT hard filters.
    This prevents categories from becoming empty.
    """
    keywords = cfg.get("keywords") or []

    if not keywords:
        return 0

    t = normalize(text)
    hits = sum(1 for keyword in keywords if normalize(keyword) in t)

    # First matches matter most; cap so generic Microsoft-type words
    # don't overpower truly critical content.
    return min(hits * 12, 60)


def score_item(
    cfg: dict,
    kind: str,
    text: str,
    source_name: str,
    severity_label: str,
) -> int:
    t = normalize(text)
    score = 0

    if severity_label == "Critical":
        score += 100
    elif severity_label == "Important":
        score += 60
    else:
        score += 10

    # Config-specific relevance.
    score += configured_keyword_score(cfg, text)

    signal_weights = {
        "cve": 25,
        "zero-day": 30,
        "0-day": 30,
        "exploited": 35,
        "in the wild": 35,
        "ransomware": 40,
        "breach": 35,
        "remote code execution": 30,
        "authentication bypass": 28,
        "outage": 25,
        "incident": 20,
        "service disruption": 25,
        "supply chain": 30,
        "nation-state": 35,
    }

    for phrase, points in signal_weights.items():
        if phrase in t:
            score += points

    if any(
        term in t
        for term in [
            "microsoft",
            "m365",
            "entra",
            "azure ad",
            "intune",
            "exchange",
            "defender",
            "copilot",
        ]
    ):
        score += 15

    if any(term in t for term in ["sonicwall", "aruba", "adtran"]):
        score += 15

    if kind == "urgent":
        if severity_label == "Critical":
            score += 50
        if any(
            term in t
            for term in [
                "actively exploited",
                "emergency",
                "ransomware",
                "zero-day",
                "remote code execution",
            ]
        ):
            score += 40

    elif kind == "security":
        if any(
            term in t
            for term in [
                "ransomware",
                "cve",
                "vulnerability",
                "zero-day",
                "breach",
                "exploited",
            ]
        ):
            score += 25

    elif kind == "microsoft":
        if any(
            term in t
            for term in [
                "microsoft",
                "m365",
                "entra",
                "exchange",
                "outlook",
                "intune",
                "defender",
                "teams",
                "copilot",
                "azure",
            ]
        ):
            score += 35

    elif kind == "sysadmin":
        if any(
            term in t
            for term in [
                "outage",
                "incident",
                "degradation",
                "patch",
                "update",
                "release",
                "breaking change",
                "deprecation",
                "dns",
                "certificate",
                "vpn",
                "authentication",
                "mail flow",
            ]
        ):
            score += 30

    elif kind == "network":
        if any(
            term in t
            for term in [
                "aruba",
                "sonicwall",
                "adtran",
                "wireless",
                "wifi",
                "wi-fi",
                "switch",
                "router",
                "firewall",
                "network",
                "ethernet",
                "firmware",
            ]
        ):
            score += 35

    elif kind == "hospitality":
        if any(
            term in t
            for term in [
                "hotel",
                "hospitality",
                "pms",
                "pos",
                "guest",
                "property management",
                "digital key",
                "booking",
                "reservation",
                "travel",
            ]
        ):
            score += 35

    elif kind == "vp":
        if any(
            term in t
            for term in [
                "pricing",
                "license",
                "licensing",
                "renewal",
                "contract",
                "acquisition",
                "merger",
                "layoffs",
                "risk",
                "compliance",
                "regulation",
                "strategy",
            ]
        ):
            score += 35

    elif kind == "ai":
        if any(
            term in t
            for term in [
                "artificial intelligence",
                " ai ",
                "copilot",
                "agent",
                "llm",
                "model",
                "gpu",
                "inference",
                "openai",
                "anthropic",
                "gemini",
                "nvidia",
            ]
        ):
            score += 35

    elif kind == "tech":
        if any(
            term in t
            for term in [
                "cpu",
                "gpu",
                "server",
                "storage",
                "processor",
                "chip",
                "semiconductor",
                "ethernet",
                "datacenter",
                "data center",
                "hardware",
            ]
        ):
            score += 30

    elif kind == "vendor":
        if any(
            term in t
            for term in [
                "advisory",
                "psirt",
                "cve",
                "patch",
                "firmware",
                "affected versions",
            ]
        ):
            score += 30

    elif kind == "compliance":
        if any(
            term in t
            for term in [
                "rule",
                "regulation",
                "enforcement",
                "deadline",
                "fine",
                "penalty",
                "compliance",
            ]
        ):
            score += 30

    source = normalize(source_name)

    if "msrc" in source or "microsoft security" in source:
        score += 12

    if "cisa" in source:
        score += 15

    if "sans" in source:
        score += 8

    if "psirt" in source:
        score += 10

    return score


def collect_candidates(cfg: dict, kind: str) -> list:
    """
    Collect ALL available articles first.

    Important: no age filtering and no hard keyword filtering happen here.
    This ensures fallback always has articles available.
    """
    candidates = []
    local_seen = set()

    for source in cfg.get("sources", []) or []:
        url = source.get("url")
        source_name = source.get("name", "Source")

        if not url:
            continue

        feed = parse_feed(url, source_name, kind)

        if not feed:
            continue

        for entry in getattr(feed, "entries", [])[:100]:
            title = (getattr(entry, "title", "") or "").strip() or "(No title)"
            link = (getattr(entry, "link", "") or url).strip()
            summary = (getattr(entry, "summary", "") or "").strip()
            published = parse_date(entry)

            dedupe_key = stable_dedupe_key(title, link)

            if dedupe_key in local_seen:
                continue

            local_seen.add(dedupe_key)

            combined = f"{title} {summary} {source_name}"

            severity_emoji, severity_label = classify_severity(combined)
            why = why_this_matters(combined, kind)
            score = score_item(
                cfg,
                kind,
                combined,
                source_name,
                severity_label,
            )

            candidates.append(
                {
                    "title": f"{severity_emoji} {title}",
                    "link": link,
                    "summary": summary,
                    "source": source_name,
                    "date": published,
                    "severity": severity_label,
                    "why": why,
                    "dedupe_key": dedupe_key,
                    "score": score,
                }
            )

    return candidates


def choose_items(
    kind: str,
    cfg: dict,
    candidates: list,
) -> list:
    max_items = MAX_ITEMS.get(kind, 60)
    min_items = MIN_ITEMS.get(kind, 10)

    max_age_hours = cfg.get(
        "max_age_hours",
        DEFAULT_MAX_AGE_HOURS.get(kind, 168),
    )

    now = datetime.now(timezone.utc)

    # Archive intentionally has no freshness limit.
    if max_age_hours <= 0:
        recent = candidates[:]
    else:
        cutoff = now - timedelta(hours=max_age_hours)
        recent = [
            article
            for article in candidates
            if article["date"] >= cutoff
        ]

    # Prefer relevance, then freshness.
    recent.sort(
        key=lambda article: (
            article["score"],
            article["date"],
        ),
        reverse=True,
    )

    chosen = recent[:max_items]

    # Fallback:
    # If the normal freshness window didn't produce enough items,
    # pull the best older articles from the full candidate pool.
    if len(chosen) < min_items:
        all_ranked = sorted(
            candidates,
            key=lambda article: (
                article["score"],
                article["date"],
            ),
            reverse=True,
        )

        chosen_keys = {
            article["dedupe_key"]
            for article in chosen
        }

        for article in all_ranked:
            if article["dedupe_key"] in chosen_keys:
                continue

            chosen.append(article)
            chosen_keys.add(article["dedupe_key"])

            if len(chosen) >= min_items:
                break

    # Final reading order is newest first.
    chosen.sort(
        key=lambda article: article["date"],
        reverse=True,
    )

    return chosen[:max_items]


def age_label(dt: datetime) -> str:
    delta = datetime.now(timezone.utc) - dt
    hours = max(0, int(delta.total_seconds() / 3600))

    if hours < 1:
        return "<1h"

    if hours < 24:
        return f"{hours}h"

    days = hours // 24
    return f"{days}d"


def write_rss(
    cfg: dict,
    out_path: str,
    items: list,
):
    rss_items = []

    for article in items:
        summary = article["summary"]

        # Avoid enormous RSS descriptions.
        if len(summary) > 1500:
            summary = summary[:1500].rstrip() + "…"

        description = (
            f"<b>{html.escape(article['why'])}</b><br/>"
            + (
                f"{summary}<br/>"
                if summary
                else ""
            )
            + f"<br/><b>Source:</b> {html.escape(article['source'])}"
            + f" &nbsp;|&nbsp; <b>Severity:</b> {html.escape(article['severity'])}"
            + f" &nbsp;|&nbsp; <b>Age:</b> {html.escape(age_label(article['date']))}"
        )

        rss_items.append(
            f"""
<item>
  <title>{html.escape(article['title'])}</title>
  <link>{html.escape(article['link'])}</link>
  <guid isPermaLink="false">{html.escape(article['dedupe_key'])}</guid>
  <pubDate>{format_datetime(article['date'])}</pubDate>
  <source>{html.escape(article['source'])}</source>
  <description><![CDATA[{description}]]></description>
</item>
"""
        )

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


def build_feed(
    cfg: dict,
    out_path: str,
    kind: str,
):
    candidates = collect_candidates(cfg, kind)
    items = choose_items(kind, cfg, candidates)

    _feed_counts[kind] = {
        "category": kind,
        "candidates": len(candidates),
        "published": len(items),
        "output": os.path.basename(out_path),
    }

    if not items:
        print(
            f"[WARN] {kind}: no articles available from any "
            "configured working source."
        )

    write_rss(cfg, out_path, items)


def write_health_report(docs_dir: str):
    feeds = list(_health.values())

    ok = sum(
        1
        for feed in feeds
        if feed["status"] == "ok"
    )

    warnings = sum(
        1
        for feed in feeds
        if feed["status"] == "parse_warning"
    )

    failed = sum(
        1
        for feed in feeds
        if feed["status"] == "fetch_failed"
    )

    total_articles_seen = sum(
        feed.get("items", 0)
        for feed in feeds
    )

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(feeds),
            "ok": ok,
            "parse_warning": warnings,
            "fetch_failed": failed,
            "articles_seen": total_articles_seen,
        },
        "categories": _feed_counts,
        "feeds": feeds,
    }

    output_path = os.path.join(
        docs_dir,
        "feed_health.json",
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            indent=2,
        )

    print(
        f"[HEALTH] {ok} healthy / "
        f"{warnings} warnings / "
        f"{failed} failed / "
        f"{len(feeds)} total"
    )

    for category, data in _feed_counts.items():
        print(
            f"[COUNT] {category}: "
            f"{data['published']} published "
            f"from {data['candidates']} candidates"
        )

    if failed:
        failed_sources = [
            feed["source"]
            for feed in feeds
            if feed["status"] == "fetch_failed"
        ]

        print(
            "[HEALTH] Failed sources: "
            + ", ".join(failed_sources)
        )


def main():
    docs_dir = os.path.join(ROOT, "docs")
    os.makedirs(docs_dir, exist_ok=True)

    for cfg_name, out_name, kind in CONFIGS:
        cfg_path = os.path.join(
            ROOT,
            cfg_name,
        )

        if not os.path.exists(cfg_path):
            print(
                f"[SKIP] {cfg_name} not found"
            )
            continue

        try:
            cfg = load_cfg(cfg_path)
        except Exception as exc:
            print(
                f"[ERROR] Could not parse "
                f"{cfg_name}: {exc}"
            )
            continue

        out_path = os.path.join(
            docs_dir,
            out_name,
        )

        print(
            f"[BUILD] {cfg_name} → {out_name}"
        )

        try:
            build_feed(
                cfg,
                out_path,
                kind,
            )
        except Exception as exc:
            # One category should never kill the entire dashboard build.
            print(
                f"[ERROR] Failed building "
                f"{kind}: {exc}"
            )

    write_health_report(docs_dir)


if __name__ == "__main__":
    main()
