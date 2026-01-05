import feedparser
import yaml
import hashlib
import html
import os
from datetime import datetime, timezone
from email.utils import format_datetime
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))

CONFIGS = [
    ("feeds-security.yaml", "security.xml"),
    ("feeds-sysadmin.yaml", "sysadmin.xml"),
    ("feeds-vp.yaml", "vp.xml"),
]

def load_cfg(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def keyword_match(cfg, text):
    if not cfg.get("keyword_filter_enabled", False):
        return True
    t = (text or "").lower()
    return any(k.lower() in t for k in (cfg.get("keywords") or []))

def build_one(cfg, out_path):
    items = []
    seen = set()

    for source in cfg.get("sources", []):
        feed = feedparser.parse(source["url"])
        for entry in feed.entries[:40]:
            title = getattr(entry, "title", "").strip() or "(No title)"
            link = getattr(entry, "link", source["url"]).strip()
            summary = getattr(entry, "summary", "").strip()

            combined = f"{title} {summary} {source.get('name','')}"
            if not keyword_match(cfg, combined):
                continue

            uid = hashlib.sha1((title + link).encode("utf-8")).hexdigest()
            if uid in seen:
                continue
            seen.add(uid)

            try:
                published = dp.parse(getattr(entry, "published", "")).astimezone(timezone.utc)
            except Exception:
                published = datetime.now(timezone.utc)

            items.append({
                "title": title,
                "link": link,
                "summary": summary,
                "source": source.get("name", "Source"),
                "date": published,
            })

    items.sort(key=lambda x: x["date"], reverse=True)
    items = items[:200]

    rss_items = []
    for it in items:
        rss_items.append(f"""
<item>
  <title>{html.escape(it['title'])}</title>
  <link>{it['link']}</link>
  <pubDate>{format_datetime(it['date'])}</pubDate>
  <description><![CDATA[{it['summary']}<br/><b>Source:</b> {it['source']}]]></description>
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
    for cfg_name, out_name in CONFIGS:
        cfg_path = os.path.join(ROOT, cfg_name)
        out_path = os.path.join(docs_dir, out_name)
        cfg = load_cfg(cfg_path)
        build_one(cfg, out_path)

if __name__ == "__main__":
    main()
