import feedparser
import yaml
import hashlib
import html
import os
from datetime import datetime, timezone
from email.utils import format_datetime
from dateutil import parser as dp

ROOT = os.path.dirname(os.path.dirname(__file__))
OUT_FILE = os.path.join(ROOT, "docs", "rss.xml")

with open(os.path.join(ROOT, "feeds.yaml"), "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

def keyword_match(text):
    if not cfg.get("keyword_filter_enabled", False):
        return True
    text = text.lower()
    return any(k.lower() in text for k in cfg.get("keywords", []))

items = []
seen = set()

for source in cfg.get("sources", []):
    feed = feedparser.parse(source["url"])
    for entry in feed.entries[:30]:
        title = getattr(entry, "title", "").strip()
        link = getattr(entry, "link", source["url"]).strip()
        summary = getattr(entry, "summary", "").strip()

        combined = f"{title} {summary}"
        if not keyword_match(combined):
            continue

        uid = hashlib.sha1((title + link).encode("utf-8")).hexdigest()
        if uid in seen:
            continue
        seen.add(uid)

        try:
            published = dp.parse(entry.published).astimezone(timezone.utc)
        except Exception:
            published = datetime.now(timezone.utc)

        items.append({
            "title": title,
            "link": link,
            "summary": summary,
            "source": source["name"],
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
  <title>{cfg['title']}</title>
  <description>{cfg['description']}</description>
  <lastBuildDate>{format_datetime(datetime.now(timezone.utc))}</lastBuildDate>
  {''.join(rss_items)}
</channel>
</rss>
"""

os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.write(rss)
