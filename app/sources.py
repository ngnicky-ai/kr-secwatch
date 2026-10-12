from .extensions import db
from .models import Source

# 2026-10-12 기준 응답 확인한 피드
DEFAULT_SOURCES = [
    {
        "key": "boannews",
        "name": "보안뉴스",
        "url": "https://cdn.boannews.com/rss/gn_rss_allArticle.xml",
        "region": "KR",
    },
    {
        "key": "dailysecu",
        "name": "데일리시큐",
        "url": "https://www.dailysecu.com/rss/allArticle.xml",
        "region": "KR",
    },
    {
        "key": "bleepingcomputer",
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "region": "INTL",
    },
    {
        "key": "thehackernews",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "region": "INTL",
    },
]


def seed_sources():
    existing = {s.key for s in Source.query.all()}
    for s in DEFAULT_SOURCES:
        if s["key"] not in existing:
            db.session.add(Source(**s))
    db.session.commit()
