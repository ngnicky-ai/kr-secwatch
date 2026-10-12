import calendar
import hashlib
import html
import logging
import re
import threading
from datetime import datetime, timedelta

import feedparser
import httpx
from flask import current_app

from ..analyzers import korea
from ..analyzers.cve import extract_cves
from ..extensions import db
from ..models import Article, Source

log = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_lock = threading.Lock()  # 스케줄러와 수동 수집이 겹치지 않도록


def clean_text(raw, limit=None):
    text = _WS_RE.sub(" ", html.unescape(_TAG_RE.sub(" ", raw or ""))).strip()
    if limit and len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def url_hash(url):
    return hashlib.sha256(url.strip().encode()).hexdigest()


_TZ_SUFFIX_RE = re.compile(r"(?:[+-]\d{2}:?\d{2}|Z|GMT|UTC|[A-Z]{3,4})\s*$")


def parse_date(entry, region):
    st = entry.get("published_parsed") or entry.get("updated_parsed")
    if not st:
        return None
    # feedparser는 UTC struct_time을 반환하지만, 시간대 없는 값("2026-10-12 17:06:08")은
    # 그대로 UTC로 취급함 → 국내 소스(데일리시큐 등)는 KST로 보정
    dt = datetime.utcfromtimestamp(calendar.timegm(st))
    raw = (entry.get("published") or entry.get("updated") or "").strip()
    if region == "KR" and raw and not _TZ_SUFFIX_RE.search(raw):
        dt -= timedelta(hours=9)
    return min(dt, datetime.utcnow())  # 미래 시각 방지


def fetch_source(source):
    """한 소스를 수집해 새로 저장한 기사 수를 반환."""
    cfg = current_app.config
    # 일시적인 연결 끊김(데일리시큐에서 간헐적 SSL EOF 확인)에 대비해 1회 재시도
    transport = httpx.HTTPTransport(retries=1)
    with httpx.Client(transport=transport, timeout=cfg["HTTP_TIMEOUT"], follow_redirects=True,
                      headers={"User-Agent": cfg["USER_AGENT"]}) as client:
        resp = client.get(source.url)
    resp.raise_for_status()
    feed = feedparser.parse(resp.content)
    if feed.bozo and not feed.entries:
        raise ValueError(f"피드 파싱 실패: {feed.bozo_exception}")

    new = 0
    for entry in feed.entries:
        link = entry.get("link")
        title = clean_text(entry.get("title"))
        if not link or not title:
            continue
        h = url_hash(link)
        if db.session.query(Article.id).filter_by(url_hash=h).first():
            continue

        summary = clean_text(entry.get("summary") or entry.get("description"), limit=600)
        full_text = f"{title}\n{summary}"
        kr = korea.analyze(full_text, source.region, cfg["KOREA_SCORE_THRESHOLD"])
        cves = extract_cves(full_text)

        db.session.add(
            Article(
                source=source,
                url_hash=h,
                url=link,
                title=title[:500],
                summary=summary,
                author=clean_text(entry.get("author"))[:200] or None,
                published_at=parse_date(entry, source.region) or datetime.utcnow(),
                korea_score=kr.score,
                is_korea=kr.is_korea,
                is_nk_threat=kr.is_nk_threat,
                korea_matches=",".join(kr.matches)[:500] or None,
                cves=",".join(cves)[:500] or None,
            )
        )
        new += 1
    return new


def collect_all():
    """활성화된 모든 RSS 소스 수집. {source_key: 신규건수 or 'error'} 반환."""
    if not _lock.acquire(blocking=False):
        log.info("이미 수집 중이라 건너뜀")
        return {"skipped": True}
    results = {}
    try:
        for source in Source.query.filter_by(enabled=True).all():
            try:
                n = fetch_source(source)
                source.last_status = "ok"
                source.last_error = None
                source.last_new_count = n
                results[source.key] = n
            except Exception as e:  # 한 소스 실패가 전체 수집을 막지 않도록
                db.session.rollback()
                source = db.session.get(Source, source.id)
                source.last_status = "error"
                source.last_error = str(e)[:1000]
                source.last_new_count = 0
                results[source.key] = "error"
                log.warning("수집 실패 %s: %s", source.key, e)
            source.last_fetched_at = datetime.utcnow()
            db.session.commit()
    finally:
        _lock.release()
    log.info("RSS 수집 완료: %s", results)
    return results
