from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import or_

from .models import Article, Source


def kst_today_start_utc():
    now_kst = datetime.utcnow() + timedelta(hours=9)
    return now_kst.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(hours=9)


def filter_articles(args):
    """뉴스 피드 필터. args: request.args 형태의 dict."""
    q = Article.query.join(Source)
    region = args.get("region")
    if region in ("KR", "INTL"):
        q = q.filter(Source.region == region)
    if args.get("source"):
        q = q.filter(Source.key == args["source"])
    tag = args.get("tag")
    if tag == "korea":
        q = q.filter(Article.is_korea.is_(True))
    elif tag == "nk":
        q = q.filter(Article.is_nk_threat.is_(True))
    elif tag == "cve":
        q = q.filter(Article.cves.isnot(None))
    if args.get("q"):
        like = f"%{args['q'].strip()}%"
        q = q.filter(or_(Article.title.ilike(like), Article.summary.ilike(like)))
    return q.order_by(Article.published_at.desc())


def dashboard_stats(days=14):
    since_7d = datetime.utcnow() - timedelta(days=7)
    today = kst_today_start_utc()

    recent = (
        Article.query.join(Source)
        .filter(Article.published_at >= today - timedelta(days=days - 1))
        .with_entities(Article.published_at, Source.region, Article.cves,
                       Article.is_korea, Article.is_nk_threat)
        .all()
    )

    # 최근 N일 일자별 국내/해외 건수 (KST 기준)
    labels = [(today + timedelta(hours=9) - timedelta(days=i)).strftime("%m-%d")
              for i in reversed(range(days))]
    daily = {l: {"KR": 0, "INTL": 0, "korea": 0, "nk": 0, "cve": 0} for l in labels}
    cve_counter = Counter()
    korea_7d = nk_7d = today_count = 0
    for published_at, region, cves, is_korea, is_nk in recent:
        label = (published_at + timedelta(hours=9)).strftime("%m-%d")
        if label in daily:
            d = daily[label]
            d[region] += 1
            d["korea"] += is_korea
            d["nk"] += is_nk
            d["cve"] += bool(cves)
        if published_at >= today:
            today_count += 1
        if published_at >= since_7d:
            korea_7d += is_korea
            nk_7d += is_nk
            if cves:
                cve_counter.update(cves.split(","))

    sources = Source.query.order_by(Source.region, Source.name).all()
    source_counts = {
        s.key: s.articles.filter(Article.published_at >= since_7d).count() for s in sources
    }
    last_fetch = max((s.last_fetched_at for s in sources if s.last_fetched_at), default=None)

    return {
        "today_count": today_count,
        "korea_7d": korea_7d,
        "nk_7d": nk_7d,
        "cve_7d": len(cve_counter),
        "total": Article.query.count(),
        "trend": {
            "labels": labels,
            "kr": [daily[l]["KR"] for l in labels],
            "intl": [daily[l]["INTL"] for l in labels],
        },
        # 숫자 카드 추이선용 최근 12일 일별 값
        "spark": {
            "labels": labels[-12:],
            "total": [daily[l]["KR"] + daily[l]["INTL"] for l in labels[-12:]],
            "korea": [daily[l]["korea"] for l in labels[-12:]],
            "nk": [daily[l]["nk"] for l in labels[-12:]],
            "cve": [daily[l]["cve"] for l in labels[-12:]],
        },
        "top_cves": cve_counter.most_common(8),
        "sources": sources,
        "source_counts": source_counts,
        "last_fetch": last_fetch,
    }


def situation_24h():
    """대시보드 상단 '최근 24시간 상황' 띠."""
    from .models import Alert

    since = datetime.utcnow() - timedelta(hours=24)
    rows = (
        Alert.query.filter(Alert.event_at >= since, Alert.status != "ignored")
        .order_by(Alert.event_at.desc())
        .all()
    )
    counts = Counter(a.severity for a in rows)
    top = next((a for a in rows if a.severity == "critical"), None) or next(
        (a for a in rows if a.severity == "high"), None)
    if counts["critical"]:
        level = ("critical", "긴급 대응 필요")
    elif counts["high"]:
        level = ("high", "주의 관찰")
    else:
        level = ("ok", "특이사항 없음")
    return {"level": level, "counts": counts, "top": top}
