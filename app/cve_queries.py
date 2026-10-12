from collections import defaultdict
from datetime import date, timedelta

from sqlalchemy import or_

from .extensions import db
from .models import Article, Cve, KevEntry


def mention_index():
    """CVE별 기사 언급 수·최근 언급 시각."""
    idx = defaultdict(lambda: {"count": 0, "last": None})
    rows = db.session.query(Article.cves, Article.published_at).filter(Article.cves.isnot(None))
    for cves, published_at in rows:
        for cid in cves.split(","):
            m = idx[cid]
            m["count"] += 1
            if published_at and (m["last"] is None or published_at > m["last"]):
                m["last"] = published_at
    return idx


def cve_list(args):
    q = Cve.query
    tag = args.get("tag")
    if tag == "kev":
        q = q.filter(Cve.in_kev.is_(True))
    elif tag == "critical":
        q = q.filter(or_(Cve.in_kev.is_(True), Cve.cvss_score >= 9.0, Cve.epss >= 0.1))
    elif tag == "korea":
        q = q.filter(Cve.korea_vendor.isnot(None))
    if args.get("q"):
        like = f"%{args['q'].strip()}%"
        q = q.filter(or_(Cve.cve_id.ilike(like), Cve.description.ilike(like), Cve.affected.ilike(like)))

    idx = mention_index()
    # 상세 페이지 직접 조회로 생긴 CVE는 제외하고 기사에 언급된 것만
    rows = [c for c in q.all() if c.cve_id in idx]
    sort = args.get("sort", "priority")
    if sort == "recent":
        rows.sort(key=lambda c: idx[c.cve_id]["last"] or c.first_seen_at, reverse=True)
    elif sort == "epss":
        rows.sort(key=lambda c: c.epss or -1, reverse=True)
    else:  # 우선순위 → CVSS → EPSS
        rows.sort(key=lambda c: (c.priority[0] if c.priority[0] != "p0" else "p9",
                                 -(c.cvss_score or 0), -(c.epss or 0)))
    return rows, idx


def cve_stats():
    mentioned = Cve.query.filter(Cve.cve_id.in_(list(mention_index())))
    tracked = mentioned.count()
    kev_recent = (
        KevEntry.query.filter(KevEntry.date_added >= date.today() - timedelta(days=30))
        .order_by(KevEntry.date_added.desc())
        .all()
    )
    return {
        "tracked": tracked,
        "kev": mentioned.filter(Cve.in_kev.is_(True)).count(),
        "critical": mentioned.filter(Cve.cvss_score >= 9.0).count(),
        "korea": mentioned.filter(Cve.korea_vendor.isnot(None)).count(),
        "kev_total": KevEntry.query.count(),
        "kev_recent": kev_recent,
        "kev_korea": KevEntry.query.filter(KevEntry.korea_vendor.isnot(None))
        .order_by(KevEntry.date_added.desc()).all(),
    }


def related_articles(cve_id, limit=30):
    pattern = f"%,{cve_id},%"
    return (
        Article.query.filter(("," + Article.cves + ",").like(pattern))
        .order_by(Article.published_at.desc())
        .limit(limit)
        .all()
    )


def cves_by_id(ids):
    if not ids:
        return {}
    return {c.cve_id: c for c in Cve.query.filter(Cve.cve_id.in_(list(ids)))}
