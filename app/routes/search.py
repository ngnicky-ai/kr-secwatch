"""⌘K 통합 검색: 메뉴·CVE·기사·랜섬웨어 피해·알람."""
import re

from flask import Blueprint, jsonify, request, url_for
from sqlalchemy import or_

from ..models import Alert, Article, Cve, RansomVictim

bp = Blueprint("search", __name__)

CVE_RE = re.compile(r"^\s*(?:cve-)?(\d{4})-(\d{4,7})\s*$", re.IGNORECASE)
LIMIT = 5

PAGES = [
    ("대시보드", "dashboard.index", "dashboard home 홈"),
    ("뉴스", "dashboard.news", "news 기사 피드 rss"),
    ("랜섬웨어", "dashboard.ransomware", "ransomware 피해 victim"),
    ("CVE 취약점", "dashboard.cves", "cve 취약점 kev epss nvd"),
    ("알람", "alerts.index", "alerts alarm 알림 slack"),
]


def _item(group, title, url, sub=None, badge=None, external=False):
    return {"group": group, "title": title, "url": url, "sub": sub, "badge": badge, "external": external}


@bp.get("/api/search")
def search():
    q = (request.args.get("q") or "").strip()
    items = []

    m = CVE_RE.match(q)
    if m:
        cid = f"CVE-{m.group(1)}-{m.group(2)}"
        items.append(_item("바로가기", f"{cid} 상세 보기", url_for("dashboard.cve_detail", cve_id=cid),
                           "NVD·KEV·EPSS 즉시 조회"))

    ql = q.lower()
    for title, endpoint, keywords in PAGES:
        if not q or ql in title.lower() or ql in keywords:
            items.append(_item("메뉴", title, url_for(endpoint)))

    if not q:
        # 검색어가 없으면 미확인 Critical·High 알람
        for a in (Alert.query.filter(Alert.status == "new", Alert.severity.in_(("critical", "high")))
                  .order_by(Alert.event_at.desc()).limit(LIMIT)):
            items.append(_item("미확인 알람", a.title, a.internal_url or a.url or url_for("alerts.index"),
                               badge=a.severity, external=not a.internal_url and bool(a.url)))
        return jsonify(items)

    if len(q) < 2:
        return jsonify(items)
    like = f"%{q}%"

    for c in (Cve.query.filter(or_(Cve.cve_id.ilike(like), Cve.description.ilike(like), Cve.affected.ilike(like)))
              .order_by(Cve.in_kev.desc(), Cve.cvss_score.desc().nullslast()).limit(LIMIT)):
        badge = "kev" if c.in_kev else None
        sub = f"CVSS {c.cvss_score:.1f}" if c.cvss_score is not None else None
        items.append(_item("CVE", c.cve_id, url_for("dashboard.cve_detail", cve_id=c.cve_id), sub, badge))

    for v in (RansomVictim.query.filter(RansomVictim.is_korea.is_(True),
                                        or_(RansomVictim.victim.ilike(like), RansomVictim.domain.ilike(like),
                                            RansomVictim.group.ilike(like)))
              .order_by(RansomVictim.discovered.desc()).limit(LIMIT)):
        when = v.discovered.strftime("%Y-%m-%d") if v.discovered else ""
        items.append(_item("한국 랜섬웨어 피해", v.victim, v.rl_url, f"{v.group} · {when}", external=True))

    for a in (Alert.query.filter(Alert.title.ilike(like)).order_by(Alert.event_at.desc()).limit(LIMIT)):
        items.append(_item("알람", a.title, a.internal_url or a.url or url_for("alerts.index"),
                           badge=a.severity, external=not a.internal_url and bool(a.url)))

    for art in (Article.query.filter(or_(Article.title.ilike(like), Article.summary.ilike(like)))
                .order_by(Article.published_at.desc()).limit(LIMIT + 3)):
        items.append(_item("뉴스", art.title, art.url, art.source.name, external=True))

    return jsonify(items)
