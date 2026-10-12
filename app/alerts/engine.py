"""알람 규칙 평가.

수집기가 돌 때마다 최근 데이터를 훑어 알람 후보를 만들고, dedup_key로 중복을 막는다.
같은 사건을 여러 매체가 보도한 경우 제목 유사도로 기존 알람에 묶는다(Slack 재전송 없음).
"""
import json
import logging
import math
import re
import threading
from collections import Counter
from datetime import datetime, timedelta

from flask import current_app

from ..cve_queries import mention_index
from ..extensions import db
from ..models import Alert, Article, Cve, KevEntry, RansomVictim, Source

log = logging.getLogger(__name__)

SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}

VICTIM_LOOKBACK = timedelta(days=30)
ARTICLE_LOOKBACK = timedelta(days=7)
KEV_LOOKBACK = timedelta(days=30)
MERGE_WINDOW = timedelta(hours=48)

# 국내 기사 중 실제 침해 사고로 보이는 제목 (대시보드 전용 medium)
KR_INCIDENT_RE = re.compile(
    r"랜섬웨어\s*(?:감염|피해)|해킹\s*(?:피해|사고)|개인정보\s*(?:유출|침해)|"
    r"정보\s*유출|침해\s*사고|뚫렸다|디도스\s*공격|DDoS\s*공격"
)
# 행사·제품 홍보·칼럼은 제외
KR_INCIDENT_EXCLUDE_RE = re.compile(
    r"모집|대회|세미나|컨퍼런스|웨비나|교육|출시|솔루션|가이드|탐지\s*가능|공략|"
    r"\[[^\]]*(?:칼럼|기고|보안 빅데이터|논하다)[^\]]*\]"
)

_lock = threading.Lock()
_WORD_RE = re.compile(r"[0-9A-Za-z가-힣]+")
_STOP = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "with", "by", "as", "at", "from",
    "is", "are", "new", "via", "used", "uses", "after", "over", "that", "could", "lets", "its",
    # 보안 기사에 흔한 일반어 — 이것만 겹치는 서로 다른 기사가 묶이지 않도록 제외
    "critical", "flaw", "flaws", "bug", "bugs", "vulnerability", "vulnerabilities", "unpatched",
    "patch", "patches", "patched", "attack", "attacks", "attackers", "hackers", "hacker", "hacking",
    "exploit", "exploits", "exploited", "unauthenticated", "authenticated", "warns", "security",
    "cyber", "cyberattack", "cyberattacks", "malware", "data", "breach", "korea", "korean", "south",
    "north", "취약점", "공격", "해킹", "보안", "패치", "긴급", "발표", "단독",
}


def _words(text):
    return [w.lower() for w in _WORD_RE.findall(text or "") if len(w) > 1 and w.lower() not in _STOP]


class EventMatcher:
    """같은 사건 보도인지 판정. 최근 기사 전체로 IDF를 계산해 아래 중 하나면 같은 사건:

    1. 제목+요약 TF-IDF 코사인 유사도 ≥ COSINE_THRESHOLD
       (실제 기사로 검증: 같은 사건 0.26~0.6, 다른 사건 ≤ 0.24)
    2. 같은 CVE 언급
    3. 최근 기사 제목 중 RARE_DF건 이하에만 나오는 브랜드형 고유명사를 공유
       — 첫 글자 이후에도 대문자가 있는 단어만 (ARTEX, NetScaler, ShinyHunters, AhsayCBS)
       ※ 일반 단어까지 허용하면 무관한 기사가 대량으로 묶여 제외함
    """

    COSINE_THRESHOLD = 0.25
    RARE_DF = 3

    _BRAND_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*")

    def __init__(self, docs):
        self.n = len(docs)
        self.df = Counter(t for title, summary in docs for t in set(_words(title) + _words(summary)))
        self.title_df = Counter(t for title, _ in docs for t in set(_words(title)))

    def _vec(self, title, summary):
        tf = Counter(_words(title) * 2 + _words(summary))  # 제목 2배 가중
        v = {t: n * (math.log((self.n + 1) / (self.df.get(t, 0) + 1)) + 1) for t, n in tf.items()}
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {t: x / norm for t, x in v.items()}

    def cosine(self, a, b):
        va, vb = self._vec(*a), self._vec(*b)
        return sum(x * vb.get(t, 0.0) for t, x in va.items())

    def _brands(self, title):
        return {w.lower() for w in self._BRAND_RE.findall(title or "")
                if len(w) >= 4 and w.lower() not in _STOP and not w.isdigit()}

    def rare_shared(self, title_a, title_b):
        shared = self._brands(title_a) & self._brands(title_b)
        return {t for t in shared if self.title_df.get(t, 0) <= self.RARE_DF}

    def same_event(self, cand, other):
        if cand["_cves"] & other["_cves"]:
            return "CVE"
        if self.rare_shared(cand["title"], other["title"]):
            return "고유명사"
        if self.cosine((cand["title"], cand.get("summary")), (other["title"], other.get("summary")))                 >= self.COSINE_THRESHOLD:
            return "유사도"
        return None


# ---------------------------------------------------------------- 후보 생성
def _victim_candidates(now):
    rows = RansomVictim.query.filter(
        RansomVictim.is_korea.is_(True), RansomVictim.discovered >= now - VICTIM_LOOKBACK
    )
    for v in rows:
        yield {
            "dedup_key": f"rv:{v.uid}",
            "kind": "ransomware",
            "severity": "critical",
            "title": f"한국 기업 랜섬웨어 피해 등록: {v.victim}",
            "summary": (v.description or "")[:400] or None,
            "url": v.rl_url,
            "internal_url": "/ransomware",
            "fields": [["그룹", v.group], ["도메인", v.domain or "-"], ["업종", v.activity or "-"],
                       ["판정 근거", ", ".join(v.match_list)]],
            "event_at": v.discovered,
        }


def _article_candidates(now):
    rows = (
        Article.query.join(Source)
        .filter(Article.published_at >= now - ARTICLE_LOOKBACK)
        .order_by(Article.published_at.asc())
    )
    for a in rows:
        base = {
            "dedup_key": f"art:{a.url_hash}",
            "title": a.title,
            "summary": (a.summary or "")[:400] or None,
            "url": a.url,
            "internal_url": None,
            "event_at": a.published_at,
            "_source": a.source.name,
            "_cves": set(a.cve_list),
        }
        if a.is_korea:
            yield {**base, "kind": "korea_news", "severity": "high",
                   "fields": [["출처", a.source.name], ["한국 관련 근거", ", ".join(a.match_list)],
                              ["CVE", ", ".join(a.cve_list) or "-"]]}
        elif a.is_nk_threat:
            yield {**base, "kind": "nk_threat", "severity": "high",
                   "fields": [["출처", a.source.name], ["위협 행위자", ", ".join(a.match_list)],
                              ["CVE", ", ".join(a.cve_list) or "-"]]}
        elif (a.source.region == "KR" and KR_INCIDENT_RE.search(a.title)
              and not KR_INCIDENT_EXCLUDE_RE.search(a.title)):
            yield {**base, "kind": "kr_incident", "severity": "medium",
                   "fields": [["출처", a.source.name]]}


def _cve_fields(c, kev):
    products = ", ".join(f"{p['vendor']} {p['product']}".strip() for p in c.affected_list[:3]) if c else ""
    fields = []
    if c and c.cvss_score is not None:
        fields.append(["CVSS", f"{c.cvss_score:.1f} {(c.cvss_severity or '').title()}"])
    if c and c.epss is not None:
        fields.append(["EPSS", f"{c.epss * 100:.2f}%"])
    if kev:
        fields.append(["KEV 등재", str(kev.date_added)])
        fields.append(["랜섬웨어 사용", "확인" if kev.ransomware_use == "Known" else "미확인"])
    fields.append(["영향 제품", products or (f"{kev.vendor} {kev.product}" if kev else "-")])
    return fields


def _cve_candidates(now):
    idx = mention_index()
    kev_map = {k.cve_id: k for k in KevEntry.query.filter(KevEntry.cve_id.in_(list(idx)))}

    for c in Cve.query.filter(Cve.cve_id.in_(list(idx))):
        last_mention = idx[c.cve_id]["last"]
        kev = kev_map.get(c.cve_id)
        if c.in_kev:
            kr = f" · 한국 제조사({c.korea_vendor})" if c.korea_vendor else ""
            yield {
                "dedup_key": f"cve-kev:{c.cve_id}",
                "kind": "kev",
                "severity": "critical" if c.korea_vendor else "high",
                "title": f"실제 악용 중인 취약점 뉴스 언급: {c.cve_id}{kr}",
                "summary": (kev.name if kev else None) or (c.description or "")[:300],
                "url": f"https://nvd.nist.gov/vuln/detail/{c.cve_id}",
                "internal_url": f"/cve/{c.cve_id}",
                "fields": _cve_fields(c, kev),
                "event_at": last_mention,
            }
        elif (c.cvss_score or 0) >= 9.0:
            yield {
                "dedup_key": f"cve-crit:{c.cve_id}",
                "kind": "cve_critical",
                "severity": "medium",
                "title": f"Critical CVE 뉴스 언급: {c.cve_id}",
                "summary": (c.description or "")[:300] or None,
                "url": f"https://nvd.nist.gov/vuln/detail/{c.cve_id}",
                "internal_url": f"/cve/{c.cve_id}",
                "fields": _cve_fields(c, None),
                "event_at": last_mention,
            }

    # 뉴스 언급과 무관하게, 한국 제조사 제품이 KEV에 새로 등재되면 Critical
    since = (now - KEV_LOOKBACK).date()
    for k in KevEntry.query.filter(KevEntry.korea_vendor.isnot(None), KevEntry.date_added >= since):
        c = db.session.get(Cve, k.cve_id)
        yield {
            "dedup_key": f"cve-kev:{k.cve_id}",
            "kind": "kev",
            "severity": "critical",
            "title": f"한국 제조사 제품 KEV 등재: {k.cve_id} · {k.vendor} {k.product}",
            "summary": k.name,
            "url": f"https://nvd.nist.gov/vuln/detail/{k.cve_id}",
            "internal_url": f"/cve/{k.cve_id}",
            "fields": _cve_fields(c, k),
            "event_at": datetime.combine(k.date_added, datetime.min.time()),
        }


# ---------------------------------------------------------------- 저장
def _slack_decision(cand, now):
    cfg = current_app.config
    if not cfg["SLACK_WEBHOOK_URL"]:
        return "skipped", "Slack 미설정"
    if SEVERITY_RANK[cand["severity"]] < SEVERITY_RANK.get(cfg["ALERT_SLACK_MIN_SEVERITY"], 2):
        return "skipped", "대시보드 전용 등급"
    max_age = timedelta(hours=cfg["ALERT_MAX_AGE_HOURS"])
    if cand.get("event_at") and now - cand["event_at"] > max_age:
        return "skipped", f"오래된 항목({cfg['ALERT_MAX_AGE_HOURS']}시간 경과)"
    return "pending", None


def _try_merge(cand, now, matcher):
    """비슷한 제목의 최근 뉴스 알람이 있으면 거기에 묶고 True."""
    if cand["kind"] not in ("korea_news", "nk_threat", "kr_incident"):
        return False
    recent = Alert.query.filter(
        Alert.kind == cand["kind"], Alert.created_at >= now - MERGE_WINDOW
    ).all()
    for alert in recent:
        related = alert.related_list
        if alert.url == cand["url"] or any(r["url"] == cand["url"] for r in related):
            return True  # 이미 묶임
        cve_field = dict(alert.field_list).get("CVE", "-")
        others = [{"title": alert.title, "summary": alert.summary,
                   "_cves": set() if cve_field == "-" else set(cve_field.split(", "))}]
        others += [{"title": r["title"], "summary": None, "_cves": set()} for r in related]
        reason = next((r for r in (matcher.same_event(cand, o) for o in others) if r), None)
        if reason:
            related.append({"title": cand["title"], "url": cand["url"], "source": cand.get("_source")})
            alert.related = json.dumps(related, ensure_ascii=False)
            log.info("알람 묶음(%s): '%s' → #%d", reason, cand["title"][:60], alert.id)
            return True
    return False


def evaluate():
    now = datetime.utcnow()
    existing = {k for (k,) in db.session.query(Alert.dedup_key)}
    docs = db.session.query(Article.title, Article.summary).filter(
        Article.published_at >= now - ARTICLE_LOOKBACK).all()
    matcher = EventMatcher(docs)
    created = []
    for gen in (_victim_candidates, _cve_candidates, _article_candidates):
        for cand in gen(now):
            if cand["dedup_key"] in existing:
                continue
            if _try_merge(cand, now, matcher):
                db.session.flush()
                continue
            status, reason = _slack_decision(cand, now)
            alert = Alert(
                dedup_key=cand["dedup_key"],
                kind=cand["kind"],
                severity=cand["severity"],
                title=cand["title"][:500],
                summary=cand.get("summary"),
                url=cand.get("url"),
                internal_url=cand.get("internal_url"),
                fields=json.dumps(cand.get("fields") or [], ensure_ascii=False),
                event_at=cand.get("event_at"),
                slack_status=status,
                slack_reason=reason,
            )
            db.session.add(alert)
            db.session.flush()
            existing.add(cand["dedup_key"])
            created.append(alert)
    db.session.commit()
    return created


def run():
    """평가 + Slack 전송. 여러 수집기 스레드에서 호출되므로 직렬화."""
    from .slack import send_pending

    if not _lock.acquire(blocking=False):
        return {"skipped": True}
    try:
        created = evaluate()
        sent = send_pending()
        result = {"created": len(created), **sent}
        if created or sent.get("sent") or sent.get("failed"):
            log.info("알람: %s", result)
        return result
    finally:
        _lock.release()
