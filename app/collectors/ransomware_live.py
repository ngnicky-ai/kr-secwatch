"""ransomware.live 공개 API 수집기.

- 공개 API는 IP당 '1 per 1 minute' 제한 → 모든 호출을 RateLimiter로 직렬화(61초 간격)
- 유출 사이트(.onion) 주소(claim_url)와 스크린샷은 저장하지 않음
"""
import base64
import hashlib
import logging
import threading
import time
from datetime import datetime, timezone

import httpx
from flask import current_app

from ..analyzers.korea import analyze_victim
from ..extensions import db
from ..models import CollectorState, RansomVictim

log = logging.getLogger(__name__)

API_BASE = "https://api.ransomware.live/v2"
MIN_INTERVAL = 61  # 초


class RateLimitError(Exception):
    pass


class _RateLimiter:
    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.last = 0.0

    def __enter__(self):
        self.lock.acquire()
        wait = self.last + self.interval - time.monotonic()
        if wait > 0:
            log.info("ransomware.live 호출 대기 %.0f초", wait)
            time.sleep(wait)

    def __exit__(self, *exc):
        self.last = time.monotonic()
        self.lock.release()


_limiter = _RateLimiter(MIN_INTERVAL)


def api_get(path):
    cfg = current_app.config
    with _limiter:
        resp = httpx.get(
            f"{API_BASE}{path}",
            headers={"User-Agent": cfg["USER_AGENT"], "Accept": "application/json"},
            timeout=60,
        )
    resp.raise_for_status()
    data = resp.json()
    # 제한 초과 시에도 200 + {"message": "1 per 1 minute"} 로 응답함
    if isinstance(data, dict) and "message" in data:
        raise RateLimitError(data["message"])
    return data


def parse_dt(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def victim_uid(group, victim):
    key = f"{(group or '').strip().lower()}|{(victim or '').strip().lower()}"
    return hashlib.sha256(key.encode()).hexdigest()


def rl_detail_url(victim, group):
    # ransomware.live 상세 페이지 ID = base64("피해기업@그룹")
    token = base64.b64encode(f"{victim}@{group}".encode()).decode()
    return f"https://www.ransomware.live/id/{token}"


def normalize(it):
    """/recentvictims 와 /countryvictims 의 서로 다른 스키마를 하나로 맞춤.

    recentvictims : victim, group, domain, attackdate, url(ransomware.live)
    countryvictims: post_title, group_name, website, published, post_url(.onion → 버림)
    """
    victim = it.get("victim") or it.get("post_title")
    group = it.get("group") or it.get("group_name")
    if not victim or not group:
        return None
    return {
        "victim": victim.strip(),
        "group": group.strip(),
        "domain": it.get("domain") or it.get("website"),
        "country": it.get("country"),
        "activity": None if it.get("activity") in (None, "", "Not Found") else it["activity"],
        "description": it.get("description"),
        "attackdate": it.get("attackdate") or it.get("published"),
        "discovered": it.get("discovered"),
        "url": it.get("url") or rl_detail_url(victim.strip(), group.strip()),
    }


def upsert_victims(items):
    """피해 목록 저장. 새로 저장한 건수와 그중 한국 건수를 반환."""
    threshold = current_app.config["KOREA_SCORE_THRESHOLD"]
    new = new_kr = 0
    seen = set()
    for raw in items:
        it = normalize(raw) if isinstance(raw, dict) else None
        if it is None:
            continue
        uid = victim_uid(it["group"], it["victim"])
        if uid in seen:
            continue
        seen.add(uid)

        row = RansomVictim.query.filter_by(uid=uid).first()
        kr = analyze_victim(it.get("victim"), it.get("domain"), it.get("country"),
                            it.get("description"), threshold)
        fields = dict(
            victim=it["victim"][:300],
            group=it["group"][:100],
            domain=(it.get("domain") or "")[:300] or None,
            country=(it.get("country") or "")[:10] or None,
            activity=(it.get("activity") or "")[:100] or None,
            description=(it.get("description") or "")[:2000] or None,
            attack_date=parse_dt(it.get("attackdate")),
            discovered=parse_dt(it.get("discovered")) or parse_dt(it.get("attackdate")),
            rl_url=(it.get("url") or "")[:500] or None,
            korea_score=kr.score,
            is_korea=kr.is_korea,
            korea_matches=",".join(kr.matches)[:300] or None,
        )
        if row is None:
            db.session.add(RansomVictim(uid=uid, **fields))
            new += 1
            new_kr += kr.is_korea
        else:
            # 엔드포인트마다 국가 정보가 다를 수 있어 한국 판정은 더 높은 점수를 유지
            if row.korea_score > kr.score:
                for k in ("korea_score", "is_korea", "korea_matches"):
                    fields.pop(k)
            for k, v in fields.items():
                if v is not None:
                    setattr(row, k, v)
    db.session.commit()
    return new, new_kr


def _run(key, path):
    state = db.session.get(CollectorState, key) or CollectorState(key=key)
    db.session.add(state)
    try:
        new, new_kr = upsert_victims(api_get(path))
        state.last_status = "ok"
        state.last_error = None
        state.last_new_count = new
        log.info("%s 완료: 신규 %d건 (한국 %d건)", key, new, new_kr)
        result = {"new": new, "new_korea": new_kr}
    except Exception as e:
        db.session.rollback()
        state = db.session.get(CollectorState, key) or CollectorState(key=key)
        db.session.add(state)
        state.last_status = "error"
        state.last_error = str(e)[:1000]
        state.last_new_count = 0
        log.warning("%s 실패: %s", key, e)
        result = {"error": str(e)}
    state.last_run_at = datetime.utcnow()
    db.session.commit()
    return result


def collect_recent():
    """전 세계 최근 피해 100건 (약 일주일치). 국가 필드가 빈 한국 피해도 여기서 잡힘."""
    return _run("rl_recent", "/recentvictims")


def collect_korea():
    """한국(KR) 전체 피해 이력."""
    return _run("rl_korea", "/countryvictims/KR")


def collect_all():
    return {"recent": collect_recent(), "korea": collect_korea()}
