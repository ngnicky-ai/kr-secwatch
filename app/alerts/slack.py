"""Slack Incoming Webhook 전송 (Block Kit)."""
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from flask import current_app

from ..extensions import db
from ..models import Alert

log = logging.getLogger(__name__)

MAX_PER_RUN = 10  # 웹훅은 초당 1건 권장 → 한 번에 많이 보내지 않고 다음 실행으로 넘김
MAX_ATTEMPTS = 3
KST = timezone(timedelta(hours=9))

SEVERITY_STYLE = {
    "critical": (":red_circle:", "Critical"),
    "high": (":large_orange_circle:", "High"),
    "medium": (":large_yellow_circle:", "Medium"),
}
KIND_LABEL = {
    "ransomware": "랜섬웨어 피해",
    "korea_news": "한국 관련 해외 보도",
    "nk_threat": "북한 위협",
    "kev": "실제 악용 취약점(KEV)",
    "cve_critical": "Critical CVE",
    "kr_incident": "국내 침해 사고 보도",
}


def esc(text):
    """Slack mrkdwn 제어 문자 이스케이프."""
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_message(alert):
    emoji, label = SEVERITY_STYLE.get(alert.severity, (":white_circle:", alert.severity))
    base = current_app.config["PUBLIC_BASE_URL"].rstrip("/")
    title = esc(alert.title)
    title_md = f"<{alert.url}|{title}>" if alert.url else title

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": f"{emoji} *[{label}] {KIND_LABEL.get(alert.kind, alert.kind)}*\n*{title_md}*"}},
    ]
    if alert.summary:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": esc(alert.summary[:500])}})
    fields = [{"type": "mrkdwn", "text": f"*{esc(k)}*\n{esc(str(v))}"} for k, v in alert.field_list[:10] if v]
    if fields:
        blocks.append({"type": "section", "fields": fields})

    when = alert.event_at.replace(tzinfo=timezone.utc).astimezone(KST).strftime("%Y-%m-%d %H:%M KST") \
        if alert.event_at else "-"
    links = [f"<{base}/alerts|알람 목록>"]
    if alert.internal_url:
        links.insert(0, f"<{base}{alert.internal_url}|대시보드에서 보기>")
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": f"KR-SecWatch · 발생 {when} · " + " · ".join(links)}
    ]})
    return {"text": f"[{label}] {alert.title}", "blocks": blocks}


def post(payload):
    url = current_app.config["SLACK_WEBHOOK_URL"]
    if not url:
        raise RuntimeError("SLACK_WEBHOOK_URL 미설정")
    resp = httpx.post(url, json=payload, timeout=15)
    if resp.status_code == 429:
        raise RateLimited(resp.headers.get("Retry-After", "?"))
    if resp.status_code != 200 or resp.text.strip() not in ("ok", ""):
        raise RuntimeError(f"Slack 응답 {resp.status_code}: {resp.text[:200]}")


class RateLimited(Exception):
    pass


def send_pending():
    if not current_app.config["SLACK_WEBHOOK_URL"]:
        return {"sent": 0, "failed": 0}
    rows = (
        Alert.query.filter(
            (Alert.slack_status == "pending")
            | ((Alert.slack_status == "failed") & (Alert.slack_attempts < MAX_ATTEMPTS))
        )
        .order_by(Alert.created_at.asc())
        .limit(MAX_PER_RUN)
        .all()
    )
    sent = failed = 0
    for i, alert in enumerate(rows):
        if i:
            time.sleep(1.1)
        alert.slack_attempts += 1
        try:
            post(build_message(alert))
            alert.slack_status, alert.slack_reason = "sent", None
            alert.slack_sent_at = datetime.utcnow()
            sent += 1
        except RateLimited as e:
            alert.slack_attempts -= 1
            log.warning("Slack 속도 제한 (Retry-After %s초) — 다음 실행에서 재시도", e)
            db.session.commit()
            break
        except Exception as e:
            alert.slack_status, alert.slack_reason = "failed", str(e)[:300]
            failed += 1
            log.warning("Slack 전송 실패 #%d: %s", alert.id, e)
        db.session.commit()
    return {"sent": sent, "failed": failed}


def send_test():
    post({
        "text": "KR-SecWatch Slack 연동 테스트",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn",
                    "text": ":white_check_mark: *KR-SecWatch Slack 연동 테스트*\n이 메시지가 보이면 알람 전송이 정상입니다."}}],
    })
