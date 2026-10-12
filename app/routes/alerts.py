from datetime import datetime, timedelta

from flask import Blueprint, Response, abort, current_app, jsonify, render_template, request

from ..alerts import engine, slack
from ..extensions import db
from ..models import Alert

bp = Blueprint("alerts", __name__)

PER_PAGE = 25
SEVERITIES = ("critical", "high", "medium")
STATUSES = ("new", "ack", "ignored")


def alert_query(args):
    q = Alert.query
    if args.get("severity") in SEVERITIES:
        q = q.filter(Alert.severity == args["severity"])
    status = args.get("status", "open")
    if status == "open":
        q = q.filter(Alert.status != "ignored")
    elif status in STATUSES:
        q = q.filter(Alert.status == status)
    if args.get("kind"):
        q = q.filter(Alert.kind == args["kind"])
    # 등급 → 사건 발생 시각 순
    order = db.case({"critical": 0, "high": 1, "medium": 2}, value=Alert.severity)
    if args.get("sort") == "severity":
        return q.order_by(order, Alert.event_at.desc())
    return q.order_by(Alert.created_at.desc(), Alert.event_at.desc())


def alert_counts():
    rows = (
        db.session.query(Alert.severity, db.func.count(Alert.id))
        .filter(Alert.status == "new")
        .group_by(Alert.severity)
        .all()
    )
    return {s: n for s, n in rows}


def serialize(a):
    return {
        "id": a.id,
        "kind": a.kind,
        "kind_label": slack.KIND_LABEL.get(a.kind, a.kind),
        "severity": a.severity,
        "title": a.title,
        "url": a.url,
        "internal_url": a.internal_url,
        "fields": a.field_list,
        "related": a.related_list,
        "event_at": a.event_at.isoformat() + "Z" if a.event_at else None,
        "created_at": a.created_at.isoformat() + "Z",
        "status": a.status,
        "slack_status": a.slack_status,
        "slack_reason": a.slack_reason,
    }


# ---------------------------------------------------------------- 화면
@bp.route("/alerts")
def index():
    cfg = current_app.config
    since = datetime.utcnow() - timedelta(days=1)
    return render_template(
        "alerts.html",
        counts=alert_counts(),
        today=Alert.query.filter(Alert.created_at >= since).count(),
        slack_sent=Alert.query.filter(Alert.slack_status == "sent").count(),
        slack_failed=Alert.query.filter(Alert.slack_status == "failed").count(),
        slack_configured=bool(cfg["SLACK_WEBHOOK_URL"]),
        slack_min=cfg["ALERT_SLACK_MIN_SEVERITY"],
        max_age=cfg["ALERT_MAX_AGE_HOURS"],
        kinds=slack.KIND_LABEL,
    )


@bp.route("/partials/alerts")
def list_partial():
    page = request.args.get("page", 1, type=int)
    pagination = alert_query(request.args).paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("partials/alert_list.html", pagination=pagination, args=request.args,
                           kinds=slack.KIND_LABEL)


@bp.post("/alerts/<int:alert_id>/status")
def set_status(alert_id):
    alert = db.session.get(Alert, alert_id) or abort(404)
    status = request.form.get("status") or (request.get_json(silent=True) or {}).get("status")
    if status not in STATUSES:
        abort(400)
    alert.status, alert.status_at = status, datetime.utcnow()
    db.session.commit()
    if request.headers.get("HX-Request"):
        resp = Response(render_template("partials/alert_row.html", a=alert, kinds=slack.KIND_LABEL))
        resp.headers["HX-Trigger"] = "alerts-changed"
        return resp
    return jsonify(serialize(alert))


@bp.route("/partials/alert-badge")
def badge_partial():
    c = alert_counts()
    return render_template("partials/alert_badge.html", n=c.get("critical", 0) + c.get("high", 0))


# ---------------------------------------------------------------- API
@bp.get("/api/alerts")
def list_api():
    limit = min(request.args.get("limit", 50, type=int), 200)
    return jsonify([serialize(a) for a in alert_query(request.args).limit(limit)])


@bp.post("/api/alerts/run")
def run_api():
    return jsonify(engine.run())


@bp.post("/api/alerts/test-slack")
def test_slack():
    try:
        slack.send_test()
        return jsonify(ok=True, message="테스트 메시지를 보냈습니다. Slack 채널을 확인하세요.")
    except Exception as e:
        return jsonify(ok=False, message=f"전송 실패: {e}"), 400


@bp.get("/api/alerts/poll")
def poll():
    """새 알람 확인 (화면에서 15초마다 호출). after 이후 생성된 알람만 반환.

    SSE는 탭마다 연결을 계속 점유해, 탭이 6개 이상이면 브라우저의 호스트당 동시 연결 한도를
    소진해 페이지 이동이 멈췄음 → 짧은 요청으로 교체.
    """
    after = request.args.get("after", type=int)
    if after is None:
        return jsonify(last_id=db.session.query(db.func.max(Alert.id)).scalar() or 0, alerts=[])
    rows = Alert.query.filter(Alert.id > after).order_by(Alert.id).limit(20).all()
    last_id = rows[-1].id if rows else after
    return jsonify(last_id=last_id, alerts=[serialize(a) for a in rows])
