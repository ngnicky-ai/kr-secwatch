import os
from datetime import timedelta, timezone

from flask import Flask

from config import BASE_DIR, Config

from .extensions import db

KST = timezone(timedelta(hours=9))


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    (BASE_DIR / "instance").mkdir(exist_ok=True)

    db.init_app(app)

    from .routes.dashboard import bp as dashboard_bp
    from .routes.alerts import bp as alerts_bp
    from .routes.api import bp as api_bp
    from .routes.search import bp as search_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(alerts_bp)
    app.register_blueprint(search_bp)

    register_filters(app)

    with app.app_context():
        from . import models
        from .sources import seed_sources

        db.create_all()
        seed_sources()

    # debug 리로더 사용 시 부모 프로세스에서는 스케줄러를 띄우지 않음 (중복 실행 방지)
    if app.config["SCHEDULER_ENABLED"] and (
        not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    ):
        from .scheduler import start_scheduler

        start_scheduler(app)

    return app


def register_filters(app):
    @app.context_processor
    def inject_now():
        from datetime import datetime

        return {"now_utc": datetime.utcnow()}

    @app.context_processor
    def inject_alert_badge():
        from .models import Alert

        from .extensions import db

        n = Alert.query.filter(Alert.status == "new", Alert.severity.in_(("critical", "high"))).count()
        last_id = db.session.query(db.func.max(Alert.id)).scalar() or 0
        return {"alert_badge_n": n, "alert_last_id": last_id}

    @app.template_filter("kst")
    def kst(dt, fmt="%m-%d %H:%M"):
        if dt is None:
            return "-"
        return dt.replace(tzinfo=timezone.utc).astimezone(KST).strftime(fmt)

    @app.template_filter("ago")
    def ago(dt):
        from datetime import datetime

        if dt is None:
            return "-"
        sec = int((datetime.utcnow() - dt).total_seconds())
        if sec < 60:
            return "방금 전"
        if sec < 3600:
            return f"{sec // 60}분 전"
        if sec < 86400:
            return f"{sec // 3600}시간 전"
        return f"{sec // 86400}일 전"
