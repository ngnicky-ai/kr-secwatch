import logging
import threading
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

log = logging.getLogger(__name__)
scheduler = BackgroundScheduler(timezone="Asia/Seoul")
_app = None


def _job(func_path):
    def run():
        from .alerts import engine

        module, name = func_path.rsplit(".", 1)
        mod = __import__(f"app.{module}", fromlist=[name])
        with _app.app_context():
            getattr(mod, name)()
            # 수집 직후 알람 규칙 평가 + Slack 전송
            try:
                engine.run()
            except Exception:
                log.exception("알람 처리 실패")
    return run


JOBS = {
    # id: (함수, 주기 설정 키, 시작 지연)
    "rss": ("collectors.rss.collect_all", "RSS_INTERVAL_MINUTES", 0),
    # ransomware.live는 분당 1회 제한 → 두 작업이 동시에 시작하지 않도록 지연을 둠
    "rl_recent": ("collectors.ransomware_live.collect_recent", "RL_RECENT_INTERVAL_MINUTES", 5),
    "rl_korea": ("collectors.ransomware_live.collect_korea", "RL_KOREA_INTERVAL_MINUTES", 75),
    "cve": ("collectors.cve_enrich.collect_all", "CVE_INTERVAL_MINUTES", 20),
}


def start_scheduler(app):
    global _app
    if scheduler.running:
        return
    _app = app
    now = datetime.now()
    for job_id, (func_path, interval_key, delay) in JOBS.items():
        scheduler.add_job(
            _job(func_path),
            "interval",
            minutes=app.config[interval_key],
            id=job_id,
            next_run_time=now + timedelta(seconds=delay),  # 시작 직후 1회 수집
            max_instances=1,
            coalesce=True,
        )
    scheduler.start()
    log.info("스케줄러 시작: %s", {k: app.config[v[1]] for k, v in JOBS.items()})


def trigger(job_ids, app):
    """작업을 즉시 실행. 스케줄러가 꺼져 있으면 백그라운드 스레드에서 실행."""
    if scheduler.running:
        for job_id in job_ids:
            scheduler.modify_job(job_id, next_run_time=datetime.now())
        return
    global _app
    _app = app

    def run_all():
        for job_id in job_ids:
            _job(JOBS[job_id][0])()

    threading.Thread(target=run_all, daemon=True).start()
