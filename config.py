import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'secwatch.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 수집 스케줄러
    SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "1") == "1"
    RSS_INTERVAL_MINUTES = int(os.getenv("RSS_INTERVAL_MINUTES", "15"))
    # ransomware.live 공개 API는 분당 1회 제한
    RL_RECENT_INTERVAL_MINUTES = int(os.getenv("RL_RECENT_INTERVAL_MINUTES", "30"))
    RL_KOREA_INTERVAL_MINUTES = int(os.getenv("RL_KOREA_INTERVAL_MINUTES", "180"))
    # CVE 보강 (NVD/KEV/EPSS). NVD API 키가 있으면 조회 속도 약 10배
    CVE_INTERVAL_MINUTES = int(os.getenv("CVE_INTERVAL_MINUTES", "15"))
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))
    # 일부 사이트(BleepingComputer)는 브라우저 UA를 Cloudflare로 차단하고 피드 리더 UA는 허용함
    USER_AGENT = os.getenv(
        "USER_AGENT", "KR-SecWatch/0.1 (RSS reader; +https://github.com/kurtmckee/feedparser)"
    )

    # 알람 / Slack
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    # 이 등급 이상만 Slack 전송 (critical / high / medium)
    ALERT_SLACK_MIN_SEVERITY = os.getenv("ALERT_SLACK_MIN_SEVERITY", "high")
    # 사건 발생 후 이 시간이 지난 항목은 Slack 전송 안 함 (첫 실행 시 과거 데이터 폭주 방지)
    ALERT_MAX_AGE_HOURS = int(os.getenv("ALERT_MAX_AGE_HOURS", "48"))
    # Slack 메시지의 '대시보드에서 보기' 링크용 외부 주소
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5000")

    # 한국 관련성 판정 기준 점수
    KOREA_SCORE_THRESHOLD = int(os.getenv("KOREA_SCORE_THRESHOLD", "60"))
