from datetime import datetime

from .extensions import db


class Source(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    region = db.Column(db.String(10), nullable=False)  # "KR" (국내) / "INTL" (해외)
    enabled = db.Column(db.Boolean, default=True, nullable=False)

    # 수집 상태 (소스 장애 감시용)
    last_fetched_at = db.Column(db.DateTime)
    last_status = db.Column(db.String(20))  # ok / error
    last_error = db.Column(db.Text)
    last_new_count = db.Column(db.Integer, default=0)

    articles = db.relationship("Article", back_populates="source", lazy="dynamic")


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey("source.id"), nullable=False, index=True)
    url_hash = db.Column(db.String(64), unique=True, nullable=False)
    url = db.Column(db.String(1000), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    summary = db.Column(db.Text)
    author = db.Column(db.String(200))
    published_at = db.Column(db.DateTime, index=True)  # UTC
    collected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # 분석 결과
    korea_score = db.Column(db.Integer, default=0, nullable=False)
    is_korea = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_nk_threat = db.Column(db.Boolean, default=False, nullable=False, index=True)
    korea_matches = db.Column(db.String(500))  # 매칭된 키워드 (콤마 구분)
    cves = db.Column(db.String(500))  # 추출된 CVE (콤마 구분)

    source = db.relationship("Source", back_populates="articles")

    @property
    def cve_list(self):
        return self.cves.split(",") if self.cves else []

    @property
    def match_list(self):
        return self.korea_matches.split(",") if self.korea_matches else []


class RansomVictim(db.Model):
    """ransomware.live 피해 등록 정보.

    유출 사이트(.onion) 주소·스크린샷은 저장하지 않고 메타데이터만 보관한다.
    """

    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(64), unique=True, nullable=False)  # group+victim 해시
    victim = db.Column(db.String(300), nullable=False)
    group = db.Column(db.String(100), nullable=False, index=True)
    domain = db.Column(db.String(300))
    country = db.Column(db.String(10), index=True)
    activity = db.Column(db.String(100))  # 업종
    description = db.Column(db.Text)
    attack_date = db.Column(db.DateTime)  # UTC, 그룹이 주장한 공격일
    discovered = db.Column(db.DateTime, index=True)  # UTC, ransomware.live 등록일
    rl_url = db.Column(db.String(500))  # ransomware.live 상세 페이지
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    korea_score = db.Column(db.Integer, default=0, nullable=False)
    is_korea = db.Column(db.Boolean, default=False, nullable=False, index=True)
    korea_matches = db.Column(db.String(300))

    @property
    def match_list(self):
        return self.korea_matches.split(",") if self.korea_matches else []


class CollectorState(db.Model):
    """API 수집기 실행 상태 (ransomware.live 등 RSS 외 수집기)."""

    key = db.Column(db.String(50), primary_key=True)
    last_run_at = db.Column(db.DateTime)
    last_status = db.Column(db.String(20))
    last_error = db.Column(db.Text)
    last_new_count = db.Column(db.Integer, default=0)


class Cve(db.Model):
    """기사에 언급된 CVE + NVD/KEV/EPSS 보강 정보."""

    cve_id = db.Column(db.String(30), primary_key=True)
    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # NVD
    description = db.Column(db.Text)
    nvd_status = db.Column(db.String(40))  # Awaiting Analysis / Analyzed / ...
    published = db.Column(db.DateTime)
    last_modified = db.Column(db.DateTime)
    cvss_score = db.Column(db.Float, index=True)
    cvss_severity = db.Column(db.String(20))
    cvss_version = db.Column(db.String(10))
    cvss_vector = db.Column(db.String(300))
    cwes = db.Column(db.String(200))
    affected = db.Column(db.Text)  # JSON: [{"vendor","product"}]
    references = db.Column(db.Text)  # JSON: [url, ...]
    nvd_fetched_at = db.Column(db.DateTime)
    nvd_error = db.Column(db.String(300))

    # EPSS
    epss = db.Column(db.Float)
    epss_percentile = db.Column(db.Float)
    epss_fetched_at = db.Column(db.DateTime)

    # CISA KEV (KevEntry와 동기화)
    in_kev = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # 한국 제조사 제품 관련 여부
    korea_vendor = db.Column(db.String(100))

    @property
    def affected_list(self):
        import json

        return json.loads(self.affected) if self.affected else []

    @property
    def reference_list(self):
        import json

        return json.loads(self.references) if self.references else []

    @property
    def priority(self):
        """대응 우선순위: (등급키, 라벨). KEV(실제 악용) > 고위험 점수 > 그 외."""
        epss = self.epss or 0
        score = self.cvss_score or 0
        if self.in_kev or (score >= 9.0 and epss >= 0.1):
            return ("p1", "긴급")
        if score >= 9.0 or epss >= 0.1:
            return ("p2", "높음")
        if score >= 7.0:
            return ("p3", "주의")
        if self.cvss_score is None and self.epss is None:
            return ("p0", "미평가")
        return ("p4", "보통")


class KevEntry(db.Model):
    """CISA Known Exploited Vulnerabilities 카탈로그 전체."""

    cve_id = db.Column(db.String(30), primary_key=True)
    vendor = db.Column(db.String(200))
    product = db.Column(db.String(200))
    name = db.Column(db.String(500))
    description = db.Column(db.Text)
    date_added = db.Column(db.Date, index=True)
    due_date = db.Column(db.Date)
    required_action = db.Column(db.Text)
    ransomware_use = db.Column(db.String(20))  # Known / Unknown
    cwes = db.Column(db.String(200))
    korea_vendor = db.Column(db.String(100))


class Alert(db.Model):
    """알람. dedup_key가 같은 사건은 한 번만 생성(=Slack 한 번만 전송)."""

    id = db.Column(db.Integer, primary_key=True)
    dedup_key = db.Column(db.String(200), unique=True, nullable=False)
    kind = db.Column(db.String(30), nullable=False, index=True)  # ransomware / korea_news / nk_threat / kev / cve_critical / kr_incident
    severity = db.Column(db.String(10), nullable=False, index=True)  # critical / high / medium
    title = db.Column(db.String(500), nullable=False)
    summary = db.Column(db.Text)
    url = db.Column(db.String(1000))  # 원문/상세
    internal_url = db.Column(db.String(300))  # 대시보드 내부 상세
    fields = db.Column(db.Text)  # JSON: [[라벨, 값], ...] — Slack 필드 표시용
    related = db.Column(db.Text)  # JSON: 같은 사건으로 묶인 추가 기사 [{title,url,source}]
    event_at = db.Column(db.DateTime)  # 원 사건 시각 (UTC)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    status = db.Column(db.String(10), default="new", nullable=False, index=True)  # new / ack / ignored
    status_at = db.Column(db.DateTime)

    slack_status = db.Column(db.String(10), default="pending", nullable=False, index=True)  # pending / sent / failed / skipped
    slack_reason = db.Column(db.String(300))  # skipped/failed 사유
    slack_attempts = db.Column(db.Integer, default=0, nullable=False)
    slack_sent_at = db.Column(db.DateTime)

    @property
    def field_list(self):
        import json

        return json.loads(self.fields) if self.fields else []

    @property
    def related_list(self):
        import json

        return json.loads(self.related) if self.related else []
