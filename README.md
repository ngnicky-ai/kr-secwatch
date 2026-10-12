# KR-SecWatch

**한국 보안 위협 모니터링 대시보드** — 국내외 보안 뉴스, 랜섬웨어 피해 등록, 취약점(CVE) 정보를 한곳에 모으고, 그중 **한국과 관련된 위협**을 자동으로 골라 Slack으로 알려줍니다.

![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)
![HTMX](https://img.shields.io/badge/HTMX-2.0-3366CC)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white)

![대시보드](docs/screenshots/dashboard-dark.png)

> **스크린샷 안내** — 랜섬웨어 피해 기업명·도메인은 범죄 그룹의 *주장*이며 실제 피해가 확인되지 않은 정보이므로 스크린샷에서는 `W********` 형태로 가렸습니다. 실제 화면에는 원문이 표시됩니다.

---

## 주요 기능

| | 기능 | 설명 |
|---|---|---|
| 📰 | **보안 뉴스 수집** | 보안뉴스 · 데일리시큐 · BleepingComputer · The Hacker News RSS를 15분마다 수집 |
| 🇰🇷 | **한국 관련 탐지** | 해외 기사에서 한국 키워드 · 한국 기업명 · `.kr` 도메인을 점수화해 자동 분류. 북한 위협 행위자(Lazarus, Kimsuky 등)는 별도 분류 |
| 🔒 | **랜섬웨어 피해 추적** | [ransomware.live](https://www.ransomware.live) 공개 API로 한국 피해 이력 전체와 전 세계 최근 피해를 수집. 월별 추이 · 공격 그룹 · 업종 통계 |
| 🛡️ | **CVE 자동 보강** | 기사 속 CVE를 추출해 NVD(CVSS · 영향 제품) · CISA KEV(실제 악용) · FIRST EPSS(악용 확률)로 보강하고 대응 우선순위 산정. 한국 제조사 제품(Samsung, LG, 한컴, 안랩 등) 표시 |
| 🚨 | **알람 + Slack** | Critical/High/Medium 규칙 기반 알람. 같은 사건을 여러 매체가 보도하면 하나로 묶어 Slack에 한 번만 전송 |
| ⌨️ | **통합 검색** | `Ctrl+K` / `⌘K` / `/` 로 CVE 번호 · 기업명 · 기사 · 알람 · 메뉴를 한 번에 검색 |
| 🌗 | **다크/라이트 · 모바일** | 다크 모드 기본, 라이트 전환, 모바일 하단 탭바 |

## 화면

### 대시보드
최근 24시간 상황 띠, 핵심 지표와 추이선, 일자별 수집 현황, 한국 관련 알람을 한 화면에서 확인합니다.

| 다크 | 라이트 |
|---|---|
| ![대시보드 다크](docs/screenshots/dashboard-dark.png) | ![대시보드 라이트](docs/screenshots/dashboard-light.png) |

### 랜섬웨어 피해 현황
한국 피해 월별 추이(24개월), 한국을 공격한 그룹 · 피해 업종, 전 세계에서 활발한 그룹.

![랜섬웨어](docs/screenshots/ransomware.png)

### CVE 취약점
뉴스에 언급된 CVE를 우선순위 · CVSS · EPSS · KEV 여부와 함께 보여주고, 최근 KEV 신규 등재와 KEV에 오른 한국 제조사 제품을 따로 모읍니다.

| 목록 | 상세 |
|---|---|
| ![CVE 목록](docs/screenshots/cve-list.png) | ![CVE 상세](docs/screenshots/cve-detail.png) |

### 알람
등급 · 상태 · 유형별 필터, 확인/무시 처리, Slack 전송 결과(전송됨 / 제외 사유)를 표시합니다.

![알람](docs/screenshots/alerts.png)

### 뉴스 · 통합 검색 · 모바일

| 뉴스 (한국 관련 필터) | 통합 검색 (`Ctrl+K`) | 모바일 |
|---|---|---|
| ![뉴스](docs/screenshots/news.png) | ![검색](docs/screenshots/search.png) | <img src="docs/screenshots/mobile.png" width="260" alt="모바일"> |

---

## 빠른 시작

```bash
git clone https://github.com/ngnicky-ai/kr-secwatch.git
cd kr-secwatch
pip install -r requirements.txt
cp .env.example .env     # 선택: Slack, NVD API 키 등 설정
python run.py            # http://127.0.0.1:5000
```

서버가 뜨면 스케줄러가 바로 1회 수집을 시작합니다. ransomware.live는 분당 1회 제한이 있어 한국 피해 이력은 약 1~2분 뒤에 채워집니다. 데이터는 `instance/secwatch.db`(SQLite)에 저장됩니다.

## 설정 (`.env`)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `SLACK_WEBHOOK_URL` | (비어 있음) | Slack Incoming Webhook URL. 비우면 Slack 전송 안 함 |
| `ALERT_SLACK_MIN_SEVERITY` | `high` | 이 등급 이상만 Slack 전송 (`critical` / `high` / `medium`) |
| `ALERT_MAX_AGE_HOURS` | `48` | 발생 후 이 시간이 지난 항목은 Slack으로 보내지 않음 (첫 실행 시 과거 데이터 폭주 방지) |
| `PUBLIC_BASE_URL` | `http://127.0.0.1:5000` | Slack 메시지의 "대시보드에서 보기" 링크 주소 |
| `NVD_API_KEY` | (비어 있음) | [NVD API 키](https://nvd.nist.gov/developers/request-an-api-key) (무료). 있으면 CVE 조회 약 10배 빠름 |
| `RSS_INTERVAL_MINUTES` | `15` | 뉴스 수집 주기 |
| `RL_RECENT_INTERVAL_MINUTES` / `RL_KOREA_INTERVAL_MINUTES` | `30` / `180` | ransomware.live 수집 주기 |
| `CVE_INTERVAL_MINUTES` | `15` | CVE 보강 주기 |
| `KOREA_SCORE_THRESHOLD` | `60` | 한국 관련 판정 기준 점수 |
| `DATABASE_URL` | SQLite | 예: `postgresql+psycopg://user:pass@host/secwatch` |
| `SECRET_KEY` | 개발용 값 | 운영 시 반드시 변경 |

### Slack 연결

1. https://api.slack.com/apps 에서 앱 생성 → **Incoming Webhooks** 활성화 → 채널 선택 후 Webhook URL 발급
2. `.env`에 `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...` 입력 후 서버 재시작
3. `/alerts` 페이지의 **테스트 메시지 보내기**로 확인

Webhook URL은 비밀값입니다. `.env`에만 두세요 (`.gitignore`에 포함되어 있습니다).

## 알람 규칙

| 등급 | 조건 | Slack |
|---|---|---|
| 🔴 Critical | 한국 기업 랜섬웨어 피해 등록 · 한국 제조사 제품 KEV 등재 | 전송 |
| 🟠 High | 해외 매체의 한국 관련 보도 · 북한 위협 · 뉴스에 언급된 KEV 취약점 | 전송 |
| 🟡 Medium | 뉴스에 언급된 CVSS 9.0 이상 · 국내 침해 사고 보도 | 대시보드만 |

- 같은 피해 기업 · CVE · 기사는 한 번만 알람을 만듭니다.
- **같은 사건 묶음** — 48시간 안의 같은 유형 알람과 ① 같은 CVE ② 제목+요약 TF-IDF 코사인 유사도 0.25 이상 ③ 드문 고유명사(ARTEX, NetScaler 등) 공유 중 하나에 해당하면 기존 알람에 "같은 사건 보도"로 붙이고 Slack은 다시 보내지 않습니다. 기준값은 실제 수집 기사 쌍으로 검증했습니다(같은 사건 0.26~0.6, 다른 사건 0.24 이하).
- 전송 실패 시 최대 3회 재시도, 웹훅 권장 속도(1건/초)에 맞춰 실행당 최대 10건 전송.
- 화면은 15초마다 새 알람을 확인해 Critical · High를 토스트로 띄웁니다(보이지 않는 탭은 확인 중지).

CVE 대응 우선순위는 **긴급**(KEV 등재, 또는 CVSS ≥ 9.0 이고 EPSS ≥ 10%) · **높음**(CVSS ≥ 9.0 또는 EPSS ≥ 10%) · **주의**(CVSS ≥ 7.0) 순입니다.

---

## 구조

```mermaid
flowchart LR
  subgraph 수집["수집 (APScheduler)"]
    RSS[RSS 4종<br/>15분]
    RL[ransomware.live<br/>30분 / 3시간]
    CVE[NVD · KEV · EPSS<br/>15분]
  end
  RSS --> AN[한국 탐지 · CVE 추출]
  RL --> AN
  AN --> DB[(SQLite)]
  CVE --> DB
  DB --> ENG[알람 엔진<br/>중복 억제 · 사건 묶음]
  ENG --> SL[Slack]
  DB --> WEB[Flask + HTMX 대시보드]
  ENG --> WEB
```

```
app/
├── collectors/
│   ├── rss.py               # RSS 수집 (중복 제거, 재시도, 국내 피드 KST 보정)
│   ├── ransomware_live.py   # ransomware.live API (분당 1회 제한 준수)
│   └── cve_enrich.py        # NVD / CISA KEV / EPSS 보강
├── analyzers/
│   ├── korea.py             # 한국 관련성 · 북한 위협 · 한국 제조사 판정 규칙
│   └── cve.py               # CVE ID 추출
├── alerts/
│   ├── engine.py            # 알람 규칙 · 중복 억제 · 같은 사건 묶음
│   └── slack.py             # Slack Incoming Webhook (Block Kit)
├── routes/                  # dashboard(화면) · api(JSON) · alerts · search(⌘K)
├── templates/ · static/     # Jinja2 + HTMX, CSS 토큰 기반 다크/라이트 테마
├── models.py                # Source · Article · RansomVictim · Cve · KevEntry · Alert
└── scheduler.py             # 수집 → 알람 평가 → Slack 전송
```

**스택**: Flask 3 · SQLAlchemy · APScheduler · feedparser · httpx · HTMX · ApexCharts · Pretendard

### API

| Method | Path | 설명 |
|---|---|---|
| GET | `/api/stats` · `/api/articles?tag=korea&region=INTL&q=` | 뉴스 통계 · 기사 목록 |
| GET | `/api/ransomware/stats` · `/api/ransomware/victims` | 랜섬웨어 통계 · 한국 피해 목록 |
| GET | `/api/cves?tag=kev\|critical\|korea` | 언급된 CVE와 보강 정보 |
| GET | `/api/alerts` · `/api/alerts/poll?after=` | 알람 목록 · 새 알람 확인 |
| GET | `/api/search?q=` | 통합 검색 |
| POST | `/api/collect` · `/api/ransomware/collect` · `/api/cve/collect` · `/api/alerts/run` | 수동 수집 · 평가 실행 |
| POST | `/api/alerts/test-slack` | Slack 테스트 메시지 |

## 구현 메모

수집 대상마다 문서화되지 않은 특성이 있어 실제 응답으로 확인하며 맞췄습니다.

- **BleepingComputer** — 브라우저 User-Agent는 Cloudflare가 403으로 차단하고, 피드 리더 형식 UA는 허용합니다.
- **데일리시큐** — RSS `pubDate`가 시간대 없이 KST로 옵니다. 국내 소스는 시간대 없는 날짜를 KST로 해석합니다.
- **ransomware.live** — 공개 API는 **IP당 분당 1회**이고, 초과해도 HTTP 200 + `{"message": "1 per 1 minute"}`로 응답합니다. 모든 호출을 61초 간격으로 직렬화합니다. `/recentvictims`와 `/countryvictims` 는 필드명이 서로 달라 하나로 정규화합니다. 최근 피해의 약 20%는 국가 필드가 비어 있어 `.kr` 도메인과 한국 기업명으로도 판정합니다.
- **NVD** — 키 없이 30초에 5회 제한. 최근 CVE는 대부분 분석 전(Awaiting Analysis)이라 CPE가 없어, CNA가 등록한 `affected` 필드에서 영향 제품을 가져옵니다.
- **실시간 알람** — 처음엔 SSE로 구현했으나 탭마다 연결을 계속 점유해, 탭이 6개 이상이면 브라우저의 호스트당 동시 연결 한도를 소진해 페이지 이동이 멈췄습니다. 15초 주기의 짧은 요청으로 바꿔 해결했습니다.

## 데이터 취급 원칙

- 뉴스는 **제목 · 요약 · 원문 링크**만 저장 · 표시합니다. 저작권은 각 언론사에 있습니다.
- 랜섬웨어 피해는 기업명 · 도메인 · 그룹 · 업종 등 **공개 메타데이터만** 저장합니다. 유출 사이트(.onion) 주소, 스크린샷, 유출 자료는 저장하지 않으며 상세 링크는 ransomware.live 페이지로 연결합니다.
- ransomware.live 등록은 범죄 그룹의 **주장**이며 실제 피해 여부는 별도 확인이 필요합니다.
- 각 데이터 출처의 이용약관과 요청 제한을 지킵니다 (RSS · 공식 API만 사용).

## ⚠️ 주의

현재 버전에는 **로그인이 없습니다.** 수집 실행 · 알람 처리 · Slack 테스트 API를 누구나 호출할 수 있으므로 **내부망이나 로컬에서만** 실행하세요. 기본 실행은 `127.0.0.1`에만 바인딩됩니다.

## 로드맵

- [x] 1단계 — RSS 수집, 한국 관련 탐지, 대시보드
- [x] 2단계 — ransomware.live 연동, 한국 피해 추적
- [x] 3단계 — CVE 보강 (NVD · KEV · EPSS), 우선순위
- [x] 4단계 — 알람 엔진, Slack 연동
- [x] 5단계 — 디자인 고도화 (통합 검색, 추이선, 모바일)
- [ ] 6단계 — 로그인, Docker 배포, 정적 자산 내장(내부망 운영)
- [ ] 관심 자산(Watchlist) — 사용 중인 제품의 CVE 즉시 알림
- [ ] AI 요약 — 해외 기사 한국어 요약, 한국 관련성 재판정
- [ ] 주간 리포트 자동 생성
