"""한국 관련성 탐지.

- 해외 기사: 키워드/기업명/.kr 도메인 점수 합산으로 '한국 관련' 판정
- 전체 기사: 북한 위협 행위자 언급은 '북한 위협'으로 별도 분류
  ("North Korea"는 공격 주체이므로 한국 피해로 세지 않도록 먼저 제거)
"""
import re
from dataclasses import dataclass, field

# (라벨, 정규식, 점수) — 패턴별로 한 번만 가산
KOREA_RULES = [
    ("kr-domain", r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.kr\b", 100),
    ("South Korea", r"\b(?:south|republic of)\s+korea(?:n)?\b", 60),
    ("Korea", r"\bkorea\b", 30),
    ("Korean", r"\bkoreans?\b", 30),
    ("Seoul", r"\bseoul\b", 40),
    ("Busan", r"\bbusan\b", 40),
    ("KISA", r"\bkisa\b", 60),
    ("KrCERT", r"\bkrcert\b", 60),
    ("AhnLab", r"\bahnlab\b", 40),
]

# 대표 한국 기업/기관 — 오탐을 피하려 짧은 약어(LG, SK, KT 등)는 구체적인 형태로만 매칭
KOREA_ORGS = [
    ("Samsung", r"\bsamsung\b"),
    ("LG", r"\blg\s+(?:electronics|uplus|u\+|chem|energy|display|cns|group)\b"),
    ("SK", r"\bsk\s+(?:telecom|hynix|shieldus|broadband|group|innovation)\b"),
    ("KT", r"\bkt\s+(?:corp(?:oration)?|telecom)\b"),
    ("Hyundai", r"\bhyundai\b"),
    ("Kia", r"\bkia\s+(?:motors?|corp(?:oration)?)\b"),
    ("Kakao", r"\bkakao(?:talk|bank|pay)?\b"),
    ("Naver", r"\bnaver\b"),
    ("Coupang", r"\bcoupang\b"),
    ("Lotte", r"\blotte\b"),
    ("CJ", r"\bcj\s+(?:group|enm|logistics|cheiljedang|olive)\b"),
    ("Shinhan", r"\bshinhan\b"),
    ("KB Kookmin", r"\bkookmin\b"),
    ("Woori", r"\bwoori\s+(?:bank|financial)\b"),
    ("Hanwha", r"\bhanwha\b"),
    ("Posco", r"\bposco\b"),
    ("Doosan", r"\bdoosan\b"),
    ("Nexon", r"\bnexon\b"),
    ("NCSoft", r"\bnc\s?soft\b"),
    ("Netmarble", r"\bnetmarble\b"),
    ("Korean Air", r"\bkorean\s+air\b"),
    ("Yes24", r"\byes24\b"),
    ("GS Retail", r"\bgs\s+(?:retail|caltex)\b"),
]
ORG_SCORE = 60

NK_RULES = [
    ("North Korea", r"\bnorth\s+korea(?:n)?\b|\bdprk\b|북한"),
    ("Lazarus", r"\blazarus\b|라자루스"),
    ("Kimsuky", r"\bkimsuky\b|김수키"),
    ("Andariel", r"\bandariel\b|안다리엘"),
    ("ScarCruft", r"\bscarcruft\b|\bapt37\b"),
    ("BlueNoroff", r"\bbluenoroff\b|\bapt38\b"),
    ("APT43", r"\bapt43\b"),
    ("Famous Chollima", r"\bfamous\s+chollima\b"),
]

_NK_STRIP = re.compile(r"\bnorth\s+korea(?:n)?s?\b|\bdprk\b", re.IGNORECASE)

_KOREA_RULES = [(l, re.compile(p, re.IGNORECASE), s) for l, p, s in KOREA_RULES]
_ORGS = [(l, re.compile(p, re.IGNORECASE)) for l, p in KOREA_ORGS]
_NK = [(l, re.compile(p, re.IGNORECASE)) for l, p in NK_RULES]


@dataclass
class KoreaResult:
    score: int = 0
    is_korea: bool = False
    is_nk_threat: bool = False
    matches: list = field(default_factory=list)


def analyze(text, region, threshold=60):
    """region: 소스 지역("KR"/"INTL"). 국내 소스는 전부 국내 기사이므로 점수 판정을 생략."""
    text = text or ""
    result = KoreaResult()

    for label, rx in _NK:
        if rx.search(text):
            result.is_nk_threat = True
            result.matches.append(label)

    if region == "KR":
        return result

    stripped = _NK_STRIP.sub(" ", text)
    for label, rx, score in _KOREA_RULES:
        if rx.search(stripped):
            result.score += score
            result.matches.append(label)
    for label, rx in _ORGS:
        if rx.search(stripped):
            result.score += ORG_SCORE
            result.matches.append(label)

    result.is_korea = result.score >= threshold
    return result


# 한국 제조사·국내 보안 솔루션 (CVE 영향 제품의 vendor/product 필드에만 적용)
KOREA_VENDORS = [
    ("Samsung", r"\bsamsung\b"),
    ("LG", r"^lg\b|\blg\s+(?:electronics|innotek|uplus|cns)\b"),
    ("Hancom", r"\bhancom\b|\bhangul\b|한컴"),
    ("AhnLab", r"\bahnlab\b|안랩"),
    ("Naver", r"\bnaver\b"),
    ("Kakao", r"\bkakao\b"),
    ("ipTIME", r"\biptime\b|\befm[\s-]?networks\b"),
    ("Hanwha Vision", r"\bhanwha\b|\btechwin\b|\bwisenet\b"),
    ("Wizvera", r"\bwizvera\b|\bveraport\b"),
    ("Initech", r"\binitech\b|\binisafe\b"),
    ("Dreamsecurity", r"\bdream\s?security\b|\bmagicline\b"),
    ("RaonSecure", r"\braon\s?secure\b"),
    ("Douzone", r"\bdou?zone\b"),
    ("Innorix", r"\binnorix\b"),
    ("Tobesoft", r"\btobesoft\b|\bnexacro\b"),
    ("NHN", r"\bnhn\b"),
]
_VENDORS = [(l, re.compile(p, re.IGNORECASE)) for l, p in KOREA_VENDORS]


def korea_vendor(*texts):
    """vendor/product 문자열 중 한국 제조사가 있으면 라벨 반환."""
    for text in texts:
        for label, rx in _VENDORS:
            if text and rx.search(text):
                return label
    return None


_KR_DOMAIN_RE = re.compile(r"\.kr$", re.IGNORECASE)
_DESC_KOREA_RE = re.compile(r"\b(?:south\s+korea|seoul|busan|incheon|republic\s+of\s+korea)\b|대한민국|한국",
                            re.IGNORECASE)


def analyze_victim(victim, domain, country, description, threshold=60):
    """랜섬웨어 피해 기업의 한국 관련성.

    설명(description)에는 고객사·거래처로 한국 기업이 언급되는 경우가 많아
    설명만으로는 기준 점수에 못 미치도록 낮게 가산한다.
    """
    result = KoreaResult()
    if (country or "").upper() == "KR":
        result.score += 100
        result.matches.append("country=KR")
    if domain and _KR_DOMAIN_RE.search(domain.strip().rstrip("/")):
        result.score += 100
        result.matches.append("kr-domain")

    name = _NK_STRIP.sub(" ", victim or "")
    for label, rx in _ORGS:
        if rx.search(name):
            result.score += ORG_SCORE
            result.matches.append(label)
    if re.search(r"\bkorea(?:n)?\b", name, re.IGNORECASE):
        result.score += 60
        result.matches.append("name:Korea")

    desc = _NK_STRIP.sub(" ", description or "")
    if _DESC_KOREA_RE.search(desc):
        result.score += 30
        result.matches.append("desc:Korea")

    result.is_korea = result.score >= threshold
    return result
