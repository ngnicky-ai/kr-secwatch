import re

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


def extract_cves(text):
    """본문에서 CVE ID를 추출해 정규화(대문자)·중복 제거·정렬해 반환."""
    found = {f"CVE-{y}-{n}" for y, n in CVE_RE.findall(text or "")}
    return sorted(found)
