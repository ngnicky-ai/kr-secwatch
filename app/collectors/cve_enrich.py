"""CVE 보강: NVD(점수·설명·영향 제품) / CISA KEV(실제 악용) / FIRST EPSS(악용 확률).

- NVD API 키가 없으면 30초에 5회 제한 → 호출 간 6.5초 대기 (키가 있으면 0.7초)
- KEV 카탈로그는 6시간마다 전체 동기화, EPSS는 하루 1회 갱신(100건씩 일괄 조회)
"""
import json
import logging
import threading
import time
from datetime import date, datetime, timedelta

import httpx
from flask import current_app
from sqlalchemy import or_

from ..analyzers.korea import korea_vendor
from ..extensions import db
from ..models import Article, CollectorState, Cve, KevEntry

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

KEV_INTERVAL = timedelta(hours=6)
EPSS_REFRESH = timedelta(hours=20)
NVD_REFRESH_PENDING = timedelta(hours=24)  # 아직 분석 전인 CVE 재조회 주기
NVD_REFRESH_DONE = timedelta(days=7)
NVD_FINAL_STATUSES = {"Analyzed", "Modified", "Rejected", "Deferred"}
NVD_BATCH = 20  # 1회 실행당 NVD 조회 최대 건수

_lock = threading.Lock()
_nvd_lock = threading.Lock()
_nvd_last = 0.0


def _client():
    return httpx.Client(
        timeout=60,
        follow_redirects=True,
        headers={"User-Agent": current_app.config["USER_AGENT"], "Accept": "application/json"},
    )


def _state(key):
    st = db.session.get(CollectorState, key)
    if st is None:
        st = CollectorState(key=key)
        db.session.add(st)
    return st


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return None


def _parse_date(value):
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


# ---------------------------------------------------------------- KEV
def sync_kev(force=False):
    st = _state("kev")
    if not force and st.last_run_at and datetime.utcnow() - st.last_run_at < KEV_INTERVAL \
            and st.last_status == "ok":
        return None
    try:
        with _client() as c:
            resp = c.get(KEV_URL)
        resp.raise_for_status()
        items = resp.json()["vulnerabilities"]

        existing = {k.cve_id: k for k in KevEntry.query.all()}
        new = 0
        for it in items:
            cid = it["cveID"].upper()
            row = existing.get(cid)
            if row is None:
                row = KevEntry(cve_id=cid)
                db.session.add(row)
                new += 1
            row.vendor = it.get("vendorProject")
            row.product = it.get("product")
            row.name = (it.get("vulnerabilityName") or "")[:500]
            row.description = it.get("shortDescription")
            row.date_added = _parse_date(it.get("dateAdded"))
            row.due_date = _parse_date(it.get("dueDate"))
            row.required_action = it.get("requiredAction")
            row.ransomware_use = it.get("knownRansomwareCampaignUse")
            row.cwes = ",".join(it.get("cwes") or [])[:200] or None
            row.korea_vendor = korea_vendor(row.vendor, row.product)
        db.session.flush()

        kev_ids = {it["cveID"].upper() for it in items}
        for cve in Cve.query.all():
            cve.in_kev = cve.cve_id in kev_ids

        st.last_status, st.last_error, st.last_new_count = "ok", None, new
        log.info("KEV 동기화: 전체 %d건, 신규 %d건", len(items), new)
    except Exception as e:
        db.session.rollback()
        st = _state("kev")
        st.last_status, st.last_error, st.last_new_count = "error", str(e)[:1000], 0
        log.warning("KEV 동기화 실패: %s", e)
    st.last_run_at = datetime.utcnow()
    db.session.commit()
    return st.last_status


# ---------------------------------------------------------------- 기사 → CVE 목록
def sync_cve_ids():
    known = {cid for (cid,) in db.session.query(Cve.cve_id)}
    kev_ids = {cid for (cid,) in db.session.query(KevEntry.cve_id)}
    mentioned = set()
    for (cves,) in db.session.query(Article.cves).filter(Article.cves.isnot(None)):
        mentioned.update(cves.split(","))
    new_ids = mentioned - known
    for cid in new_ids:
        db.session.add(Cve(cve_id=cid, in_kev=cid in kev_ids))
    db.session.commit()
    return len(new_ids)


# ---------------------------------------------------------------- NVD
def _nvd_wait():
    global _nvd_last
    interval = 0.7 if current_app.config.get("NVD_API_KEY") else 6.5
    wait = _nvd_last + interval - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _nvd_last = time.monotonic()


def _best_metric(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        return {
            "score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
            "version": data.get("version"),
            "vector": data.get("vectorString"),
        }
    return None


def _affected_products(cve):
    out, seen = [], set()

    def add(vendor, product):
        vendor, product = (vendor or "").strip(), (product or "").strip()
        if vendor.lower() in ("n/a", "-", "*"):
            vendor = ""
        if product.lower() in ("n/a", "-", "*"):
            product = ""
        key = (vendor.lower(), product.lower())
        if (vendor or product) and key not in seen and len(out) < 30:
            seen.add(key)
            out.append({"vendor": vendor, "product": product})

    for src in cve.get("affected") or []:
        for a in src.get("affectedData") or []:
            add(a.get("vendor"), a.get("product"))
    # NVD 분석 완료된 CVE는 configurations의 CPE에 제품 정보가 있음
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    parts = (m.get("criteria") or "").split(":")
                    if len(parts) > 4:
                        add(parts[3].replace("_", " ").title(), parts[4].replace("_", " "))
    return out


def apply_nvd(row, cve):
    row.description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    row.nvd_status = cve.get("vulnStatus")
    row.published = _parse_dt(cve.get("published"))
    row.last_modified = _parse_dt(cve.get("lastModified"))
    m = _best_metric(cve.get("metrics") or {})
    if m:
        row.cvss_score, row.cvss_severity = m["score"], m["severity"]
        row.cvss_version, row.cvss_vector = m["version"], (m["vector"] or "")[:300] or None
    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    row.cwes = ",".join(cwes)[:200] or None
    products = _affected_products(cve)
    row.affected = json.dumps(products, ensure_ascii=False) if products else None
    refs = []
    for r in cve.get("references") or []:
        if r.get("url") and r["url"] not in refs:
            refs.append(r["url"])
    row.references = json.dumps(refs[:15]) if refs else None

    kev = db.session.get(KevEntry, row.cve_id)
    row.korea_vendor = (kev.korea_vendor if kev else None) or next(
        (v for v in (korea_vendor(p["vendor"], p["product"]) for p in products) if v), None
    )


def fetch_nvd(row, client):
    with _nvd_lock:
        _nvd_wait()
        headers = {}
        if current_app.config.get("NVD_API_KEY"):
            headers["apiKey"] = current_app.config["NVD_API_KEY"]
        resp = client.get(NVD_URL, params={"cveId": row.cve_id}, headers=headers)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities") or []
    row.nvd_fetched_at = datetime.utcnow()
    if not vulns:
        row.nvd_error = "NVD 미등록"
        return
    row.nvd_error = None
    apply_nvd(row, vulns[0]["cve"])


def _nvd_due_query():
    now = datetime.utcnow()
    return Cve.query.filter(
        or_(
            Cve.nvd_fetched_at.is_(None),
            # 분석 전/미등록 CVE는 하루마다, 분석 완료는 일주일마다 재조회
            (Cve.nvd_fetched_at < now - NVD_REFRESH_PENDING)
            & (or_(Cve.nvd_status.is_(None), Cve.nvd_status.notin_(NVD_FINAL_STATUSES))),
            Cve.nvd_fetched_at < now - NVD_REFRESH_DONE,
        )
    ).order_by(Cve.nvd_fetched_at.is_(None).desc(), Cve.first_seen_at.desc())


def enrich_nvd(limit=NVD_BATCH):
    rows = _nvd_due_query().limit(limit).all()
    done = 0
    with _client() as c:
        for row in rows:
            try:
                fetch_nvd(row, c)
                done += 1
            except Exception as e:
                row.nvd_error = f"조회 실패: {e}"[:300]
                log.warning("NVD 조회 실패 %s: %s", row.cve_id, e)
            db.session.commit()
    return done


# ---------------------------------------------------------------- EPSS
def enrich_epss(rows=None):
    if rows is None:
        cutoff = datetime.utcnow() - EPSS_REFRESH
        rows = Cve.query.filter(or_(Cve.epss_fetched_at.is_(None), Cve.epss_fetched_at < cutoff)).all()
    done = 0
    with _client() as c:
        for i in range(0, len(rows), 100):
            batch = {r.cve_id: r for r in rows[i:i + 100]}
            resp = c.get(EPSS_URL, params={"cve": ",".join(batch)})
            resp.raise_for_status()
            for d in resp.json().get("data", []):
                row = batch.get(d["cve"].upper())
                if row:
                    row.epss = float(d["epss"])
                    row.epss_percentile = float(d["percentile"])
            now = datetime.utcnow()
            for row in batch.values():
                row.epss_fetched_at = now  # EPSS에 없는 신규 CVE도 하루 뒤 재시도
            done += len(batch)
            db.session.commit()
    return done


# ---------------------------------------------------------------- 실행
def collect_all():
    if not _lock.acquire(blocking=False):
        return {"skipped": True}
    st = _state("cve")
    db.session.commit()
    try:
        kev = sync_kev()
        new = sync_cve_ids()
        nvd = enrich_nvd()
        epss = enrich_epss()
        st = _state("cve")
        st.last_status, st.last_error, st.last_new_count = "ok", None, new
        result = {"kev": kev, "new_cves": new, "nvd": nvd, "epss": epss}
        log.info("CVE 보강 완료: %s", result)
    except Exception as e:
        db.session.rollback()
        st = _state("cve")
        st.last_status, st.last_error = "error", str(e)[:1000]
        log.warning("CVE 보강 실패: %s", e)
        result = {"error": str(e)}
    finally:
        _lock.release()
    st.last_run_at = datetime.utcnow()
    db.session.commit()
    return result


def enrich_one(cve_id):
    """상세 페이지에서 처음 보는 CVE를 즉시 조회."""
    row = db.session.get(Cve, cve_id)
    if row is None:
        row = Cve(cve_id=cve_id, in_kev=db.session.get(KevEntry, cve_id) is not None)
        db.session.add(row)
        db.session.commit()
    if row.nvd_fetched_at is None:
        try:
            with _client() as c:
                fetch_nvd(row, c)
        except Exception as e:
            row.nvd_error = f"조회 실패: {e}"[:300]
        db.session.commit()
    if row.epss_fetched_at is None:
        try:
            enrich_epss([row])
        except Exception as e:
            log.warning("EPSS 조회 실패 %s: %s", cve_id, e)
    return row
