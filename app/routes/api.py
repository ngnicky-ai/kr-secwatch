from flask import Blueprint, current_app, jsonify, request

from ..collectors.rss import collect_all
from ..cve_queries import cve_list
from ..queries import dashboard_stats, filter_articles
from ..ransom_queries import korea_victims, ransomware_stats
from ..scheduler import trigger

bp = Blueprint("api", __name__)


@bp.post("/collect")
def collect():
    from ..alerts import engine

    result = collect_all()
    engine.run()  # 새 기사로 알람 평가
    return jsonify(result)


@bp.get("/stats")
def stats():
    s = dashboard_stats()
    return jsonify(
        today_count=s["today_count"],
        korea_7d=s["korea_7d"],
        nk_7d=s["nk_7d"],
        cve_7d=s["cve_7d"],
        total=s["total"],
        trend=s["trend"],
        top_cves=s["top_cves"],
        sources=[
            {
                "key": src.key,
                "name": src.name,
                "region": src.region,
                "status": src.last_status,
                "last_fetched_at": src.last_fetched_at.isoformat() + "Z" if src.last_fetched_at else None,
                "error": src.last_error,
                "count_7d": s["source_counts"][src.key],
            }
            for src in s["sources"]
        ],
    )


@bp.post("/ransomware/collect")
def ransomware_collect():
    # ransomware.live는 분당 1회 제한이라 동기 실행 시 1분 이상 걸림 → 백그라운드 실행
    trigger(["rl_recent", "rl_korea"], current_app._get_current_object())
    return jsonify(status="scheduled", note="분당 1회 제한으로 완료까지 약 1~2분 소요"), 202


@bp.get("/ransomware/stats")
def ransomware_stats_api():
    s = ransomware_stats()
    return jsonify(
        kr_total=s["kr_total"],
        kr_this_year=s["kr_this_year"],
        kr_30d=s["kr_30d"],
        kr_7d=s["kr_7d"],
        global_7d=s["global_7d"],
        monthly=s["monthly"],
        kr_groups=s["kr_groups"],
        kr_sectors=s["kr_sectors"],
        global_groups=[list(g) for g in s["global_groups"]],
        collectors={
            k: {
                "status": v.last_status,
                "last_run_at": v.last_run_at.isoformat() + "Z" if v.last_run_at else None,
                "error": v.last_error,
                "new": v.last_new_count,
            }
            for k, v in s["states"].items()
        },
    )


@bp.get("/ransomware/victims")
def ransomware_victims_api():
    limit = min(request.args.get("limit", 50, type=int), 500)
    rows = korea_victims(request.args).limit(limit).all()
    return jsonify(
        [
            {
                "victim": v.victim,
                "group": v.group,
                "domain": v.domain,
                "country": v.country,
                "activity": v.activity,
                "discovered": v.discovered.isoformat() + "Z" if v.discovered else None,
                "attack_date": v.attack_date.isoformat() + "Z" if v.attack_date else None,
                "korea_score": v.korea_score,
                "matches": v.match_list,
                "ransomware_live": v.rl_url,
            }
            for v in rows
        ]
    )


@bp.post("/cve/collect")
def cve_collect():
    trigger(["cve"], current_app._get_current_object())
    return jsonify(status="scheduled"), 202


@bp.get("/cves")
def cves_api():
    rows, idx = cve_list(request.args)
    return jsonify(
        [
            {
                "cve_id": c.cve_id,
                "priority": c.priority[1],
                "cvss_score": c.cvss_score,
                "cvss_severity": c.cvss_severity,
                "cvss_version": c.cvss_version,
                "epss": c.epss,
                "epss_percentile": c.epss_percentile,
                "in_kev": c.in_kev,
                "korea_vendor": c.korea_vendor,
                "nvd_status": c.nvd_status,
                "affected": c.affected_list,
                "mentions": idx[c.cve_id]["count"],
            }
            for c in rows
        ]
    )


@bp.get("/articles")
def articles():
    limit = min(request.args.get("limit", 50, type=int), 200)
    rows = filter_articles(request.args).limit(limit).all()
    return jsonify(
        [
            {
                "title": a.title,
                "url": a.url,
                "source": a.source.name,
                "region": a.source.region,
                "published_at": a.published_at.isoformat() + "Z" if a.published_at else None,
                "is_korea": a.is_korea,
                "is_nk_threat": a.is_nk_threat,
                "korea_score": a.korea_score,
                "matches": a.match_list,
                "cves": a.cve_list,
            }
            for a in rows
        ]
    )
