import re

from flask import Blueprint, abort, render_template, request

from ..alerts.slack import KIND_LABEL
from ..cve_queries import cve_list, cve_stats, cves_by_id, related_articles
from ..extensions import db
from ..models import Alert, KevEntry, Source
from ..queries import dashboard_stats, filter_articles, situation_24h
from ..ransom_queries import korea_groups, korea_victims, ransomware_stats

bp = Blueprint("dashboard", __name__)

PER_PAGE = 20


@bp.route("/")
def index():
    rs = ransomware_stats()
    stats = dashboard_stats()
    return render_template(
        "dashboard.html",
        stats=stats,
        situation=situation_24h(),
        cve_map=cves_by_id(c for c, _ in stats["top_cves"]),
        rstats=rs,
        alerts=Alert.query.filter(Alert.status != "ignored", Alert.severity.in_(("critical", "high")))
        .order_by((Alert.status == "new").desc(), Alert.event_at.desc()).limit(10).all(),
        kind_labels=KIND_LABEL,
        articles=filter_articles({}).limit(12).all(),
    )


@bp.route("/news")
def news():
    return render_template("news.html", sources=Source.query.order_by(Source.name).all())


@bp.route("/partials/feed")
def feed_partial():
    page = request.args.get("page", 1, type=int)
    pagination = filter_articles(request.args).paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("partials/feed.html", pagination=pagination, args=request.args)


@bp.route("/ransomware")
def ransomware():
    return render_template("ransomware.html", rstats=ransomware_stats(), groups=korea_groups())


@bp.route("/partials/ransom-victims")
def ransom_victims_partial():
    page = request.args.get("page", 1, type=int)
    pagination = korea_victims(request.args).paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_template("partials/ransom_victims.html", pagination=pagination, args=request.args)


CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@bp.route("/cve")
def cves():
    return render_template("cve.html", cstats=cve_stats())


@bp.route("/partials/cve-list")
def cve_list_partial():
    rows, idx = cve_list(request.args)
    return render_template("partials/cve_list.html", rows=rows, idx=idx)


@bp.route("/cve/<cve_id>")
def cve_detail(cve_id):
    from ..collectors.cve_enrich import enrich_one

    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        abort(404)
    cve = enrich_one(cve_id)  # 처음 보는 CVE면 NVD/EPSS 즉시 조회
    return render_template(
        "cve_detail.html",
        cve=cve,
        kev=db.session.get(KevEntry, cve_id),
        articles=related_articles(cve_id),
    )
