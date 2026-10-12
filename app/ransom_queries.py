from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, or_

from .extensions import db
from .models import CollectorState, RansomVictim

KST_OFFSET = timedelta(hours=9)


def _month_labels(n):
    now = datetime.utcnow() + KST_OFFSET
    y, m = now.year, now.month
    out = []
    for _ in range(n):
        out.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    return list(reversed(out))


def ransomware_stats(months=24):
    now = datetime.utcnow()
    kr = RansomVictim.query.filter(RansomVictim.is_korea.is_(True))
    kr_rows = kr.with_entities(RansomVictim.discovered, RansomVictim.group, RansomVictim.activity).all()

    labels = _month_labels(months)
    monthly = Counter()
    year_start = datetime(now.year, 1, 1)
    this_year = last_30d = 0
    for discovered, _, _ in kr_rows:
        if not discovered:
            continue
        monthly[(discovered + KST_OFFSET).strftime("%Y-%m")] += 1
        this_year += discovered >= year_start
        last_30d += discovered >= now - timedelta(days=30)

    groups = Counter(g for _, g, _ in kr_rows).most_common(10)
    sectors = Counter((a or "미분류") for _, _, a in kr_rows).most_common(10)

    # 전 세계 최근 7일 (recentvictims 누적분 기준)
    since_7d = now - timedelta(days=7)
    global_7d = RansomVictim.query.filter(RansomVictim.discovered >= since_7d)
    global_7d_count = global_7d.count()
    kr_7d_count = global_7d.filter(RansomVictim.is_korea.is_(True)).count()
    global_groups = (
        global_7d.with_entities(RansomVictim.group, func.count(RansomVictim.id))
        .group_by(RansomVictim.group)
        .order_by(func.count(RansomVictim.id).desc())
        .limit(10)
        .all()
    )

    return {
        "kr_total": len(kr_rows),
        "kr_this_year": this_year,
        "kr_30d": last_30d,
        "kr_7d": kr_7d_count,
        "global_7d": global_7d_count,
        "monthly": {"labels": labels, "values": [monthly[l] for l in labels]},
        "kr_groups": groups,
        "kr_sectors": sectors,
        "global_groups": global_groups,
        "states": {s.key: s for s in CollectorState.query.all()},
    }


def korea_victims(args):
    q = RansomVictim.query.filter(RansomVictim.is_korea.is_(True))
    if args.get("group"):
        q = q.filter(RansomVictim.group == args["group"])
    if args.get("q"):
        like = f"%{args['q'].strip()}%"
        q = q.filter(or_(RansomVictim.victim.ilike(like), RansomVictim.domain.ilike(like),
                         RansomVictim.activity.ilike(like)))
    return q.order_by(RansomVictim.discovered.desc())


def korea_groups():
    return [
        g for (g,) in db.session.query(RansomVictim.group)
        .filter(RansomVictim.is_korea.is_(True)).distinct().order_by(RansomVictim.group)
    ]
