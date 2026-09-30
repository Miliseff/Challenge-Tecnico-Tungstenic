import json
from dataclasses import asdict

from ..models import Report


def to_dict(report: Report) -> dict:
    results = []
    for r in report.results:
        m = r.module
        results.append(
            {
                "id": m.id,
                "maswe": m.maswe,
                "masvs": m.masvs,
                "title": m.title,
                "severity": m.severity,
                "mode": m.mode,
                "status": r.status.value,
                "description": m.description,
                "impact": m.impact,
                "mitigation": m.mitigation,
                "references": m.references,
                "notes": r.notes,
                "absence": asdict(r.absence) if r.absence else None,
                "evidences": [asdict(e) for e in r.evidences],
                "dynamic": [asdict(o) for o in r.dynamic],
            }
        )
    return {
        "target": report.target,
        "started_at": report.started_at,
        "results": results,
    }


def render(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=False) + "\n"
