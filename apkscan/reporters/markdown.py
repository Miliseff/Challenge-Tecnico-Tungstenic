from ..models import Report, Status
from .common import (
    DYNAMIC_LABEL,
    ROLE_LABEL,
    absence_summary,
    counts,
    evidence_location,
    in_match,
    severity_label,
    status_label,
)


def render(report: Report) -> str:
    totals = counts(report)
    out = [
        "# Reporte apkscan",
        "",
        f"- Objetivo: `{report.target}`",
        f"- Fecha: {report.started_at}",
        f"- Resultado: {totals[Status.VULNERABLE]} vulnerables, "
        f"{totals[Status.REVIEW]} a revisar, {totals[Status.PASSED]} sin hallazgos",
        "",
        "| Test | MASWE | Estado | Severidad | Evidencias |",
        "|---|---|---|---|---|",
    ]
    for r in report.results:
        shown = "ausencia" if r.absence is not None else len(r.evidences)
        out.append(
            f"| {r.module.id} | {r.module.maswe} | {status_label(r)} | "
            f"{severity_label(r)} | {shown} |"
        )
    for r in report.results:
        out.append("")
        out.append(render_result(r))
    return "\n".join(out) + "\n"


def render_result(result) -> str:
    m = result.module
    out = [
        f"## {m.id} - {m.title}",
        "",
        f"- Estado: **{status_label(result)}**",
        f"- MASWE: {m.maswe} / {m.masvs}",
        f"- Severidad: {severity_label(result)}",
        "",
        "### Descripcion",
        "",
        m.description,
        "",
        "### Evidencias",
        "",
    ]
    out += evidence_block(result)
    if result.dynamic:
        out += ["", "### Prueba dinamica", "", "| Activity | Resultado | Detalle |", "|---|---|---|"]
        for obs in result.dynamic:
            out.append(f"| `{obs.target}` | {DYNAMIC_LABEL.get(obs.verdict, obs.verdict)} | {obs.detail} |")
    if result.notes:
        out += [""] + [f"> {n}" for n in result.notes]
    if result.status is not Status.PASSED or m.mode == "absence":
        out += ["", "### Impacto", "", m.impact, "", "### Mitigacion", "", m.mitigation]
    if m.validation and result.status is not Status.PASSED:
        out += ["", "### Validacion manual", "", m.validation]
    if m.references:
        out += ["", "### Referencias", ""] + [f"- {ref}" for ref in m.references]
    return "\n".join(out)


def evidence_block(result) -> list[str]:
    out = []
    if result.absence is not None:
        out.append("Evidencia por ausencia: el analisis no encontro la proteccion esperada.")
        out.append("")
        out += [f"- {item}" for item in absence_summary(result.absence)]
        out += ["", "Patrones buscados:", "", "```text"] + result.absence.patterns + ["```"]
        if result.absence.components:
            out += ["", "Activities declaradas sin proteccion detectada:", ""]
            out += [f"- `{c}`" for c in result.absence.components]
    if not result.evidences:
        if result.absence is None:
            out.append("No se encontraron coincidencias.")
        return out

    if result.absence is not None:
        out += ["", "Codigo que debilita la proteccion:"]
    for n, ev in enumerate(result.evidences, 1):
        out += [
            "",
            f"**#{n}** `{evidence_location(ev)}` ({ROLE_LABEL.get(ev.role, ev.role)}) - {ev.template_name}",
            "",
            "```java",
        ]
        if ev.context:
            for number, text in ev.context:
                marker = ">" if in_match(ev, number) else " "
                out.append(f"{marker} {number:>5} | {text.rstrip()}")
        else:
            out.append(ev.match)
        out.append("```")
    return out
