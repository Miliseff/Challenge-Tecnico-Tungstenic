import textwrap

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

COLORS = {
    Status.VULNERABLE: "31",
    Status.REVIEW: "33",
    Status.PASSED: "32",
}
WIDTH = 100


def paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def wrap(text: str, indent: str = "  ") -> str:
    paragraphs = [p for p in text.split("\n\n")]
    out = [
        textwrap.fill(" ".join(p.split()), width=WIDTH, initial_indent=indent, subsequent_indent=indent)
        for p in paragraphs
    ]
    return "\n\n".join(out)


def render(report: Report, color: bool = False, max_evidence: int = 20) -> str:
    out = []
    bar = "=" * WIDTH
    out.append(bar)
    out.append(f"apkscan - {report.target}")
    out.append(f"Analisis iniciado: {report.started_at}")
    out.append(bar)
    for result in report.results:
        out.append("")
        out.append(render_result(result, color, max_evidence))
    totals = counts(report)
    out.append("")
    out.append(bar)
    out.append(
        f"Resumen: {totals[Status.VULNERABLE]} vulnerables, "
        f"{totals[Status.REVIEW]} a revisar, {totals[Status.PASSED]} sin hallazgos "
        f"(de {len(report.results)} modulos)"
    )
    return "\n".join(out)


def render_result(result, color: bool, max_evidence: int) -> str:
    m = result.module
    tag = paint(f"[{status_label(result)}]", COLORS[result.status], color)
    lines = [
        f"{tag} {m.id} / {m.maswe} / {m.masvs}  (severidad: {severity_label(result)})",
        f"Titulo: {m.title}",
        "",
        "Descripcion:",
        wrap(m.description),
        "",
    ]
    lines += render_evidence(result, max_evidence)
    lines += render_dynamic(result)
    lines += [f"Nota: {note}" for note in result.notes]
    if result.status is not Status.PASSED or result.module.mode == "absence":
        lines += ["", "Impacto:", wrap(m.impact), "", "Mitigacion:", wrap(m.mitigation)]
    if m.validation and result.status is not Status.PASSED:
        lines += ["", "Validacion manual:", wrap(m.validation)]
    lines.append("")
    lines.append("-" * WIDTH)
    return "\n".join(lines)


def render_dynamic(result) -> list[str]:
    if not result.dynamic:
        return []
    lines = ["", f"Prueba dinamica ({len(result.dynamic)} activities):"]
    for obs in result.dynamic:
        lines.append(f"  [{DYNAMIC_LABEL.get(obs.verdict, obs.verdict)}] {obs.target}")
        lines.append(f"     {obs.detail}")
    return lines


def render_evidence(result, max_evidence: int) -> list[str]:
    lines = []
    if result.absence is not None:
        lines.append("Evidencia (por ausencia):")
        lines += [f"  - {item}" for item in absence_summary(result.absence)]
        lines.append("  Patrones buscados:")
        lines += [f"    {p}" for p in result.absence.patterns]
        if result.absence.components:
            lines.append("  Activities sin proteccion detectada:")
            lines += [f"    {c}" for c in result.absence.components]
    if not result.evidences:
        if result.absence is None:
            lines.append("Evidencias: no se encontraron coincidencias.")
        return lines

    shown = result.evidences[:max_evidence]
    header = f"Evidencias ({len(result.evidences)}):"
    if result.absence is not None:
        header = f"Codigo que debilita la proteccion ({len(result.evidences)}):"
    lines.append(header)
    for n, ev in enumerate(shown, 1):
        lines.append(f"  #{n} [{ROLE_LABEL.get(ev.role, ev.role)}] {evidence_location(ev)}")
        lines.append(f"     regla: {ev.template_name}")
        for number, text in ev.context:
            marker = ">" if in_match(ev, number) else " "
            lines.append(f"     {marker} {number:>5} | {text.rstrip()}")
        if not ev.context and ev.match:
            lines.append(f"     > {ev.match}")
    hidden = len(result.evidences) - len(shown)
    if hidden > 0:
        lines.append(f"  ... y {hidden} evidencias mas (usa --md o --json para verlas todas)")
    return lines
