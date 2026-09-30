from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Status(str, Enum):
    VULNERABLE = "VULNERABLE"
    REVIEW = "REVIEW"
    PASSED = "PASSED"


@dataclass
class TemplateInfo:
    id: str
    name: str
    role: str
    patterns: list[str]
    extensions: list[str]
    path: Path


@dataclass
class ModuleSpec:
    id: str
    title: str
    maswe: str
    masvs: str
    severity: str
    mode: str
    description: str
    impact: str
    mitigation: str
    validation: str
    references: list[str]
    path: Path
    templates: list[TemplateInfo] = field(default_factory=list)

    @property
    def templates_dir(self) -> Path:
        return self.path / "templates"

    def templates_with_role(self, role: str) -> list[TemplateInfo]:
        return [t for t in self.templates if t.role == role]


@dataclass
class Hit:
    template_id: str
    file: Path
    extracted: list[str]


@dataclass
class Evidence:
    file: str
    line: int | None
    end_line: int | None
    match: str
    template_id: str
    template_name: str
    role: str
    context: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class AbsenceProof:
    patterns: list[str]
    files_scanned: int
    components: list[str]
    manifest: str | None


@dataclass
class DynamicObservation:
    target: str
    verdict: str
    detail: str


@dataclass
class ModuleResult:
    module: ModuleSpec
    status: Status
    evidences: list[Evidence]
    absence: AbsenceProof | None = None
    notes: list[str] = field(default_factory=list)
    dynamic: list[DynamicObservation] = field(default_factory=list)


@dataclass
class Report:
    target: str
    source_root: str
    started_at: str
    results: list[ModuleResult]
