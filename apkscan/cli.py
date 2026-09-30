import argparse
import os
import sys
from pathlib import Path

from . import __version__
from . import dynamic
from .decompile import DecompileError, decompile, is_apk
from .dynamic.adb import Adb, AdbError
from .engine import scan
from .manifest import read_manifest
from .models import Status
from .nuclei import NucleiError, NucleiRunner
from .registry import RegistryError, discover, select
from .reporters import console, jsonout, markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apkscan",
        description="Analisis estatico de APKs contra tests del OWASP MASTG usando templates de nuclei.",
    )
    p.add_argument("target", nargs="?", help="archivo .apk o directorio con el codigo decompilado")
    p.add_argument("--md", metavar="ARCHIVO", help="guarda el reporte en markdown")
    p.add_argument("--json", metavar="ARCHIVO", help="guarda el reporte en json")
    p.add_argument("--only", nargs="+", metavar="TEST", help="corre solo estos modulos (ej: 0221 MASTG-TEST-0212)")
    p.add_argument("--skip", nargs="+", metavar="TEST", help="excluye estos modulos")
    p.add_argument("--modules-dir", action="append", type=Path, default=[], help="carpeta con modulos extra")
    p.add_argument("--list-modules", action="store_true", help="lista los modulos disponibles y sale")
    p.add_argument("--workdir", type=Path, default=Path(".apkscan-work"), help="donde se guarda lo decompilado")
    p.add_argument("--force", action="store_true", help="vuelve a decompilar aunque ya exista")
    p.add_argument("--nuclei", help="ruta al binario de nuclei")
    p.add_argument("--jadx", help="ruta al binario de jadx")
    p.add_argument("--dynamic", action="store_true", help="agrega la prueba dinamica con adb (emulador o dispositivo)")
    p.add_argument("--install", action="store_true", help="con --dynamic, instala el apk antes de probar")
    p.add_argument("--serial", help="serial del dispositivo adb")
    p.add_argument("--adb", help="ruta al binario de adb")
    p.add_argument("--settle", type=float, default=2.0, help="segundos de espera tras abrir cada activity")
    p.add_argument("--max-evidence", type=int, default=20, help="evidencias por modulo en consola")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"apkscan {__version__}")
    return p


def list_modules(modules) -> None:
    for m in modules:
        print(f"{m.id}  {m.maswe}  {m.mode:<8}  {m.severity:<8}  {m.title}")


def use_color(args) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


def resolve_source(args) -> Path:
    target = Path(args.target)
    if not target.exists():
        raise FileNotFoundError(f"no existe: {target}")
    if is_apk(target):
        print(f"Decompilando {target.name} con jadx...", file=sys.stderr)
        return decompile(target, args.workdir, args.jadx, args.force)
    if target.is_dir():
        return target
    raise FileNotFoundError(f"el objetivo debe ser un .apk o un directorio: {target}")


def run_dynamic(args, report, source: Path) -> None:
    if not dynamic.supported_ids(report):
        print("ningun modulo seleccionado tiene prueba dinamica", file=sys.stderr)
        return
    manifest = read_manifest(source)
    if manifest is None or not manifest.package:
        raise AdbError("no pude leer el package del AndroidManifest.xml")
    adb = Adb(args.adb, args.serial)
    if not adb.devices():
        raise AdbError("adb no ve ningun dispositivo o emulador conectado")
    target = Path(args.target)
    if args.install:
        if not is_apk(target):
            raise AdbError("--install necesita un .apk como objetivo")
        print(f"Instalando {target.name}...", file=sys.stderr)
        adb.install(target)
    print(f"Probando {len(manifest.activities)} activities de {manifest.package}...", file=sys.stderr)
    dynamic.run(report, adb, manifest.package, manifest.activities, args.settle)


def write_file(path: str, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")
    print(f"Reporte guardado en {path}", file=sys.stderr)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        modules = discover(args.modules_dir)
        if args.list_modules:
            list_modules(modules)
            return 0
        if not args.target:
            print("falta el objetivo (.apk o directorio). Usa --help.", file=sys.stderr)
            return 2
        modules = select(modules, args.only, args.skip)
        if not modules:
            print("no quedo ningun modulo para ejecutar", file=sys.stderr)
            return 2
        source = resolve_source(args)
        report = scan(source, modules, NucleiRunner(args.nuclei))
        report.target = args.target
        if args.dynamic:
            run_dynamic(args, report, source)
    except (RegistryError, DecompileError, NucleiError, AdbError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(console.render(report, use_color(args), args.max_evidence))
    if args.md:
        write_file(args.md, markdown.render(report))
    if args.json:
        write_file(args.json, jsonout.render(report))
    return 1 if any(r.status is Status.VULNERABLE for r in report.results) else 0
