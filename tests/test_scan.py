import json
import re
import tempfile
import unittest
from pathlib import Path

from apkscan.engine import scan
from apkscan.models import Status
from apkscan.registry import discover, select
from apkscan.reporters import console, jsonout, markdown

from .nuclei_sim import SimulatedNuclei

FIXTURES = Path(__file__).parent / "fixtures"
ALL = discover()


def run(fixture: str, only=None):
    modules = select(ALL, only, None)
    return scan(FIXTURES / fixture, modules, SimulatedNuclei())


def result(report, test_id):
    return next(r for r in report.results if r.module.id == test_id)


def line_of(fixture_file: Path, needle: str) -> int:
    for number, text in enumerate(fixture_file.read_text(encoding="utf-8").splitlines(), 1):
        if needle in text:
            return number
    raise AssertionError(needle)


WEAK = FIXTURES / "crypto_bad/sources/com/example/vault/WeakCrypto.java"
KEYS = FIXTURES / "crypto_bad/sources/com/example/vault/HardcodedKeys.java"


class WeakAlgorithms(unittest.TestCase):
    def setUp(self):
        self.res = result(run("crypto_bad", ["0221"]), "MASTG-TEST-0221")

    def test_is_vulnerable(self):
        self.assertIs(self.res.status, Status.VULNERABLE)

    def test_finds_each_algorithm_with_its_line(self):
        found = {(e.file.split("/")[-1], e.line) for e in self.res.evidences}
        for needle in ('getInstance("DES")', 'getInstance("RC4")', 'getInstance("Blowfish")', 'getInstance("DESede")'):
            self.assertIn(("WeakCrypto.java", line_of(WEAK, needle)), found, needle)

    def test_des_with_mode_and_keyspec(self):
        lines = {e.line for e in self.res.evidences}
        self.assertIn(line_of(WEAK, "DES/CBC/PKCS5Padding"), lines)
        self.assertIn(line_of(WEAK, "new DESKeySpec"), lines)

    def test_evidence_carries_context(self):
        ev = next(e for e in self.res.evidences if 'getInstance("RC4"' in e.match)
        self.assertTrue(any(n == ev.line and "RC4" in text for n, text in ev.context))

    def test_safe_code_is_clean(self):
        clean = result(run("crypto_ok", ["0221"]), "MASTG-TEST-0221")
        self.assertIs(clean.status, Status.PASSED)
        self.assertEqual(clean.evidences, [])


class EncryptionModes(unittest.TestCase):
    def setUp(self):
        self.res = result(run("crypto_bad", ["0232"]), "MASTG-TEST-0232")

    def test_explicit_and_implicit_ecb(self):
        lines = {e.line for e in self.res.evidences}
        self.assertEqual(
            lines,
            {line_of(WEAK, "AES/ECB/PKCS5Padding"), line_of(WEAK, 'getInstance("AES")')},
        )

    def test_rsa_ecb_is_not_reported(self):
        self.assertFalse(any("RSA" in e.match for e in self.res.evidences))

    def test_gcm_is_clean(self):
        clean = result(run("crypto_ok", ["0232"]), "MASTG-TEST-0232")
        self.assertIs(clean.status, Status.PASSED)


class HardcodedKeys(unittest.TestCase):
    def setUp(self):
        self.res = result(run("crypto_bad", ["0212"]), "MASTG-TEST-0212")
        self.lines = {e.line for e in self.res.evidences}

    def test_is_vulnerable(self):
        self.assertIs(self.res.status, Status.VULNERABLE)

    def test_byte_array_and_its_use(self):
        self.assertIn(line_of(KEYS, "byte[] keyBytes"), self.lines)
        self.assertIn(line_of(KEYS, "new SecretKeySpec(keyBytes"), self.lines)

    def test_inline_literal(self):
        self.assertIn(line_of(KEYS, "s3cr3t-k3y-inline"), self.lines)

    def test_string_literal_variable(self):
        self.assertIn(line_of(KEYS, "0123456789abcdef"), self.lines)

    def test_base64_literal(self):
        self.assertIn(line_of(KEYS, "c2VjcmV0LWtleS1mb3ItdGVzdGluZw=="), self.lines)

    def test_derived_key_is_clean(self):
        clean = result(run("crypto_ok", ["0212"]), "MASTG-TEST-0212")
        self.assertIs(clean.status, Status.PASSED)


class ScreenCapture(unittest.TestCase):
    def test_absence_is_reported_as_vulnerable(self):
        res = result(run("screen_unprotected", ["0291"]), "MASTG-TEST-0291")
        self.assertIs(res.status, Status.VULNERABLE)
        self.assertEqual(res.evidences, [])
        self.assertIsNotNone(res.absence)

    def test_absence_proof_content(self):
        proof = result(run("screen_unprotected", ["0291"]), "MASTG-TEST-0291").absence
        self.assertEqual(proof.files_scanned, 2)
        self.assertEqual(
            sorted(proof.components),
            ["com.example.vault.LoginActivity", "com.example.vault.ui.BalanceActivity"],
        )
        self.assertEqual(proof.manifest, "resources/AndroidManifest.xml")
        self.assertTrue(any("FLAG_SECURE" in p for p in proof.patterns))

    def test_numeric_flag_counts_as_protection(self):
        res = result(run("screen_protected", ["0291"]), "MASTG-TEST-0291")
        self.assertIs(res.status, Status.PASSED)
        self.assertIsNone(res.absence)
        path = FIXTURES / "screen_protected/sources/com/example/vault/LoginActivity.java"
        self.assertEqual([e.line for e in res.evidences], [line_of(path, "addFlags(8192)")])

    def test_cleared_flag_needs_review(self):
        res = result(run("screen_cleared", ["0291"]), "MASTG-TEST-0291")
        self.assertIs(res.status, Status.REVIEW)
        roles = {e.role for e in res.evidences}
        self.assertEqual(roles, {"protection", "weakening"})

    def test_only_clear_is_still_vulnerable(self):
        path = FIXTURES / "screen_cleared/sources/com/example/vault/LoginActivity.java"
        text = path.read_text(encoding="utf-8").replace("getWindow().setFlags", "getWindow().noop")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sources/com/example/vault/LoginActivity.java"
            target.parent.mkdir(parents=True)
            target.write_text(text, encoding="utf-8")
            report = scan(Path(tmp), select(ALL, ["0291"], None), SimulatedNuclei())
        res = result(report, "MASTG-TEST-0291")
        self.assertIs(res.status, Status.VULNERABLE)
        self.assertEqual([e.role for e in res.evidences], ["weakening"])


class Reporters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run("crypto_bad")
        cls.report.target = "sample.apk"
        cls.absent = run("screen_unprotected", ["0291"])

    def test_console_has_required_sections(self):
        text = console.render(self.report)
        for piece in ("Titulo:", "Descripcion:", "Evidencias (", "Impacto:", "Mitigacion:", "WeakCrypto.java:"):
            self.assertIn(piece, text)

    def test_console_shows_absence_evidence(self):
        text = console.render(self.absent)
        self.assertIn("Evidencia (por ausencia)", text)
        self.assertIn("Patrones buscados", text)
        self.assertIn("com.example.vault.ui.BalanceActivity", text)

    def test_console_limits_evidence(self):
        text = console.render(self.report, max_evidence=1)
        self.assertRegex(text, r"y \d+ evidencias mas")

    def test_markdown(self):
        text = markdown.render(self.report)
        self.assertTrue(text.startswith("# Reporte apkscan"))
        self.assertIn("```java", text)
        self.assertRegex(text, r"`[^`]*WeakCrypto\.java:\d+`")

    def test_json_roundtrip(self):
        data = json.loads(jsonout.render(self.report))
        ids = [r["id"] for r in data["results"]]
        self.assertEqual(ids, sorted(ids))
        weak = next(r for r in data["results"] if r["id"] == "MASTG-TEST-0221")
        self.assertEqual(weak["status"], "VULNERABLE")
        self.assertTrue(all(isinstance(e["line"], int) for e in weak["evidences"]))

    def test_no_ansi_without_color(self):
        self.assertIsNone(re.search(r"\x1b\[", console.render(self.report, color=False)))


if __name__ == "__main__":
    unittest.main()
