import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apkscan import cli
from apkscan.nuclei import NucleiError, NucleiRunner, parse_jsonl
from apkscan.registry import RegistryError, discover, select

FIXTURES = Path(__file__).parent / "fixtures"


class Registry(unittest.TestCase):
    def test_loads_builtin_modules(self):
        ids = [m.id for m in discover()]
        self.assertEqual(ids, ["MASTG-TEST-0212", "MASTG-TEST-0221", "MASTG-TEST-0232", "MASTG-TEST-0291"])

    def test_every_regex_compiles(self):
        for module in discover():
            for template in module.templates:
                for pattern in template.patterns:
                    re.compile(pattern)

    def test_absence_module_has_protection_templates(self):
        module = next(m for m in discover() if m.id == "MASTG-TEST-0291")
        self.assertEqual(module.mode, "absence")
        self.assertTrue(module.templates_with_role("protection"))
        self.assertTrue(module.templates_with_role("weakening"))

    def test_select_accepts_short_ids(self):
        chosen = select(discover(), ["221", "0212"], None)
        self.assertEqual([m.id for m in chosen], ["MASTG-TEST-0212", "MASTG-TEST-0221"])

    def test_select_skip(self):
        chosen = select(discover(), None, ["0291"])
        self.assertEqual(len(chosen), 3)

    def test_select_unknown(self):
        with self.assertRaises(RegistryError):
            select(discover(), ["9999"], None)

    def test_extra_module_is_picked_up_and_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "custom"
            (folder / "templates").mkdir(parents=True)
            (folder / "module.yaml").write_text(
                "id: CUSTOM-1\ntitle: t\nmaswe: M\nseverity: low\nmode: presence\n"
                "description: d\nimpact: i\nmitigation: m\n",
                encoding="utf-8",
            )
            (folder / "templates" / "t.yaml").write_text(
                "id: custom-1-t\ninfo:\n  name: n\n  author: a\n  severity: low\n"
                "file:\n  - extensions: [java]\n    matchers:\n      - type: regex\n        regex: ['foo']\n",
                encoding="utf-8",
            )
            self.assertIn("CUSTOM-1", [m.id for m in discover([Path(tmp)])])
            (folder / "module.yaml").write_text(
                (folder / "module.yaml").read_text(encoding="utf-8") + "enabled: false\n", encoding="utf-8"
            )
            self.assertNotIn("CUSTOM-1", [m.id for m in discover([Path(tmp)])])

    def test_incomplete_module_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "broken"
            folder.mkdir()
            (folder / "module.yaml").write_text("id: X\n", encoding="utf-8")
            with self.assertRaises(RegistryError):
                discover([Path(tmp)])


class NucleiParsing(unittest.TestCase):
    def test_parse_jsonl(self):
        line = json.dumps(
            {
                "template-id": "mastg-0221-weak-algorithm",
                "matched-at": str(FIXTURES / "crypto_bad/sources/com/example/vault/WeakCrypto.java"),
                "extracted-results": ['Cipher.getInstance("RC4")'],
                "type": "file",
            }
        )
        hits = parse_jsonl("[INF] banner\n" + line + "\n\n", FIXTURES / "crypto_bad")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].template_id, "mastg-0221-weak-algorithm")
        self.assertEqual(hits[0].extracted, ['Cipher.getInstance("RC4")'])
        self.assertTrue(hits[0].file.exists())

    def test_relative_match_path_is_resolved_against_target(self):
        line = json.dumps({"template-id": "x", "matched-at": "sources/com/example/vault/WeakCrypto.java"})
        hits = parse_jsonl(line, FIXTURES / "crypto_bad")
        self.assertTrue(hits[0].file.exists())

    def test_ignores_garbage(self):
        self.assertEqual(parse_jsonl("{not json}\nplain text", Path(".")), [])

    def test_command_layout(self):
        runner = NucleiRunner("nuclei")
        cmd = runner.command([Path("a"), Path("b")], Path("src"))
        self.assertEqual(cmd[0], "nuclei")
        self.assertEqual(cmd.count("-t"), 2)
        self.assertIn("-jsonl", cmd)
        self.assertEqual(cmd[cmd.index("-target") + 1], "src")

    def test_missing_binary(self):
        with mock.patch("apkscan.nuclei.shutil.which", return_value=None), mock.patch.dict(
            os.environ, {}, clear=True
        ):
            with self.assertRaises(NucleiError):
                NucleiRunner().run([Path("a")], Path("src"))


class Cli(unittest.TestCase):
    def test_list_modules(self):
        self.assertEqual(cli.main(["--list-modules"]), 0)

    def test_requires_target(self):
        self.assertEqual(cli.main([]), 2)

    def test_missing_target(self):
        self.assertEqual(cli.main(["no-existe-este-directorio"]), 2)

    def test_unknown_module(self):
        self.assertEqual(cli.main([str(FIXTURES), "--only", "9999"]), 2)

    def test_exit_code_and_reports(self):
        from .nuclei_sim import SimulatedNuclei

        with tempfile.TemporaryDirectory() as tmp, mock.patch("apkscan.cli.NucleiRunner", lambda _b: SimulatedNuclei()):
            md, js = Path(tmp) / "r.md", Path(tmp) / "r.json"
            code = cli.main([str(FIXTURES / "crypto_bad"), "--md", str(md), "--json", str(js), "--no-color"])
            self.assertEqual(code, 1)
            self.assertIn("MASTG-TEST-0221", md.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(js.read_text(encoding="utf-8"))["target"], str(FIXTURES / "crypto_bad"))
            clean = cli.main(["--only", "0212,0221", "--only", "0232", str(FIXTURES / "crypto_ok"), "--no-color"])
            self.assertEqual(clean, 0)
            self.assertEqual(cli.main([str(FIXTURES / "crypto_ok"), "--no-color"]), 1)


if __name__ == "__main__":
    unittest.main()
