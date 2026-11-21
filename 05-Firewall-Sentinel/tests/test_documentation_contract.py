#!/usr/bin/python3 -I
"""Release checks: command/flag docs, bilingual layout, checksum integrity and privacy."""
import hashlib
import pathlib
import re
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]


class DocumentationContract(unittest.TestCase):
    def setUp(self):
        self.code = (BASE / 'aegis-firewall-sentinel.py').read_text(encoding='utf-8')
        self.en_tr = (BASE / 'README.md').read_text(encoding='utf-8')
        self.ar = (BASE / 'README_AR.md').read_text(encoding='utf-8')

    def test_entire_parser_documented(self):
        subcommands = set(re.findall(r'sub\.add_parser\("([^"]+)"', self.code))
        flags = set(re.findall(r'\.add_argument\("(--[\w-]+)"', self.code))
        self.assertGreaterEqual(len(subcommands), 25)
        self.assertGreaterEqual(len(flags), 25)
        for title, body in [('README.md', self.en_tr), ('README_AR.md', self.ar)]:
            for cmd in subcommands:
                self.assertRegex(body, re.escape(cmd), title + ': ' + cmd)
            for flag in flags:
                self.assertIn(flag, body, title + ': ' + flag)

    def test_layout_and_arabic_language(self):
        self.assertGreaterEqual(self.en_tr.count('<table>'), 40)
        self.assertEqual(self.en_tr.count('<table>'), self.en_tr.count('</table>'))
        self.assertIn('ENGLISH 🇬🇧', self.en_tr)
        self.assertIn('TÜRKÇE 🇹🇷', self.en_tr)
        self.assertIn('README_AR.md', self.en_tr)
        self.assertGreater(len(re.findall(r'[\u0600-\u06FF]', self.ar)), 1000)
        self.assertIn('COMMITTED:', self.ar)
        self.assertIn('VERIFIED:', self.ar)

    def test_private_machine_identity_not_published(self):
        # Generalized privacy guards: no actual user home, hardware-specific Wi-Fi
        # interface identifiers or private connection UUID in tracked text.
        patterns = (
            r'/home/[a-zA-Z0-9_.-]+/',
            r'\bwlp\d+s\d+f\d+\b',
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        )
        for path in BASE.rglob('*'):
            if not path.is_file() or path.name == 'SHA256SUMS' or '__pycache__' in path.parts:
                continue
            for pattern in patterns:
                if 'tests' in path.relative_to(BASE).parts and '0-9a-f' in pattern:
                    continue  # static test fixtures intentionally contain synthetic UUIDs
                self.assertIsNone(re.search(pattern, path.read_text(encoding='utf-8')),
                                  path.as_posix() + ' pattern=' + pattern)

    def test_reboot_evidence_and_limitations(self):
        self.assertIn('Post-reboot', self.en_tr)
        self.assertIn('0 loaded units listed', self.en_tr)
        self.assertIn('not field', self.en_tr.lower())
        self.assertIn('لم تُختبر الطباعة', self.ar)

    def test_checksum_manifest(self):
        listing = (BASE / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        self.assertGreaterEqual(len(listing), 15)
        for line in listing:
            digest, relpath = line.split('  ', 1)
            path = BASE / relpath
            self.assertTrue(path.is_file(), relpath)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, relpath)


if __name__ == '__main__':
    unittest.main(verbosity=2)
