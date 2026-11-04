import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("live_keymap", Path(__file__).resolve().parents[1] / "live-os/keymap.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DebianKeyboardSettings(unittest.TestCase):
    def test_debian_assignments_preserve_layout_variant_and_options(self):
        settings = module.settings('''# Debian keyboard-configuration
XKBMODEL="pc105"
XKBLAYOUT='it,us'
XKBVARIANT=,intl
XKBOPTIONS="compose:ralt,grp:alt_shift_toggle" # chosen in Debian
BACKSPACE="guess"
''')
        self.assertEqual(settings, {"XKBMODEL": "pc105", "XKBLAYOUT": "it,us", "XKBVARIANT": ",intl", "XKBOPTIONS": "compose:ralt,grp:alt_shift_toggle"})

    def test_empty_assignments_and_comments_are_valid_debian_values(self):
        settings = module.settings('XKBLAYOUT="it"\nXKBVARIANT=\nXKBOPTIONS= # none\n')
        self.assertEqual(settings["XKBMODEL"], "pc105")
        self.assertEqual(settings["XKBLAYOUT"], "it")
        self.assertEqual(settings["XKBVARIANT"], "")
        self.assertEqual(settings["XKBOPTIONS"], "")

    def test_configuration_is_never_executed_as_shell_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "executed"
            with self.assertRaises(ValueError):
                module.settings('XKBLAYOUT="$(touch ' + str(marker) + ')"\n')
            self.assertFalse(marker.exists())
        for value in ('XKBLAYOUT="--include"', 'XKBOPTIONS="us\nother"', 'XKBLAYOUT="us" "other"', 'XKBLAYOUT="unfinished'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.settings(value)

    def test_oversized_or_binary_configuration_is_rejected(self):
        for value in ('XKBLAYOUT="' + 'a' * 1025 + '"', '#' * 16385, 'XKBLAYOUT="it\0"'):
            with self.assertRaises(ValueError):
                module.settings(value)
