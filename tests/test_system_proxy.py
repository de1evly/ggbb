import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from pathfinder import system_proxy


class FakeRegistry:
    HKEY_CURRENT_USER = 0
    KEY_QUERY_VALUE = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self):
        self.values = {"ProxyEnable": (1, self.REG_DWORD), "AutoConfigURL": ("https://old.example/pac", self.REG_SZ)}

    def OpenKey(self, *args):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]

    def SetValueEx(self, key, name, reserved, kind, value):
        self.values[name] = (value, kind)

    def DeleteValue(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


class ProxySettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.registry = FakeRegistry()
        self.before = self.registry.values.copy()
        self.patches = [patch.dict('sys.modules', {'winreg': self.registry}),
                        patch.object(system_proxy, 'require_windows'),
                        patch.object(system_proxy, 'notify_windows')]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_round_trip_preserves_original_proxy(self):
        system_proxy.enable(self.root, 47831)
        self.assertEqual(self.registry.values['ProxyEnable'][0], 0)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, self.before)

    def test_repeated_enable_does_not_overwrite_backup(self):
        system_proxy.enable(self.root, 47831)
        original = (self.root / 'proxy-backup.json').read_bytes()
        system_proxy.enable(self.root, 47831)
        self.assertEqual(original, (self.root / 'proxy-backup.json').read_bytes())
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, self.before)

    def test_external_edit_is_not_overwritten_on_exit(self):
        system_proxy.enable(self.root, 47831)
        self.registry.values['AutoConfigURL'] = ('https://new.example/pac', 1)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values['AutoConfigURL'][0], 'https://new.example/pac')
        self.assertEqual(self.registry.values['ProxyEnable'], self.before['ProxyEnable'])

    def test_port_change_requires_restore_first(self):
        system_proxy.enable(self.root, 47831)
        with self.assertRaises(RuntimeError):
            system_proxy.enable(self.root, 47832)

    def test_absent_original_values_are_removed(self):
        self.registry.values = {}
        system_proxy.enable(self.root, 47831)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, {})


if __name__ == '__main__':
    unittest.main()
