import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from pathfinder import system_proxy
from pathfinder import __version__


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

    def test_versioned_pac_upgrade_preserves_original_backup(self):
        system_proxy.enable(self.root, 47831)
        backup = self.root / 'proxy-backup.json'
        old = json.loads(backup.read_text())
        old['installed']['AutoConfigURL']['value'] = 'http://127.0.0.1:47831/proxy.pac'
        backup.write_text(json.dumps(old))
        self.registry.values['AutoConfigURL'] = ('http://127.0.0.1:47831/proxy.pac', 1)
        system_proxy.enable(self.root, 47831)
        self.assertIn('?v=' + __version__, self.registry.values['AutoConfigURL'][0])
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, self.before)

    def test_absent_original_values_are_removed(self):
        self.registry.values = {}
        system_proxy.enable(self.root, 47831)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, {})

    def test_manual_https_proxy_and_ru_bypass_restore_all_four_values(self):
        self.registry.values['ProxyServer'] = ('http=old-proxy:8080', 1)
        self.registry.values['ProxyOverride'] = ('*.example.org', 1)
        before = self.registry.values.copy()
        system_proxy.enable(self.root, 47831, proxy_port=47830, direct_domains=['*.ru'])
        self.assertEqual(self.registry.values['ProxyEnable'][0], 1)
        self.assertEqual(self.registry.values['ProxyServer'][0], 'https=127.0.0.1:47830')
        self.assertIn('*.ru', self.registry.values['ProxyOverride'][0].split(';'))
        self.assertNotIn('vk.com', self.registry.values['ProxyOverride'][0])
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values, before)

    def test_old_two_value_backup_migrates_and_restores_new_proxy_values(self):
        system_proxy.enable(self.root, 47831)
        backup = self.root / 'proxy-backup.json'
        saved = json.loads(backup.read_text())
        for key in ('ProxyServer', 'ProxyOverride'):
            saved['before'].pop(key, None)
        backup.write_text(json.dumps(saved))
        self.registry.values['ProxyServer'] = ('https=old-proxy:443', 1)
        system_proxy.enable(self.root, 47831, proxy_port=47830, direct_domains=['*.ru'])
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values['ProxyServer'][0], 'https=old-proxy:443')
        self.assertEqual(self.registry.values['AutoConfigURL'], self.before['AutoConfigURL'])

    def test_external_manual_proxy_edit_is_preserved(self):
        system_proxy.enable(self.root, 47831, proxy_port=47830)
        self.registry.values['ProxyServer'] = ('https=new-proxy:443', 1)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values['ProxyServer'][0], 'https=new-proxy:443')
        self.assertEqual(self.registry.values['AutoConfigURL'], self.before['AutoConfigURL'])

    def test_manual_activation_preserves_changes_to_previously_unowned_fields(self):
        self.registry.values['ProxyServer'] = ('https=first-proxy:443', 1)
        system_proxy.enable(self.root, 47831)
        self.registry.values['ProxyServer'] = ('https=changed-while-pac-only:443', 1)
        system_proxy.enable(self.root, 47831, proxy_port=47830)
        system_proxy.disable(self.root)
        self.assertEqual(self.registry.values['ProxyServer'][0], 'https=changed-while-pac-only:443')


if __name__ == '__main__':
    unittest.main()
