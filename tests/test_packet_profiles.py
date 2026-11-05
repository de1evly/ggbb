import tempfile
import unittest
from pathlib import Path

from pathfinder.packet_profiles import PROFILES, PROFILE_VERSION, build_args


def branches(arguments):
    groups = [[]]
    for argument in arguments:
        if argument == "--new":
            groups.append([])
        else:
            groups[-1].append(argument)
    return groups


class PacketProfilesTests(unittest.TestCase):
    def test_every_profile_limits_protocols_and_excludes_ru_in_each_branch(self):
        self.assertEqual(list(PROFILES), ["alt1", "alt2", "alt3", "alt4"])
        self.assertTrue(PROFILE_VERSION)
        for profile_id in PROFILES:
            with self.subTest(profile=profile_id):
                args = build_args("/tmp/packet runtime", profile_id)
                self.assertIn("--wf-tcp-out=80,443,8443,8080", args)
                self.assertIn("--wf-udp-out=443", args)
                self.assertIn("--wf-filter-lan=1", args)
                self.assertIn("--ipcache-hostname=0", args)
                self.assertNotIn("--wf-tcp-empty=1", args)
                groups = branches(args)
                self.assertEqual(len(groups), 3)
                for group, protocol, payload in zip(groups, ("http", "tls", "quic"),
                                                    ("http_req", "tls_client_hello", "quic_initial")):
                    self.assertIn("--hostlist-exclude-domains=ru", group)
                    self.assertIn("--filter-l7=" + protocol, group)
                    self.assertIn("--payload=" + payload, group)
                    self.assertTrue(any(arg.startswith("--out-range=-d") for arg in group))
                self.assertIn("--filter-tcp=80", groups[0])
                self.assertIn("--filter-tcp=443,8443,8080", groups[1])
                self.assertIn("--filter-udp=443", groups[2])

    def test_unknown_and_exact_patterns_are_not_wildcarded(self):
        args = build_args("/tmp/runtime", "alt1", ["*.ru", "example.com", "*.cdn.net", "*.su"])
        expected = "--hostlist-exclude-domains=ru,^example.com,cdn.net,su"
        self.assertEqual(args.count(expected), 3)
        # A literal top-level entry 'ru' uses the upstream dot-label matcher;
        # '*ru', suffix globs and a catch-all unknown profile are never emitted.
        self.assertFalse(any("*ru" in value or "evilru" in value for value in args))
        self.assertFalse(any("unknown" in value or "--filter-l7=all" in value for value in args))

    def test_ru_is_mandatory_with_empty_or_custom_exclusions(self):
        for patterns in (None, [], ["example.com"], ["*.ru", "*.ru"]):
            args = build_args("/tmp/runtime", "alt1", patterns)
            for value in args:
                if value.startswith("--hostlist-exclude-domains="):
                    self.assertEqual(value.split("=", 1)[1].split(",")[0], "ru")
                    self.assertEqual(value.split("=", 1)[1].split(",").count("ru"), 1)

    def test_rejects_untrusted_or_ambiguous_patterns(self):
        for pattern in ("*", "*ru", "*.com", "bad.com,ru", "^bad.com", "bad.com:443",
                        "https://example.com", "example.com ", "EXAMPLE.com", "127.0.0.1",
                        "--lua-init=bad.com", "*.local", "bad.com\nru", None):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                build_args("/tmp/runtime", "alt1", [pattern])
        for patterns in ("*.ru", {}, ["*.ru"] * 257):
            with self.subTest(patterns=type(patterns)), self.assertRaises(ValueError):
                build_args("/tmp/runtime", "alt1", patterns)

    def test_fixed_candidates_differ_and_fooling_only_affects_fake_packets(self):
        commands = [build_args("/tmp/runtime", profile) for profile in PROFILES]
        self.assertEqual(len({tuple(command) for command in commands}), 4)
        for command in commands:
            for value in command:
                if "tcp_md5" in value or "tcp_seq" in value:
                    self.assertTrue(value.startswith("--lua-desync=fake:"))
        self.assertFalse(any("fake_default_tls" in arg for arg in commands[0]))
        self.assertFalse(any("fake_default_tls" in arg for arg in commands[1]))
        self.assertIn("--lua-desync=multisplit:pos=1,midsld", commands[0])
        self.assertIn("--lua-desync=multidisorder:pos=1,midsld", commands[1])
        self.assertIn("--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=2", commands[2])
        self.assertIn("--lua-desync=fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000:repeats=6", commands[3])

    def test_only_required_lua_files_and_no_shell_quoting(self):
        with tempfile.TemporaryDirectory(prefix="packet runtime ") as directory:
            args = build_args(directory, "alt1")
            lua = [arg for arg in args if arg.startswith("--lua-init=")]
            self.assertEqual(lua, ["--lua-init=@" + str(Path(directory).resolve() / "lua" / name)
                                   for name in ("zapret-lib.lua", "zapret-antidpi.lua")])
            self.assertFalse(any(Path(directory).iterdir()))
            self.assertFalse(any('"' in arg for arg in args))

    def test_rejects_unknown_profile_without_emitting_arguments(self):
        for value in ("unknown", "alt5", "ALT1", "alt1 --debug=1", None, {}):
            with self.subTest(profile=value), self.assertRaises(ValueError):
                build_args("/tmp/runtime", value)


if __name__ == "__main__":
    unittest.main()
