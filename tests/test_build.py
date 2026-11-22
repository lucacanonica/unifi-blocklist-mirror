import ipaddress
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def lines(path):
    return pathlib.Path(path).read_text().split()


class ParseTests(unittest.TestCase):
    def test_spamhaus_text_and_json(self):
        nets, header = build.parse((FIX / "spamhaus.txt").read_text())
        self.assertIn(ipaddress.ip_network("1.10.16.0/20"), nets[4])
        self.assertIn(ipaddress.ip_network("2.56.192.0/22"), nets[4])  # JSON line
        self.assertIn(ipaddress.ip_network("2a06:a80::/29"), nets[6])
        self.assertTrue(header[0].startswith("; Spamhaus DROP List"))

    def test_dshield_columns(self):
        nets, _ = build.parse((FIX / "dshield.txt").read_text(), "dshield")
        self.assertEqual(nets[4], {ipaddress.ip_network("45.142.193.0/24")})

    def test_garbage_and_too_wide_prefix_ignored(self):
        nets, _ = build.parse("0.0.0.0/0\nnot-an-ip\n999.1.1.1\n8.8.8.8 3\n")
        self.assertEqual(nets[4], {ipaddress.ip_network("8.8.8.8/32")})

    def test_reserved_ranges_removed_even_inside_supernet(self):
        got = build.clean({ipaddress.ip_network(n) for n in
                           ("10.0.0.0/8", "192.168.1.5/32", "192.0.0.0/8", "5.5.5.5/32")}, 4)
        self.assertIn(ipaddress.ip_network("5.5.5.5/32"), got)
        for net in got:
            for res in build.RESERVED[4]:
                self.assertFalse(net.overlaps(res), f"{net} overlaps {res}")
        # the public part of 192.0.0.0/8 survives
        self.assertTrue(any(ipaddress.ip_address("192.1.2.3") in n for n in got))

    def test_overlaps_merged(self):
        got = build.clean({ipaddress.ip_network(n) for n in
                           ("5.5.5.0/24", "5.5.5.7/32", "6.6.6.0/25", "6.6.6.128/25")}, 4)
        self.assertEqual([str(n) for n in got], ["5.5.5.0/24", "6.6.6.0/24"])


class BuildTests(unittest.TestCase):
    def sources(self, tmp, extra=()):
        src = [
            {"id": "a", "name": "A", "owner": "Owner A", "homepage": "h", "terms": "t",
             "license": "l", "urls": [(FIX / "spamhaus.txt").as_uri()], "combined": True},
            {"id": "d", "name": "D", "owner": "Owner D", "homepage": "h", "terms": "t",
             "license": "l", "urls": [(FIX / "dshield.txt").as_uri()],
             "parser": "dshield", "combined": True},
            {"id": "off", "name": "Off", "owner": "o", "homepage": "h", "terms": "t",
             "license": "l", "urls": ["file:///nonexistent"], "enabled": False},
            *extra,
        ]
        path = os.path.join(tmp, "sources.json")
        with open(path, "w") as fh:
            json.dump({"sources": src}, fh)
        return path

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "lists")
            self.assertEqual(build.build(self.sources(tmp), out), 0)
            plain, cidr = lines(f"{out}/a_v4.txt"), lines(f"{out}/a_v4_cidr.txt")
            self.assertIn("9.9.9.9", plain)          # host without prefix
            self.assertIn("9.9.9.9/32", cidr)        # host with prefix
            self.assertIn("1.10.16.0/20", plain)     # networks keep the prefix
            self.assertEqual(len(plain), len(cidr))
            self.assertFalse(any(c in open(f"{out}/a_v4.txt").read() for c in "#;"))
            self.assertIn("2a06:a80::/29", lines(f"{out}/a_v6.txt"))
            combined = lines(f"{out}/combined_v4.txt")
            self.assertIn("45.142.193.0/24", combined)
            self.assertIn("1.10.16.0/20", combined)
            self.assertFalse(os.path.exists(f"{out}/off_v4.txt"))
            notice = open(f"{out}/NOTICE.md").read()
            self.assertIn("Owner A", notice)
            self.assertIn("; Spamhaus DROP List", notice)

    def test_failed_source_keeps_previous_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "lists")
            build.build(self.sources(tmp), out)
            before = lines(f"{out}/a_v4.txt")
            broken = self.sources(tmp)
            data = json.load(open(broken))
            data["sources"][0]["urls"] = ["file:///nonexistent"]
            json.dump(data, open(broken, "w"))
            build.fetch.__defaults__ = (1,)  # no retries in the test
            self.assertEqual(build.build(broken, out), 0)
            self.assertEqual(lines(f"{out}/a_v4.txt"), before)
            status = json.load(open(f"{out}/status.json"))
            self.assertTrue(status["sources"]["a"]["stale"])
            self.assertIn("; Spamhaus DROP List", open(f"{out}/NOTICE.md").read())

    def test_split_over_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = set()
            old, build.MAX_ENTRIES = build.MAX_ENTRIES, 3
            try:
                nets = [ipaddress.ip_network(f"5.5.{i}.1/32") for i in range(7)]
                build.write_list(tmp, "x_v4", nets, written)
            finally:
                build.MAX_ENTRIES = old
            self.assertEqual(len(lines(f"{tmp}/x_v4.txt")), 7)
            self.assertEqual(len(lines(f"{tmp}/x_v4_part1.txt")), 3)
            self.assertEqual(len(lines(f"{tmp}/x_v4_part3.txt")), 1)


if __name__ == "__main__":
    unittest.main()
