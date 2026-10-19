import time
import unittest

from mo_port_scan.utils import RateLimiter, expand_target, parse_ports, parse_targets, top_ports


class PortParsingTests(unittest.TestCase):
    def test_single_list_and_range(self):
        self.assertEqual(parse_ports("80"), [80])
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("1-3,10"), [1, 2, 3, 10])

    def test_all(self):
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_invalid(self):
        for bad in ("0", "70000", "10-5", "abc", ""):
            with self.assertRaises(ValueError, msg=bad):
                parse_ports(bad)

    def test_top_ports(self):
        self.assertEqual(len(top_ports(10)), 10)
        with self.assertRaises(ValueError):
            top_ports(0)


class TargetParsingTests(unittest.TestCase):
    def test_cidr(self):
        self.assertEqual(len(expand_target("192.168.1.0/30")), 2)

    def test_single_host_cidr(self):
        self.assertEqual(expand_target("10.0.0.5/32"), [("10.0.0.5", "10.0.0.5")])

    def test_last_octet_range(self):
        ips = [ip for _, ip in expand_target("10.0.0.1-3")]
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_full_range(self):
        self.assertEqual(len(expand_target("10.0.0.254-10.0.1.1")), 4)

    def test_ipv6_and_ip(self):
        self.assertEqual(expand_target("::1"), [("::1", "::1")])
        self.assertEqual(expand_target("127.0.0.1"), [("127.0.0.1", "127.0.0.1")])

    def test_localhost_resolves(self):
        label, ip = expand_target("localhost")[0]
        self.assertEqual(label, "localhost")
        self.assertIn(ip, ("127.0.0.1", "::1"))

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            expand_target("10.0.0.9-3")

    def test_too_large(self):
        with self.assertRaises(ValueError):
            expand_target("10.0.0.0/8")

    def test_exclude_and_dedupe(self):
        out = parse_targets(["10.0.0.1-5", "10.0.0.3"], exclude=["10.0.0.2", "10.0.0.4"])
        self.assertEqual([ip for _, ip in out], ["10.0.0.1", "10.0.0.3", "10.0.0.5"])


class RateLimiterTests(unittest.TestCase):
    def test_unlimited_is_instant(self):
        rl = RateLimiter(0)
        t = time.monotonic()
        for _ in range(100):
            rl.wait()
        self.assertLess(time.monotonic() - t, 0.5)

    def test_limited(self):
        rl = RateLimiter(50)  # 20 ms interval
        t = time.monotonic()
        for _ in range(6):
            rl.wait()
        self.assertGreaterEqual(time.monotonic() - t, 0.08)


if __name__ == "__main__":
    unittest.main()
