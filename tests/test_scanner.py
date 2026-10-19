import json
import os
import socket
import tempfile
import threading
import unittest

from mo_port_scan.cli import main
from mo_port_scan.scanner import Scanner, host_alive, probe_tcp, probe_udp
from mo_port_scan.reporters import write_report


def free_tcp_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TcpServer:
    """Tiny TCP server that sends a greeting and closes."""

    def __init__(self, greeting=b"SSH-2.0-OpenSSH_9.6\r\n"):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.greeting = greeting
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.sendall(self.greeting)
            except OSError:
                pass
            finally:
                conn.close()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class UdpEchoServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(1024)
                self.sock.sendto(b"pong" + data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.sock.close()
        self._thread.join(timeout=2)


class TcpTests(unittest.TestCase):
    def test_open_port_detected(self):
        with TcpServer() as srv:
            res = probe_tcp("127.0.0.1", srv.port, 1.0, retries=0)
            self.assertIsNotNone(res)
            self.assertEqual(res.state, "open")

    def test_closed_port_not_reported(self):
        self.assertIsNone(probe_tcp("127.0.0.1", free_tcp_port(), 0.5, retries=0))

    def test_banner_and_service_detection(self):
        with TcpServer() as srv:
            res = probe_tcp("127.0.0.1", srv.port, 1.0, retries=0, banner=True)
            self.assertEqual(res.service, "ssh")
            self.assertEqual(res.version, "OpenSSH_9.6")
            self.assertTrue(res.banner.startswith("SSH-2.0"))

    def test_host_alive_localhost(self):
        self.assertTrue(host_alive("127.0.0.1", 0.5))

    def test_scanner_multi_port(self):
        with TcpServer() as a, TcpServer() as b:
            closed = free_tcp_port()
            scanner = Scanner([a.port, b.port, closed], threads=10, timeout=0.5, retries=0,
                              randomize=True, skip_discovery=True)
            hosts = list(scanner.scan([("127.0.0.1", "127.0.0.1")]))
            self.assertEqual(len(hosts), 1)
            self.assertEqual(sorted(p.port for p in hosts[0].ports), sorted([a.port, b.port]))


class UdpTests(unittest.TestCase):
    def test_udp_open(self):
        with UdpEchoServer() as srv:
            res = probe_udp("127.0.0.1", srv.port, 1.0, retries=0)
            self.assertIsNotNone(res)
            self.assertEqual(res.state, "open")

    def test_udp_closed(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertIsNone(probe_udp("127.0.0.1", port, 0.5, retries=0))


class CliAndReportTests(unittest.TestCase):
    def test_cli_json_html_csv(self):
        with TcpServer() as srv, tempfile.TemporaryDirectory() as tmp:
            base = ["127.0.0.1", "-p", str(srv.port), "-b", "-q", "--no-color", "--timeout", "0.5", "-r", "0"]
            for ext in ("json", "csv", "html", "txt"):
                out = os.path.join(tmp, f"r.{ext}")
                self.assertEqual(main(base + ["-o", out]), 0)
                self.assertGreater(os.path.getsize(out), 0)
            with open(os.path.join(tmp, "r.json"), encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["meta"]["open_ports"], 1)
            self.assertEqual(data["hosts"][0]["ports"][0]["service"], "ssh")
            with open(os.path.join(tmp, "r.html"), encoding="utf-8") as fh:
                self.assertIn("OpenSSH_9.6", fh.read())

    def test_cli_rejects_bad_input(self):
        self.assertEqual(main(["127.0.0.1", "-p", "99999", "-q"]), 1)
        self.assertEqual(main(["10.0.0.0/16", "-q"]), 1)  # >256 hosts needs --yes

    def test_html_escapes_content(self):
        from mo_port_scan.scanner import HostResult, PortResult
        h = HostResult("t", "1.2.3.4", ports=[PortResult(80, banner="<script>alert(1)</script>")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.html")
            write_report(path, [h], {"version": "x"})
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("<script>alert", fh.read())


if __name__ == "__main__":
    unittest.main()
