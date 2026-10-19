import unittest

from mo_port_scan.services import clean_banner, identify, risk_note


class IdentifyTests(unittest.TestCase):
    def test_ssh(self):
        svc, ver, _ = identify(2222, "tcp", "SSH-2.0-OpenSSH_9.6\r\n")
        self.assertEqual((svc, ver), ("ssh", "OpenSSH_9.6"))

    def test_http_server_and_title(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n<html><title> Hello  World </title>"
        svc, ver, extra = identify(8081, "tcp", raw)
        self.assertEqual((svc, ver), ("http", "nginx/1.25.3"))
        self.assertEqual(extra["http_title"], "Hello World")

    def test_ftp_and_smtp(self):
        self.assertEqual(identify(2100, "tcp", "220 (vsFTPd 3.0.5)")[0], "ftp")
        self.assertEqual(identify(2525, "tcp", "220 mail.example.com ESMTP Postfix")[0:2], ("smtp", "Postfix"))

    def test_mysql_binary_greeting(self):
        raw = "\x4a\x00\x00\x00\x0a8.0.36\x00abc"
        self.assertEqual(identify(3307, "tcp", raw)[0:2], ("mysql", "8.0.36"))

    def test_unknown_banner_keeps_port_service(self):
        self.assertEqual(identify(22, "tcp", "garbage")[0], "ssh")

    def test_clean_banner(self):
        self.assertEqual(clean_banner("\r\n\x01hello\x02 world\nsecond"), ".hello. world")
        self.assertEqual(len(clean_banner("A" * 500)), 100)

    def test_risk_note(self):
        self.assertTrue(risk_note(23, "tcp"))
        self.assertEqual(risk_note(22, "tcp"), "")


if __name__ == "__main__":
    unittest.main()
