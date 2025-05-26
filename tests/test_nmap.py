import unittest

from nbs.nmap import Nmap


class TestRequest(unittest.TestCase):
    def test_api(self):

        nmap = Nmap("test", ["127.0.0.1/32"])
        self.assertIsInstance(nmap, Nmap)
        nmap.run()
        self.assertIsInstance(nmap.hosts, list)
        self.assertEqual(nmap.hosts[0][0], "127.0.0.1")
        self.assertEqual(nmap.hosts[0][1], "localhost")


if __name__ == '__main__':
    unittest.main()
