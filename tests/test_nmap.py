import unittest
from os import environ
from nbs.nmap import Nmap


class TestRequest(unittest.TestCase):
    def test_api(self):
        path = environ.get('NMAP_PATH')

        nmap = Nmap(path, 'test')
        self.assertIsInstance(nmap, Nmap)
        nmap.run()
        self.assertIsInstance(nmap.hosts, list)


if __name__ == '__main__':
    unittest.main()
