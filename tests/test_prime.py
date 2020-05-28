import unittest
from os import environ
from nbs.prime import Prime


class TestRequest(unittest.TestCase):
    def test_api(self):
        address = environ.get('PRIME_ADDRESS')
        username = environ.get('PRIME_USER')
        password = environ.get('PRIME_PASS')
        
        prime = Prime(address, username, password, False, 'unknown')
        self.assertIsInstance(prime, Prime)
        prime.run()
        self.assertIsInstance(prime.hosts, list)


if __name__ == '__main__':
    unittest.main()
