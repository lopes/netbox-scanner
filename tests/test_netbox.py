import unittest
from os import environ
from nbs import NetBoxScanner


class TestRequest(unittest.TestCase):
    def test_api(self):
        address = environ.get('NETBOX_ADDRESS')
        token = environ.get('NETBOX_TOKEN')

        netbox = NetBoxScanner(address, token, False, [], 'test', False)
        self.assertIsInstance(netbox, NetBoxScanner)
        self.assertEqual(netbox.sync(), True)


if __name__ == '__main__':
    unittest.main()
