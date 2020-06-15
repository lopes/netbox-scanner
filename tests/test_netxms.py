import unittest
from os import environ
from nbs.netxms import NetXMS


class TestRequest(unittest.TestCase):
    def test_api(self):
        address = environ.get('NETXMS_ADDRESS')
        username = environ.get('NETXMS_USER')
        password = environ.get('NETXMS_PASS')
        
        netxms = NetXMS(address, username, password, False, 'unknown')
        self.assertIsInstance(netxms, NetXMS)
        netxms.run()
        self.assertIsInstance(netxms.hosts, list)


if __name__ == '__main__':
    unittest.main()
