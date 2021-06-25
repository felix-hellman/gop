from gop import GopController
from gop import FileLayer
from gop import ApiClient
from unittest.mock import MagicMock
import unittest

class TestGop(unittest.TestCase):

    def test_ping(self):
        for expected in [True, False]:
            client = ApiClient("", "")
            client.ping = MagicMock(return_value=expected)
            self.assertEqual(GopController(client, FileLayer()).ping(), expected)

if __name__ == '__main__':
    unittest.main()
