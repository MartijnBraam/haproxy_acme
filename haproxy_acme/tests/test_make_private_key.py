from unittest import TestCase
from haproxy_acme.private import make_private_key_ec


class TestMake_private_key_ec(TestCase):
    def test_make_private_key(self):
        result = make_private_key_ec()
        self.assertIsNotNone(result)
