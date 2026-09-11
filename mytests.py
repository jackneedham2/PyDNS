"""
Some straightforward unit tests to make sure the encoding and decoding logic is behaving as expected
"""

import unittest
import dns_querier
import definition_maps as dm

BBC_DOMAIN = {
	"encoded": bytes([3, 98, 98, 99, 2, 99, 111, 2, 117, 107, 0]), 
	"decoded": "bbc.co.uk"
}

TEST_FLAGS = {
	"encoded": 33152,
	"decoded": {
		   'QR': 'Response',
           'OPCODE': 'QUERY',
           'AA': False,
           'TC': False,
           'RD': True,
           'RA': True,
           'Z': 0,
           'RCODE': 'No Error'}
 }


class MyTest(unittest.TestCase):

	def test_domain_decode(self):
		decoded_domain = dns_querier.decode_domain(BBC_DOMAIN["encoded"])[1]
		self.assertEqual(decoded_domain, "bbc.co.uk", "Should be "+str(BBC_DOMAIN))

	def test_domain_encode(self):
		encoded_domain = dns_querier.encode_domain(BBC_DOMAIN["decoded"])
		self.assertEqual(encoded_domain, BBC_DOMAIN["encoded"], "Should be "+str(BBC_DOMAIN))

	def test_flags_encode(self):
		encoded_flags = dns_querier.encode_flags(TEST_FLAGS["decoded"])
		self.assertEqual(encoded_flags, TEST_FLAGS["encoded"], "Should be "+str(TEST_FLAGS))

	def test_flags_decode(self):
		decoded_flags = dns_querier.decode_flags(TEST_FLAGS["encoded"])
		self.assertEqual(decoded_flags, TEST_FLAGS["decoded"], "Should be "+str(TEST_FLAGS))

if __name__ == "__main__":
    unittest.main()