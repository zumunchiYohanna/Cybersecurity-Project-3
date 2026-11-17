import unittest

from cyber_assessment.models import PortResult
from cyber_assessment.service_id import identify_service


class ServiceIdentificationTests(unittest.TestCase):
    def test_known_port_is_a_likely_label_not_a_verified_banner(self):
        result = PortResult(
            "a", 1, "127.0.0.1", 443, "open", None, None, 1.0, None,
        )
        identified = identify_service(result)
        self.assertEqual(identified.service_name, "https")
        self.assertEqual(identified.identification_basis, "well_known_port")

    def test_unknown_port_is_not_guessed(self):
        result = PortResult("a", 1, "127.0.0.1", 49152, "open", None, None, 1.0, None)
        self.assertIsNone(identify_service(result).service_name)


if __name__ == "__main__":
    unittest.main()
