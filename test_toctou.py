"""Executable regression tests for the three local experiment scenarios."""

import unittest

from toctou_lab import run_scenario


class CouponRaceTests(unittest.TestCase):
    def test_sequential_rejects_second_request(self):
        result = run_scenario("vulnerable_sequential")
        self.assertEqual(
            [item["response"]["status"] for item in result["requests"]],
            [200, 409],
        )
        self.assertEqual(result["final_state"]["successful_redemptions"], 1)

    def test_race_accepts_two_stale_checks(self):
        result = run_scenario("vulnerable_parallel")
        self.assertEqual(
            [item["response"]["status"] for item in result["requests"]],
            [200, 200],
        )
        self.assertEqual(result["final_state"]["successful_redemptions"], 2)
        checks = [event for event in result["events"] if event["action"] == "check"]
        accepts = [event for event in result["events"] if event["action"] == "accepted"]
        self.assertEqual(len(checks), 2)
        self.assertTrue(all(not event["used"] for event in checks))
        self.assertLess(
            max(event["sequence"] for event in checks),
            min(event["sequence"] for event in accepts),
        )

    def test_fixed_path_accepts_only_one(self):
        result = run_scenario("fixed_parallel")
        self.assertEqual(
            sorted(item["response"]["status"] for item in result["requests"]),
            [200, 409],
        )
        self.assertEqual(result["final_state"]["successful_redemptions"], 1)


if __name__ == "__main__":
    unittest.main()
