"""Offline tests for the change logic (no API calls). Run: python -m unittest"""
import copy
import unittest

from modules.detectors import (
    mut_add_recipient, mut_remove_recipient, mut_replace_recipient,
    mut_add_team, mut_remove_tag, parse_recipient,
)

DET = {
    "id": "D1", "name": "Mobile4 - API latency", "teams": ["T1"], "tags": ["mobile"],
    "rules": [
        {"detectLabel": "crit", "severity": "Critical",
         "notifications": [{"type": "Team", "team": "OLD"},
                           {"type": "Email", "email": "a@x.com"}]},
        {"detectLabel": "warn", "severity": "Warning",
         "notifications": [{"type": "Team", "team": "OLD"}]},
    ],
}


class TestMutators(unittest.TestCase):
    def setUp(self):
        self.d = copy.deepcopy(DET)

    def test_parse(self):
        self.assertEqual(parse_recipient("slack:C1:alerts"),
                         {"type": "Slack", "credentialId": "C1", "channel": "alerts"})
        with self.assertRaises(ValueError):
            parse_recipient("fax:123")

    def test_remove_team_recipient_warns_on_empty_rule(self):
        s = mut_remove_recipient(parse_recipient("team:OLD"))(self.d)
        self.assertIn("2 rule(s)", s)
        self.assertIn("WARNING", s)  # warn rule now empty
        self.assertEqual(self.d["rules"][1]["notifications"], [])

    def test_severity_filter(self):
        mut_remove_recipient(parse_recipient("team:OLD"), "Critical")(self.d)
        self.assertEqual(len(self.d["rules"][1]["notifications"]), 1)

    def test_add_is_idempotent(self):
        m = mut_add_recipient(parse_recipient("email:a@x.com"))
        self.assertIn("1 rule(s)", m(self.d))   # only the warn rule lacked it
        self.assertEqual(m(self.d), "")         # second run: nothing to do

    def test_replace(self):
        s = mut_replace_recipient(parse_recipient("team:OLD"),
                                  parse_recipient("team:NEW"))(self.d)
        self.assertIn("2 rule(s)", s)
        self.assertIn({"type": "Team", "team": "NEW"}, self.d["rules"][1]["notifications"])

    def test_team_and_tag(self):
        self.assertEqual(mut_add_team("T1")(self.d), "")
        self.assertTrue(mut_add_team("T2")(self.d))
        self.assertTrue(mut_remove_tag("mobile")(self.d))
        self.assertEqual(self.d["tags"], [])


if __name__ == "__main__":
    unittest.main()
