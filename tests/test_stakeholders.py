"""Tests for critical-infrastructure sector labels in stakeholder CSV exports."""

import csv
import unittest

from mock import MagicMock

from cyhy_report.stakeholders.stakeholders import generate_stakeholders_csv


class StakeholderSectorTests(unittest.TestCase):
    """Exercise direct and nested sector membership without a database."""

    def setUp(self):
        """Provide request documents and the hierarchy returned by CyHy core."""
        self.db = MagicMock()
        hierarchy = {
            "CRITICAL_INFRASTRUCTURE": [
                "ENERGY",
                "WATER",
                "DIRECT",
                "GROUP",
                "NESTED",
                "DEEPER",
                "OTHER",
            ],
            "ENERGY": ["DIRECT", "GROUP", "NESTED", "DEEPER"],
            "WATER": ["OTHER"],
            "ELECTION": [],
            "FED_GOLD": [],
        }
        nodes = {
            "CRITICAL_INFRASTRUCTURE": {"children": ["ENERGY", "WATER"]},
            "ENERGY": {"children": ["DIRECT", "GROUP"]},
            "WATER": {"children": ["OTHER"]},
            "GROUP": {"children": ["NESTED"]},
            "NESTED": {"children": ["DEEPER"]},
        }
        owners = ["DIRECT", "NESTED", "DEEPER", "OTHER", "OUTSIDE"]
        documents = []
        for owner in owners:
            documents.append(
                {
                    "_id": owner,
                    "agency": {
                        "name": owner,
                        "location": {
                            "name": "Example City",
                            "county": "Example County",
                            "state": "VA",
                            "gnis_id": 1,
                        },
                    },
                    "scheduler": "default",
                    "report_period": "weekly",
                }
            )
        self.db.RequestDoc.get_owner_to_type_dict.return_value = dict.fromkeys(
            owners, "STATE"
        )
        self.db.RequestDoc.get_by_owner.side_effect = nodes.__getitem__
        self.db.RequestDoc.get_all_descendants.side_effect = hierarchy.__getitem__
        self.db.RequestDoc.find.return_value.sort.return_value = documents
        self.db.SnapshotDoc.collection.aggregate.return_value = []
        output = generate_stakeholders_csv(self.db)
        output.seek(0)
        self.rows = {row["Organization ID"]: row for row in csv.DictReader(output)}

    def test_direct_member_retains_sector(self):
        """Direct members keep their existing critical-infrastructure label."""
        self.assertEqual(self.rows["DIRECT"]["Critical Infrastructure"], "Yes")
        self.assertEqual(self.rows["DIRECT"]["CI Sector"], "ENERGY")

    def test_nested_member_inherits_sector(self):
        """Members below a grouping node receive their sector label."""
        self.assertEqual(self.rows["NESTED"]["Critical Infrastructure"], "Yes")
        self.assertEqual(self.rows["NESTED"]["CI Sector"], "ENERGY")

    def test_deeper_member_inherits_sector(self):
        """Sector assignment works beyond a single level of nesting."""
        self.assertEqual(self.rows["DEEPER"]["Critical Infrastructure"], "Yes")
        self.assertEqual(self.rows["DEEPER"]["CI Sector"], "ENERGY")

    def test_other_sector_stays_independent(self):
        """A different sector's member must not receive the first sector label."""
        self.assertEqual(self.rows["OTHER"]["CI Sector"], "WATER")

    def test_nonmember_is_unchanged(self):
        """Nonmembers retain empty sectors and their other exported fields."""
        self.assertEqual(self.rows["OUTSIDE"]["Critical Infrastructure"], "No")
        self.assertEqual(self.rows["OUTSIDE"]["CI Sector"], "")
        self.assertEqual(self.rows["OUTSIDE"]["Region"], "Region 3")
        self.assertEqual(self.rows["OUTSIDE"]["First Scan"], "No Scans")


if __name__ == "__main__":
    unittest.main()
