"""Exercise the scope CSV generators without the legacy PDF/database stack.

The generator module uses Python 2 syntax and imports the complete report stack
at import time. Compile its unchanged scope methods in isolation so these tests
can run on Python 3 with only netaddr and unicodecsv installed. CSV writing and
network membership use the same implementations as the report generator.
"""

import copy
import os
from pathlib import Path
import re
import tempfile
import unittest

from netaddr import IPAddress, IPNetwork
import unicodecsv as csv


def load_scope_generator():
    source_path = (
        Path(__file__).resolve().parents[1] / "cyhy_report/customer/generate_report.py"
    )
    lines = source_path.read_text().splitlines(keepends=True)
    selected = ["\n"] * len(lines)
    class_line = next(
        i for i, line in enumerate(lines) if line.startswith("class ReportGenerator(")
    )
    selected[class_line] = lines[class_line]
    for name in (
        "__generate_scope_ip_attachment",
        "__generate_scope_host_attachment",
        "__anonymize_structure",
        "__get_scope_descendant_hostnames",
    ):
        start = next(
            i
            for i, line in enumerate(lines)
            if line.startswith("    def " + name + "(")
        )
        end = next(
            (
                i
                for i in range(start + 1, len(lines))
                if lines[i].startswith("    def ")
            ),
            len(lines),
        )
        selected[start:end] = lines[start:end]
    for i, line in enumerate(lines):
        if line.startswith(("IPV4_ADDRESS_RE =", "ANONYMOUS_IPV4 =")):
            selected[i] = line
    namespace = {"re": re, "IPAddress": IPAddress, "csv": csv, "basestring": str}
    # Preserve source line numbers so failures refer to the real implementation.
    exec(compile("".join(selected), str(source_path), "exec"), namespace)
    return namespace["ReportGenerator"]


ReportGenerator = load_scope_generator()


class ScopeAttachmentsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous_directory = os.getcwd()
        os.chdir(self.directory.name)

    def tearDown(self):
        os.chdir(self.previous_directory)
        self.directory.cleanup()

    def generator(
        self, anonymize, descendants=True, prepared=False, ip_hostnames=False
    ):
        # The last two networks/hostnames become identical anonymous rows.
        # Keep both to preserve the real report's row count and attribution.
        children = [
            {
                "owner": "CHILD_A",
                "networks": [IPNetwork("198.51.2.0/24")],
                "hostnames": ["child-a.internal.example"],
            },
            {
                "owner": "CHILD_B",
                "networks": [IPNetwork("203.0.2.0/24")],
                "hostnames": ["child-b.internal.example"],
            },
        ]
        snapshot = {
            "owner": "PARENT",
            "networks": [IPNetwork("192.0.2.0/24")],
            "hostnames": ["parent.internal.example"],
        }
        if ip_hostnames:
            # These distinct names collide under generic IPv4 anonymization.
            snapshot["hostnames"] = ["host-192.0.2.1.internal.example"]
            children[0]["hostnames"] = ["host-198.51.2.1.internal.example"]
            children[1]["hostnames"] = ["host-203.0.2.1.internal.example"]
        if descendants:
            snapshot["descendants_included"] = True
            for child in children:
                snapshot["networks"].extend(child["networks"])
                snapshot["hostnames"].extend(child["hostnames"])
        report = object.__new__(ReportGenerator)
        report._ReportGenerator__owner = "PARENT"
        report._ReportGenerator__anonymize = anonymize
        report._ReportGenerator__snapshots = [snapshot]
        report._ReportGenerator__results = {}
        if descendants:
            report._ReportGenerator__results["ss0_descendant_snapshots"] = children
        report._ReportGenerator__scope_descendant_hostnames = (
            report._ReportGenerator__get_scope_descendant_hostnames()
        )
        if prepared:
            # Match generate_report's state at the attachment stage.
            report._ReportGenerator__owner = "SAMPLE"
            snapshot["owner"] = "SAMPLE"
            report._ReportGenerator__results = (
                report._ReportGenerator__anonymize_structure(
                    report._ReportGenerator__results
                )
            )
        return report

    def produce(self, report):
        report._ReportGenerator__generate_scope_ip_attachment()
        report._ReportGenerator__generate_scope_host_attachment()
        outputs = {}
        for name in ("scope-ip.csv", "scope-hostname.csv"):
            path = Path(name)
            if path.exists():
                with path.open("rb") as source:
                    reader = csv.DictReader(source)
                    outputs[name] = (reader.fieldnames, list(reader))
        return outputs

    def test_anonymous_descendant_headers_match_real_reports(self):
        ordinary = self.produce(self.generator(False))
        anonymous = self.produce(self.generator(True, prepared=True))
        for name in ordinary:
            with self.subTest(attachment=name):
                self.assertEqual(ordinary[name][0], anonymous[name][0])
                self.assertEqual(anonymous[name][0][0], "owner")

    def test_parent_and_descendant_placeholders(self):
        for prepared in (False, True):
            outputs = self.produce(self.generator(True, prepared=prepared))
            for name, (_, rows) in outputs.items():
                with self.subTest(prepared=prepared, attachment=name):
                    self.assertEqual(
                        [r["owner"] for r in rows], ["SAMPLE", "SUB_ORG", "SUB_ORG"]
                    )
                    content = Path(name).read_text()
                    for private in ("PARENT", "CHILD_A", "CHILD_B", "internal.example"):
                        self.assertNotIn(private, content)

    def test_duplicate_anonymous_rows_are_retained(self):
        outputs = self.produce(self.generator(True, prepared=True))
        for name, (_, rows) in outputs.items():
            with self.subTest(attachment=name):
                self.assertEqual(len(rows), 3)
                self.assertEqual(rows[1], rows[2])

    def test_anonymous_network_fields_and_counts_remain_masked(self):
        _, rows = self.produce(self.generator(True, prepared=True))["scope-ip.csv"]
        for row in rows:
            self.assertEqual(row["cidr"], "x.x.2.0/24")
            self.assertEqual(row["first"], "x.x.2.0")
            self.assertEqual(row["last"], "x.x.2.255")
            self.assertEqual(row["count"], "256")

    def test_anonymous_hostnames_remain_masked(self):
        report = self.generator(True, prepared=True)
        _, rows = self.produce(report)["scope-hostname.csv"]
        self.assertEqual([r["hostname"] for r in rows], ["www.example.com"] * 3)
        self.assertTrue(report._ReportGenerator__results["has_scope_host_attachment"])

    def test_ordinary_descendants_retain_real_attribution(self):
        outputs = self.produce(self.generator(False))
        for name, (_, rows) in outputs.items():
            with self.subTest(attachment=name):
                self.assertEqual(
                    [r["owner"] for r in rows], ["PARENT", "CHILD_A", "CHILD_B"]
                )
        self.assertEqual(outputs["scope-ip.csv"][1][0]["cidr"], "192.0.2.0/24")
        self.assertEqual(
            outputs["scope-hostname.csv"][1][0]["hostname"], "parent.internal.example"
        )

    def test_ip_address_hostnames_retain_original_scope_ownership(self):
        report = self.generator(True, prepared=True, ip_hostnames=True)
        _, rows = self.produce(report)["scope-hostname.csv"]
        self.assertEqual(
            [row["owner"] for row in rows], ["SAMPLE", "SUB_ORG", "SUB_ORG"]
        )
        self.assertEqual([row["hostname"] for row in rows], ["www.example.com"] * 3)

    def test_single_organization_keeps_owner_column_absent(self):
        for anonymize in (False, True):
            outputs = self.produce(self.generator(anonymize, descendants=False))
            for name, (headers, rows) in outputs.items():
                with self.subTest(anonymize=anonymize, attachment=name):
                    self.assertNotIn("owner", headers)
                    self.assertNotIn("owner", rows[0])
                    self.assertEqual(len(rows), 1)

    def test_empty_networks_keep_the_expected_header(self):
        report = self.generator(True, prepared=True)
        report._ReportGenerator__snapshots[0]["networks"] = []
        header, rows = self.produce(report)["scope-ip.csv"]
        self.assertEqual(header, ["owner", "cidr", "first", "last", "count"])
        self.assertEqual(rows, [])

    def test_missing_hostnames_do_not_create_attachment(self):
        report = self.generator(True, prepared=True)
        report._ReportGenerator__snapshots[0].pop("hostnames")
        outputs = self.produce(report)
        self.assertNotIn("scope-hostname.csv", outputs)
        self.assertFalse(report._ReportGenerator__results["has_scope_host_attachment"])

    def test_empty_hostnames_do_not_create_attachment(self):
        report = self.generator(True, prepared=True)
        report._ReportGenerator__snapshots[0]["hostnames"] = []
        outputs = self.produce(report)
        self.assertNotIn("scope-hostname.csv", outputs)
        self.assertFalse(report._ReportGenerator__results["has_scope_host_attachment"])

    def test_generation_does_not_mutate_snapshot_data(self):
        report = self.generator(True, prepared=True)
        before = copy.deepcopy(report._ReportGenerator__snapshots)
        family = copy.deepcopy(
            report._ReportGenerator__results["ss0_descendant_snapshots"]
        )
        self.produce(report)
        self.assertEqual(report._ReportGenerator__snapshots, before)
        self.assertEqual(
            report._ReportGenerator__results["ss0_descendant_snapshots"], family
        )


if __name__ == "__main__":
    unittest.main()
