# Scope attachment tests

Run the isolated CSV regressions from the repository root with Python 3:

```sh
python -m pip install netaddr unicodecsv
python -m unittest discover -s tests -v
```

These tests compile the actual scope-attachment and structure-anonymization
methods from `generate_report.py`, preserving source line numbers. They avoid
importing the Python 2 PDF/database stack and use real `netaddr` objects and
`unicodecsv` writers. All snapshots and organizations are synthetic; temporary
CSV files are removed after each test. This does not test full report rendering,
database queries, or the production Python 2 environment.

When descendants are present, anonymous scope attachments retain the same
columns as ordinary reports. Top-level ownership becomes `SAMPLE` and child
ownership becomes `SUB_ORG`. Rows are deliberately not deduplicated after
anonymization: different original scope entries can produce identical masked
values, and retaining them preserves the ordinary report's row count and
per-entry counts. Single-organization column sets are unchanged.
