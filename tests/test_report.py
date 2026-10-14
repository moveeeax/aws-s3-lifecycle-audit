"""Reporter tests: table shape, JSON shape, and the empty case."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from aws_s3_lifecycle_audit.pricing import human_bytes, monthly_usd, savings_usd
from aws_s3_lifecycle_audit.report import render, text_report
from aws_s3_lifecycle_audit.rules import evaluate_all

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
GIB = 1024 ** 3

BUCKETS = [
    {
        "name": "build-artifacts",
        "region": "eu-central-1",
        "lifecycle_present": False,
        "lifecycle": [],
        "versioning": "Disabled",
        "metrics": {"bytes_standard": 3072 * GIB},
        "multipart": {"upload_count": 4, "part_bytes": 11 * GIB,
                      "oldest_initiated": "2025-11-20T03:14:00Z"},
    }
]


def test_empty_findings_report_names_the_bucket_count():
    assert text_report([], buckets_scanned=7) == "No lifecycle findings across 7 bucket(s).\n"


def test_table_has_a_header_and_one_row_per_finding():
    findings = evaluate_all(BUCKETS, now=NOW)
    lines = text_report(findings, buckets_scanned=1).splitlines()
    assert lines[0].split() == ["BUCKET", "RULE", "SEV", "WASTED", "$/MO", "DETAIL"]
    assert set(lines[1].replace(" ", "")) == {"-"}
    rows = [line for line in lines if line.startswith("build-artifacts")]
    assert len(rows) == len(findings)
    assert "worst buckets:" in "\n".join(lines)


def test_table_columns_line_up():
    findings = evaluate_all(
        BUCKETS + [dict(BUCKETS[0], name="a-very-much-longer-bucket-name")], now=NOW
    )
    lines = text_report(findings, buckets_scanned=2).splitlines()
    starts = {line.index("no-") for line in lines if line.startswith(("build-", "a-very"))}
    assert len(starts) == 1


def test_render_rejects_an_unknown_format():
    with pytest.raises(ValueError):
        render([], fmt="yaml")


def test_json_render_carries_extra_keys():
    findings = evaluate_all(BUCKETS, now=NOW)
    data = json.loads(render(findings, fmt="json", buckets_scanned=1,
                             extra={"emitted_lifecycle_files": 1}))
    assert data["emitted_lifecycle_files"] == 1
    assert data["summary"]["buckets_scanned"] == 1
    assert data["findings"][0]["bucket"] == "build-artifacts"


@pytest.mark.parametrize(
    "value,expected",
    [(0, "0 B"), (512, "512 B"), (1024, "1.0 KiB"), (GIB, "1.0 GiB"), (1024 * GIB, "1.0 TiB")],
)
def test_human_bytes(value, expected):
    assert human_bytes(value) == expected


def test_price_helpers():
    assert monthly_usd(100 * GIB, 0.023) == pytest.approx(2.3, abs=0.01)
    assert monthly_usd(0, 0.023) == 0.0
    assert savings_usd(1000 * GIB, 0.023, 0.0125) == pytest.approx(10.5, abs=0.01)
    assert savings_usd(1000 * GIB, 0.01, 0.02) == 0.0
