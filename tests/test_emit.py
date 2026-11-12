"""Emitter tests: merged JSON configs and the Terraform rendering, from hand-built dicts."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from aws_s3_lifecycle_audit.emit import resource_name, terraform_config, write_emitted
from aws_s3_lifecycle_audit.rules import evaluate_all

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)

OWNER_RULE = {
    "ID": "archive-logs",
    "Status": "Enabled",
    "Filter": {"And": {"Prefix": "logs/", "Tags": [{"Key": "tier", "Value": "cold"}],
                       "ObjectSizeGreaterThan": 131072}},
    "Transitions": [
        {"Days": 30, "StorageClass": "GLACIER"},
        {"Date": dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc), "StorageClass": "DEEP_ARCHIVE"},
    ],
    "Expiration": {"Days": 365},
}
DISABLED_RULE = {
    "ID": "expire-tmp",
    "Status": "Disabled",
    "Filter": {"Tag": {"Key": "tmp", "Value": "true"}},
    "Expiration": {"ExpiredObjectDeleteMarker": True},
    "NoncurrentVersionTransitions": [
        {"NoncurrentDays": 30, "StorageClass": "STANDARD_IA", "NewerNoncurrentVersions": 2}
    ],
}


def bucket(**overrides):
    base = {
        "name": "logs.example",
        "region": "eu-central-1",
        "lifecycle_present": True,
        "lifecycle": [OWNER_RULE, DISABLED_RULE],
        "versioning": "Enabled",
        "metrics": {"bytes_standard": 0, "bytes_noncurrent": 0},
        "multipart": {"upload_count": 0, "part_bytes": 0},
    }
    base.update(overrides)
    return base


def emit(tmp_path, buckets, **kwargs):
    warnings = []
    findings = evaluate_all(buckets, now=NOW)
    result = write_emitted(str(tmp_path), findings, buckets, warn=warnings.append, **kwargs)
    return result, warnings


def test_merged_json_keeps_the_owner_rules_and_adds_the_missing_ones(tmp_path):
    result, warnings = emit(tmp_path, [bucket()], merge=True)
    assert result == {"written": 1, "skipped": []}
    assert warnings == []
    config = json.loads((tmp_path / "logs.example.json").read_text(encoding="utf-8"))
    ids = [r["ID"] for r in config["Rules"]]
    assert ids == [
        "archive-logs",
        "expire-tmp",
        "lifecycle-audit-no-abort-mpu",
        "lifecycle-audit-no-noncurrent-expiry",
    ]
    # Datetimes from boto3 come out as RFC 3339 strings, everything else untouched.
    assert config["Rules"][0]["Transitions"][1]["Date"] == "2027-01-01T00:00:00Z"
    assert config["Rules"][1] == DISABLED_RULE


def test_unmerged_json_warns_that_it_replaces_existing_rules(tmp_path):
    result, warnings = emit(tmp_path, [bucket()])
    assert result["written"] == 1
    config = json.loads((tmp_path / "logs.example.json").read_text(encoding="utf-8"))
    assert [r["ID"] for r in config["Rules"]] == [
        "lifecycle-audit-no-abort-mpu",
        "lifecycle-audit-no-noncurrent-expiry",
    ]
    assert len(warnings) == 1
    assert "2 existing rule(s)" in warnings[0]
    assert "--merge" in warnings[0]


def test_no_warning_for_a_bucket_without_rules(tmp_path):
    _, warnings = emit(tmp_path, [bucket(lifecycle=[], lifecycle_present=False)])
    assert warnings == []


def test_merge_skips_a_bucket_whose_config_was_not_readable(tmp_path):
    denied = bucket(lifecycle=[], lifecycle_present=False, lifecycle_unknown=True)
    result, warnings = emit(tmp_path, [denied], merge=True)
    assert result == {"written": 0, "skipped": ["logs.example"]}
    assert "not readable" in warnings[0]
    assert not list(tmp_path.iterdir())


def test_merged_json_warns_about_a_non_default_minimum_object_size(tmp_path):
    _, warnings = emit(
        tmp_path, [bucket(lifecycle_transition_min_size="varies_by_storage_class")], merge=True
    )
    assert len(warnings) == 1
    assert "--transition-default-minimum-object-size varies_by_storage_class" in warnings[0]


def test_terraform_file_has_one_resource_with_every_rule(tmp_path):
    result, _ = emit(
        tmp_path,
        [bucket(lifecycle_transition_min_size="varies_by_storage_class")],
        merge=True,
        fmt="terraform",
    )
    assert result["written"] == 1
    text = (tmp_path / "logs.example.tf").read_text(encoding="utf-8")
    assert text.startswith(
        'resource "aws_s3_bucket_lifecycle_configuration" "logs_example" {\n'
        '  bucket                                 = "logs.example"\n'
        '  transition_default_minimum_object_size = "varies_by_storage_class"\n'
    )
    assert text.count("\n  rule {") == 4
    assert 'id     = "archive-logs"' in text
    assert 'status = "Disabled"' in text
    assert "        tags = {\n          \"tier\" = \"cold\"\n        }\n" in text
    assert 'date          = "2027-01-01T00:00:00Z"' in text
    assert "expired_object_delete_marker = true" in text
    assert "newer_noncurrent_versions = 2" in text
    assert "days_after_initiation = 7" in text
    assert text.endswith("}\n")


def test_terraform_matches_terraform_fmt_layout():
    config = {
        "Rules": [
            {
                "ID": "lifecycle-audit-no-abort-mpu",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
            },
            {"ID": "legacy", "Status": "Enabled", "Expiration": {"Days": 30}},
        ]
    }
    assert terraform_config("b", config) == (
        'resource "aws_s3_bucket_lifecycle_configuration" "b" {\n'
        '  bucket = "b"\n'
        "\n"
        "  rule {\n"
        '    id     = "lifecycle-audit-no-abort-mpu"\n'
        '    status = "Enabled"\n'
        "\n"
        "    abort_incomplete_multipart_upload {\n"
        "      days_after_initiation = 7\n"
        "    }\n"
        "\n"
        "    filter {\n"
        '      prefix = ""\n'
        "    }\n"
        "  }\n"
        "\n"
        "  rule {\n"
        '    id     = "legacy"\n'
        '    status = "Enabled"\n'
        "\n"
        "    expiration {\n"
        "      days = 30\n"
        "    }\n"
        "\n"
        "    filter {}\n"
        "  }\n"
        "}\n"
    )


def test_terraform_turns_a_top_level_prefix_into_a_filter():
    config = {"Rules": [{"ID": "old", "Status": "Enabled", "Prefix": "tmp/",
                         "Expiration": {"Days": 1}}]}
    text = terraform_config("b", config)
    assert 'filter {\n      prefix = "tmp/"\n    }' in text
    assert "\n    prefix" not in text


def test_terraform_escapes_template_sequences():
    config = {"Rules": [{"ID": "x", "Status": "Enabled", "Filter": {"Prefix": "a/${b}/%{c}"},
                         "Expiration": {"Days": 1}}]}
    assert 'prefix = "a/$${b}/%%{c}"' in terraform_config("b", config)


def test_terraform_refuses_a_rule_field_it_cannot_render(tmp_path):
    odd = dict(OWNER_RULE, SomethingNew={"x": 1})
    result, warnings = emit(tmp_path, [bucket(lifecycle=[odd])], merge=True, fmt="terraform")
    assert result == {"written": 0, "skipped": ["logs.example"]}
    assert "SomethingNew" in warnings[0]


@pytest.mark.parametrize(
    "name,expected",
    [("build-artifacts", "build-artifacts"), ("logs.example.com", "logs_example_com"),
     ("123-data", "bucket_123-data")],
)
def test_resource_name(name, expected):
    assert resource_name(name) == expected


def test_unknown_format_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        write_emitted(str(tmp_path), [], [], fmt="yaml")
