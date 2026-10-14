"""Rule engine tests. No AWS, no credentials, no clock."""

from __future__ import annotations

import datetime as dt

import pytest

from aws_s3_lifecycle_audit.rules import (
    RULE_ALL_RULES_DISABLED,
    RULE_NO_ABORT_MPU,
    RULE_NO_NONCURRENT_EXPIRY,
    RULE_NO_TRANSITION,
    evaluate,
    evaluate_all,
    oldest_upload_age_days,
    parse_timestamp,
    severity_for,
    should_fail,
    suggest_lifecycle,
    summarize,
    unknown_rules,
)

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
GIB = 1024 ** 3

ABORT_RULE = {
    "ID": "abort",
    "Status": "Enabled",
    "Filter": {"Prefix": ""},
    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
}
NONCURRENT_RULE = {
    "ID": "expire-old",
    "Status": "Enabled",
    "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
}
TRANSITION_RULE = {
    "ID": "to-ia",
    "Status": "Enabled",
    "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
}


def bucket(**overrides):
    base = {
        "name": "demo",
        "region": "eu-central-1",
        "lifecycle_present": True,
        "lifecycle": [ABORT_RULE, NONCURRENT_RULE, TRANSITION_RULE],
        "versioning": "Enabled",
        "metrics": {"bytes_standard": 0, "bytes_noncurrent": 0, "objects": 0},
        "multipart": {"upload_count": 0, "part_bytes": 0},
    }
    base.update(overrides)
    return base


def rules_of(findings):
    return [f.rule for f in findings]


def one(findings, rule):
    matches = [f for f in findings if f.rule == rule]
    assert len(matches) == 1, "expected exactly one %s in %s" % (rule, rules_of(findings))
    return matches[0]


def test_fully_configured_bucket_is_silent():
    assert evaluate(bucket(), now=NOW) == []


# --- no-abort-mpu ---------------------------------------------------------------


def test_missing_abort_rule_reports_parts_and_age():
    found = evaluate(
        bucket(
            name="build-artifacts",
            lifecycle=[NONCURRENT_RULE, TRANSITION_RULE],
            multipart={
                "upload_count": 3,
                "part_bytes": 5 * GIB,
                "oldest_initiated": "2025-08-01T10:00:00Z",
            },
        ),
        now=NOW,
    )
    finding = one(found, RULE_NO_ABORT_MPU)
    assert finding.bucket == "build-artifacts"
    assert finding.wasted_bytes == 5 * GIB
    assert finding.facts["upload_count"] == 3
    # 2025-08-01T10:00Z to 2026-10-14T00:00Z is 438 whole days.
    assert finding.facts["oldest_age_days"] == 438
    assert "438 day(s) old" in finding.detail
    assert finding.monthly_usd == pytest.approx(0.12, abs=0.01)


def test_disabled_abort_rule_does_not_count():
    disabled = dict(ABORT_RULE, Status="Disabled")
    found = evaluate(
        bucket(lifecycle=[disabled, NONCURRENT_RULE, TRANSITION_RULE]), now=NOW
    )
    assert RULE_NO_ABORT_MPU in rules_of(found)


def test_abort_rule_without_days_does_not_count():
    empty = {"ID": "x", "Status": "Enabled", "AbortIncompleteMultipartUpload": {}}
    found = evaluate(bucket(lifecycle=[empty, NONCURRENT_RULE, TRANSITION_RULE]), now=NOW)
    assert RULE_NO_ABORT_MPU in rules_of(found)


def test_unreadable_part_size_is_said_out_loud():
    found = evaluate(
        bucket(
            lifecycle=[NONCURRENT_RULE, TRANSITION_RULE],
            multipart={"upload_count": 2, "part_bytes": 0, "part_bytes_known": False},
        ),
        now=NOW,
    )
    finding = one(found, RULE_NO_ABORT_MPU)
    assert "not readable" in finding.detail
    assert finding.facts["part_bytes_known"] is False


# --- no-noncurrent-expiry -------------------------------------------------------


def test_versioning_without_expiry_names_the_noncurrent_bytes():
    found = evaluate(
        bucket(
            name="configs",
            lifecycle=[ABORT_RULE, TRANSITION_RULE],
            metrics={"bytes_standard": 0, "bytes_noncurrent": 700 * GIB},
        ),
        now=NOW,
    )
    finding = one(found, RULE_NO_NONCURRENT_EXPIRY)
    assert finding.wasted_bytes == 700 * GIB
    assert finding.monthly_usd == pytest.approx(16.1, abs=0.05)
    assert finding.severity == "high"
    assert "700.0 GiB" in finding.detail


def test_expiry_rule_present_means_no_finding():
    found = evaluate(bucket(lifecycle=[ABORT_RULE, NONCURRENT_RULE, TRANSITION_RULE]), now=NOW)
    assert RULE_NO_NONCURRENT_EXPIRY not in rules_of(found)


def test_versioning_suspended_is_not_flagged():
    found = evaluate(
        bucket(versioning="Suspended", lifecycle=[ABORT_RULE, TRANSITION_RULE]), now=NOW
    )
    assert RULE_NO_NONCURRENT_EXPIRY not in rules_of(found)


def test_unknown_noncurrent_bytes_still_reports_but_prices_nothing():
    found = evaluate(
        bucket(
            lifecycle=[ABORT_RULE, TRANSITION_RULE],
            metrics={"bytes_standard": 0, "bytes_noncurrent": None},
        ),
        now=NOW,
    )
    finding = one(found, RULE_NO_NONCURRENT_EXPIRY)
    assert finding.monthly_usd == 0.0
    assert finding.severity == "medium"
    assert "--deep" in finding.detail


# --- no-transition --------------------------------------------------------------


def test_no_transition_estimates_the_ia_delta():
    found = evaluate(
        bucket(
            name="cold-logs",
            lifecycle=[ABORT_RULE, NONCURRENT_RULE],
            metrics={"bytes_standard": 2048 * GIB, "bytes_noncurrent": 0},
        ),
        now=NOW,
    )
    finding = one(found, RULE_NO_TRANSITION)
    # 2048 GiB * (0.023 - 0.0125) = 21.504
    assert finding.monthly_usd == pytest.approx(21.5, abs=0.01)
    assert finding.severity == "high"
    assert "STANDARD_IA" in finding.detail


def test_noncurrent_transition_counts_as_a_transition():
    rule = {
        "ID": "nc-to-ia",
        "Status": "Enabled",
        "NoncurrentVersionTransitions": [{"NoncurrentDays": 30, "StorageClass": "STANDARD_IA"}],
    }
    found = evaluate(bucket(lifecycle=[ABORT_RULE, NONCURRENT_RULE, rule]), now=NOW)
    assert RULE_NO_TRANSITION not in rules_of(found)


def test_legacy_single_transition_shape_counts():
    rule = {"ID": "old", "Status": "Enabled", "Transition": {"Days": 60, "StorageClass": "GLACIER"}}
    found = evaluate(bucket(lifecycle=[ABORT_RULE, NONCURRENT_RULE, rule]), now=NOW)
    assert RULE_NO_TRANSITION not in rules_of(found)


# --- all-rules-disabled ---------------------------------------------------------


def test_every_rule_disabled_is_config_theater():
    disabled = [
        dict(ABORT_RULE, Status="Disabled"),
        dict(NONCURRENT_RULE, Status="Disabled"),
        dict(TRANSITION_RULE, Status="Disabled"),
    ]
    found = evaluate(bucket(lifecycle=disabled), now=NOW)
    finding = one(found, RULE_ALL_RULES_DISABLED)
    assert finding.facts["rule_count"] == 3
    assert finding.severity == "medium"
    # The disabled rules protect nothing, so the three hygiene rules fire too.
    assert set(rules_of(found)) == {
        RULE_NO_ABORT_MPU,
        RULE_NO_NONCURRENT_EXPIRY,
        RULE_NO_TRANSITION,
        RULE_ALL_RULES_DISABLED,
    }


def test_no_lifecycle_config_at_all_is_not_all_rules_disabled():
    found = evaluate(bucket(lifecycle_present=False, lifecycle=[]), now=NOW)
    assert RULE_ALL_RULES_DISABLED not in rules_of(found)
    assert len(found) == 3


def test_findings_come_back_in_rule_order():
    found = evaluate(
        bucket(
            lifecycle=[dict(ABORT_RULE, Status="Disabled")],
            metrics={"bytes_standard": GIB, "bytes_noncurrent": GIB},
        ),
        now=NOW,
    )
    assert rules_of(found) == [
        RULE_NO_ABORT_MPU,
        RULE_NO_NONCURRENT_EXPIRY,
        RULE_NO_TRANSITION,
        RULE_ALL_RULES_DISABLED,
    ]


# --- filters, rates, helpers ----------------------------------------------------


def test_ignored_bucket_produces_nothing_at_all():
    naked = bucket(name="my-archive", lifecycle_present=False, lifecycle=[])
    assert evaluate_all([naked], now=NOW)
    assert evaluate_all([naked], now=NOW, ignore_buckets=["my-archive"]) == []


def test_ignore_rule_mutes_only_its_target():
    naked = bucket(lifecycle_present=False, lifecycle=[])
    found = evaluate_all([naked], now=NOW, ignore_rules=[RULE_NO_TRANSITION])
    assert RULE_NO_TRANSITION not in rules_of(found)
    assert RULE_NO_ABORT_MPU in rules_of(found)


def test_min_monthly_usd_and_severity_filters():
    rich = bucket(
        name="big",
        lifecycle_present=False,
        lifecycle=[],
        versioning="Disabled",
        metrics={"bytes_standard": 4096 * GIB},
    )
    assert len(evaluate_all([rich], now=NOW)) == 2
    only_expensive = evaluate_all([rich], now=NOW, min_monthly_usd=5.0)
    assert rules_of(only_expensive) == [RULE_NO_TRANSITION]
    assert rules_of(evaluate_all([rich], now=NOW, min_severity="high")) == [RULE_NO_TRANSITION]


def test_custom_rates_change_the_estimate():
    cold = bucket(
        lifecycle=[ABORT_RULE, NONCURRENT_RULE],
        metrics={"bytes_standard": 1000 * GIB},
    )
    finding = one(evaluate(cold, standard_rate=0.1, ia_rate=0.05, now=NOW), RULE_NO_TRANSITION)
    assert finding.monthly_usd == pytest.approx(50.0, abs=0.01)


def test_ia_rate_above_standard_never_reports_a_negative_saving():
    cold = bucket(lifecycle=[ABORT_RULE, NONCURRENT_RULE], metrics={"bytes_standard": 10 * GIB})
    finding = one(evaluate(cold, standard_rate=0.01, ia_rate=0.05, now=NOW), RULE_NO_TRANSITION)
    assert finding.monthly_usd == 0.0


def test_severity_thresholds():
    assert severity_for(0.0) == "low"
    assert severity_for(1.0) == "medium"
    assert severity_for(9.99) == "medium"
    assert severity_for(10.0) == "high"
    assert severity_for(0.0, floor="medium") == "medium"
    assert severity_for(50.0, floor="medium") == "high"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-10-04T00:00:00Z", 10),
        ("2026-10-04T00:00:00+00:00", 10),
        ("2026-10-14T00:00:00Z", 0),
        ("not-a-date", None),
        (None, None),
    ],
)
def test_oldest_upload_age_days(value, expected):
    assert oldest_upload_age_days({"oldest_initiated": value}, now=NOW) == expected


def test_precomputed_age_wins():
    assert oldest_upload_age_days({"oldest_age_days": 42, "oldest_initiated": "2026-01-01Z"}) == 42


def test_parse_timestamp_makes_naive_input_utc():
    assert parse_timestamp("2026-10-14T00:00:00") == NOW
    assert parse_timestamp(dt.datetime(2026, 10, 14)) == NOW
    assert parse_timestamp("") is None


def test_should_fail_matches_rules_and_all():
    found = evaluate(bucket(lifecycle_present=False, lifecycle=[]), now=NOW)
    assert should_fail(found, [RULE_NO_ABORT_MPU]) is True
    assert should_fail(found, [RULE_ALL_RULES_DISABLED]) is False
    assert should_fail(found, ["all"]) is True
    assert should_fail(found, []) is False
    assert should_fail([], ["all"]) is False


def test_unknown_rules_lists_typos_only():
    assert unknown_rules(["no-abort-mpu", "all"]) == []
    assert unknown_rules(["no-abort-mpus"]) == ["no-abort-mpus"]


def test_summary_rolls_up_waste_worst_bucket_first():
    buckets = [
        bucket(name="small", lifecycle_present=False, lifecycle=[],
               metrics={"bytes_standard": 10 * GIB, "bytes_noncurrent": 0}),
        bucket(name="huge", lifecycle_present=False, lifecycle=[],
               metrics={"bytes_standard": 4096 * GIB, "bytes_noncurrent": 0}),
    ]
    found = evaluate_all(buckets, now=NOW)
    stats = summarize(found, buckets_scanned=2)
    assert stats["buckets_scanned"] == 2
    assert stats["buckets_with_findings"] == 2
    assert stats["by_rule"][RULE_NO_TRANSITION] == 2
    assert [b["bucket"] for b in stats["worst_buckets"]] == ["huge", "small"]
    assert stats["estimated_monthly_usd"] > 40


def test_suggest_lifecycle_adds_only_missing_rules():
    found = evaluate(bucket(lifecycle=[NONCURRENT_RULE, TRANSITION_RULE]), now=NOW)
    config = suggest_lifecycle(found)
    assert [r["ID"] for r in config["Rules"]] == ["abort-incomplete-multipart-upload"]
    assert config["Rules"][0]["AbortIncompleteMultipartUpload"]["DaysAfterInitiation"] == 7


def test_suggest_lifecycle_is_empty_for_a_clean_bucket():
    assert suggest_lifecycle(evaluate(bucket(), now=NOW)) == {"Rules": []}


def test_finding_as_dict_is_json_shaped():
    finding = one(evaluate(bucket(lifecycle=[NONCURRENT_RULE, TRANSITION_RULE]), now=NOW),
                  RULE_NO_ABORT_MPU)
    data = finding.as_dict()
    assert set(data) == {
        "bucket", "region", "rule", "severity", "detail",
        "wasted_bytes", "monthly_usd", "facts",
    }
    assert isinstance(data["wasted_bytes"], int)
