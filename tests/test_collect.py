"""Collector tests against a hand-rolled fake session.

The fake speaks the slice of the boto3 surface the collector uses: ``client()``,
a handful of calls, ``get_paginator().paginate()`` and botocore-shaped errors. That is
enough to pin the adapter's behaviour — including the AccessDenied degradation paths —
without moto, without credentials and without the network.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aws_s3_lifecycle_audit import collect as collector

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)


class ClientError(Exception):
    """Same shape as botocore's: ``error.response['Error']['Code']``."""

    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        return list(self._pages)


class FakeS3:
    def __init__(self, state):
        self.state = state
        self.calls = []

    def _bucket(self, name):
        return self.state["buckets"][name]

    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": name, "CreationDate": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)}
                for name in self.state["buckets"]
            ]
        }

    def get_bucket_location(self, Bucket):  # noqa: N803 - boto3 naming
        self.calls.append(("location", Bucket))
        value = self._bucket(Bucket).get("location", "eu-central-1")
        if isinstance(value, Exception):
            raise value
        return {"LocationConstraint": value}

    def get_bucket_lifecycle_configuration(self, Bucket):  # noqa: N803
        value = self._bucket(Bucket).get("lifecycle")
        if isinstance(value, Exception):
            raise value
        return {"Rules": value}

    def get_bucket_versioning(self, Bucket):  # noqa: N803
        value = self._bucket(Bucket).get("versioning")
        if isinstance(value, Exception):
            raise value
        return {"Status": value} if value else {}

    def get_paginator(self, name):
        if name == "list_multipart_uploads":
            value = self.state["mpu"]
            if isinstance(value, Exception):
                raise value
            return _Paginator([{"Uploads": value}])
        if name == "list_parts":
            value = self.state["parts"]
            if isinstance(value, Exception):
                raise value
            return _Paginator([{"Parts": value}])
        if name == "list_object_versions":
            return _Paginator([{"Versions": self.state["versions"]}])
        raise AssertionError("unexpected paginator %s" % name)


class FakeCloudWatch:
    def __init__(self, state):
        self.state = state

    def get_metric_statistics(self, **kwargs):
        value = self.state["metrics"].get(kwargs["MetricName"])
        if isinstance(value, Exception):
            raise value
        if value is None:
            return {"Datapoints": []}
        return {
            "Datapoints": [
                {"Timestamp": dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc), "Average": value / 2},
                {"Timestamp": dt.datetime(2026, 10, 13, tzinfo=dt.timezone.utc), "Average": value},
            ]
        }


class FakeSession:
    def __init__(self, **state):
        self.state = {
            "buckets": {},
            "mpu": [],
            "parts": [],
            "versions": [],
            "metrics": {},
        }
        self.state.update(state)

    def client(self, service, region_name=None):
        if service == "s3":
            return FakeS3(self.state)
        if service == "cloudwatch":
            return FakeCloudWatch(self.state)
        raise AssertionError("unexpected service %s" % service)


def test_collect_builds_engine_shaped_dicts():
    session = FakeSession(
        buckets={
            "one": {
                "location": "eu-central-1",
                "versioning": "Enabled",
                "lifecycle": [{"ID": "x", "Status": "Enabled"}],
            }
        },
        mpu=[{"Key": "big.tar", "UploadId": "u1",
              "Initiated": dt.datetime(2026, 9, 14, tzinfo=dt.timezone.utc)}],
        parts=[{"Size": 5 * 1024 ** 3}],
        metrics={"BucketSizeBytes": 1024 ** 4, "NumberOfObjects": 1234},
    )
    buckets = collector.collect(session, now=NOW)
    assert len(buckets) == 1
    bucket = buckets[0]
    assert bucket["name"] == "one"
    assert bucket["region"] == "eu-central-1"
    assert bucket["lifecycle_present"] is True
    assert bucket["versioning"] == "Enabled"
    assert bucket["metrics"]["bytes_standard"] == 1024 ** 4
    assert bucket["metrics"]["objects"] == 1234
    assert bucket["metrics"]["bytes_noncurrent"] is None
    assert bucket["multipart"]["upload_count"] == 1
    assert bucket["multipart"]["part_bytes"] == 5 * 1024 ** 3
    assert bucket["multipart"]["oldest_age_days"] == 30


def test_latest_datapoint_wins():
    session = FakeSession(
        buckets={"one": {"versioning": "Disabled", "lifecycle": []}},
        metrics={"BucketSizeBytes": 400, "NumberOfObjects": None},
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["metrics"]["bytes_standard"] == 400
    assert bucket["metrics"]["objects"] is None


def test_missing_lifecycle_config_is_not_an_error():
    session = FakeSession(
        buckets={
            "one": {
                "versioning": "Disabled",
                "lifecycle": ClientError("NoSuchLifecycleConfiguration"),
            }
        }
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["lifecycle_present"] is False
    assert bucket["lifecycle"] == []
    assert "lifecycle_unknown" not in bucket


def test_denied_lifecycle_is_marked_unknown_not_absent():
    session = FakeSession(
        buckets={"one": {"versioning": "Disabled", "lifecycle": ClientError("AccessDenied")}}
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["lifecycle_unknown"] is True


def test_denied_versioning_and_metrics_degrade_to_unknown():
    session = FakeSession(
        buckets={"one": {"versioning": ClientError("AccessDenied"), "lifecycle": []}},
        metrics={"BucketSizeBytes": ClientError("AccessDenied")},
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["versioning"] == "Unknown"
    assert bucket["metrics"]["bytes_standard_known"] is False


def test_denied_part_listing_keeps_the_upload_count():
    session = FakeSession(
        buckets={"one": {"versioning": "Disabled", "lifecycle": []}},
        mpu=[{"Key": "k", "UploadId": "u",
              "Initiated": dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)}],
        parts=ClientError("AccessDenied"),
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["multipart"]["upload_count"] == 1
    assert bucket["multipart"]["part_bytes_known"] is False


def test_denied_multipart_listing_is_survivable():
    session = FakeSession(
        buckets={"one": {"versioning": "Disabled", "lifecycle": []}},
        mpu=ClientError("AccessDenied"),
    )
    bucket = collector.collect(session, now=NOW)[0]
    assert bucket["multipart"]["unknown"] is True


def test_an_unexpected_error_is_not_swallowed():
    session = FakeSession(
        buckets={"one": {"versioning": ClientError("ThrottlingException"), "lifecycle": []}}
    )
    with pytest.raises(ClientError):
        collector.collect(session, now=NOW)


@pytest.mark.parametrize(
    "constraint,expected",
    [(None, "us-east-1"), ("", "us-east-1"), ("EU", "eu-west-1"), ("ap-south-1", "ap-south-1")],
)
def test_location_constraint_quirks(constraint, expected):
    session = FakeSession(buckets={"one": {"location": constraint}})
    assert collector.bucket_region(session, "one") == expected


def test_region_filter_and_ignore_list_skip_buckets():
    session = FakeSession(
        buckets={
            "here": {"location": "eu-central-1", "versioning": "Disabled", "lifecycle": []},
            "there": {"location": "us-east-1", "versioning": "Disabled", "lifecycle": []},
            "muted": {"location": "eu-central-1", "versioning": "Disabled", "lifecycle": []},
        }
    )
    names = [b["name"] for b in collector.collect(session, regions=["eu-central-1"],
                                                  ignore_buckets=["muted"], now=NOW)]
    assert names == ["here"]


def test_deep_scan_sums_noncurrent_versions_only():
    session = FakeSession(
        buckets={"one": {"versioning": "Enabled", "lifecycle": []}},
        versions=[
            {"Size": 100, "IsLatest": True},
            {"Size": 40, "IsLatest": False},
            {"Size": 60, "IsLatest": False},
        ],
    )
    bucket = collector.collect(session, deep=True, now=NOW)[0]
    assert bucket["metrics"]["bytes_noncurrent"] == 100
    assert bucket["metrics"]["noncurrent_version_count"] == 2


def test_deep_scan_is_skipped_when_versioning_is_off():
    session = FakeSession(
        buckets={"one": {"versioning": "Suspended", "lifecycle": []}},
        versions=[{"Size": 40, "IsLatest": False}],
    )
    bucket = collector.collect(session, deep=True, now=NOW)[0]
    assert bucket["metrics"]["bytes_noncurrent"] is None


def test_on_bucket_callback_fires_per_bucket():
    session = FakeSession(
        buckets={
            "a": {"versioning": "Disabled", "lifecycle": []},
            "b": {"versioning": "Disabled", "lifecycle": []},
        }
    )
    seen = []
    collector.collect(session, now=NOW, on_bucket=lambda b: seen.append(b["name"]))
    assert seen == ["a", "b"]
