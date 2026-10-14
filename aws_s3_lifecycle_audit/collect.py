"""The boto3 adapter: AWS in, plain bucket dicts out.

Every call here is read-only. boto3 is imported inside the functions so the rule
engine, the reporter and their tests stay importable with no AWS SDK installed.

Required IAM, nothing more::

    s3:ListAllMyBuckets        list the buckets
    s3:GetBucketLocation       pick the right regional endpoint
    s3:GetLifecycleConfiguration
    s3:GetBucketVersioning
    s3:ListBucketMultipartUploads   + s3:ListMultipartUploadParts for part sizes
    s3:ListBucketVersions      only with --deep
    cloudwatch:GetMetricStatistics  BucketSizeBytes / NumberOfObjects

An AccessDenied on any per-bucket call degrades that one fact to "unknown" and keeps
going, because a half-scanned account is still worth reporting on.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional, Sequence

#: CloudWatch reports daily storage metrics; look back far enough to survive a gap.
METRIC_LOOKBACK_DAYS = 3
METRIC_PERIOD_SECONDS = 86400

#: Cap on per-upload ListParts calls per bucket. A bucket with thousands of abandoned
#: uploads does not need an exact byte count to be worth fixing.
DEFAULT_MAX_MPU_UPLOADS = 200

#: Cap on keys walked by --deep. Noncurrent bytes become a floor, not a total, past it.
DEFAULT_MAX_VERSION_KEYS = 100000


class _Denied(Exception):
    pass


def _code(error: Exception) -> str:
    response = getattr(error, "response", None) or {}
    return str((response.get("Error") or {}).get("Code") or "")


def _client(session, service: str, region: Optional[str]):
    if region:
        return session.client(service, region_name=region)
    return session.client(service)


def list_buckets(session) -> List[Dict[str, Any]]:
    s3 = session.client("s3")
    response = s3.list_buckets()
    out = []
    for bucket in response.get("Buckets", []):
        out.append({"name": bucket["Name"], "created": bucket.get("CreationDate")})
    return out


def bucket_region(session, name: str) -> Optional[str]:
    s3 = session.client("s3")
    try:
        location = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    except Exception as error:  # noqa: BLE001 - a denied location is not fatal
        if _code(error) in ("AccessDenied", "NoSuchBucket"):
            return None
        raise
    # us-east-1 answers with a null constraint, and EU is the legacy alias for eu-west-1.
    if not location:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return location


def lifecycle(session, name: str, region: Optional[str]) -> Dict[str, Any]:
    s3 = _client(session, "s3", region)
    try:
        response = s3.get_bucket_lifecycle_configuration(Bucket=name)
    except Exception as error:  # noqa: BLE001
        code = _code(error)
        if code in ("NoSuchLifecycleConfiguration", "NoSuchConfiguration"):
            return {"lifecycle_present": False, "lifecycle": []}
        if code == "AccessDenied":
            return {"lifecycle_present": False, "lifecycle": [], "lifecycle_unknown": True}
        raise
    return {"lifecycle_present": True, "lifecycle": list(response.get("Rules") or [])}


def versioning(session, name: str, region: Optional[str]) -> str:
    s3 = _client(session, "s3", region)
    try:
        response = s3.get_bucket_versioning(Bucket=name)
    except Exception as error:  # noqa: BLE001
        if _code(error) == "AccessDenied":
            return "Unknown"
        raise
    return str(response.get("Status") or "Disabled")


def multipart(
    session,
    name: str,
    region: Optional[str],
    max_uploads: int = DEFAULT_MAX_MPU_UPLOADS,
    now: Optional[dt.datetime] = None,
) -> Dict[str, Any]:
    """Incomplete uploads, their part bytes and the age of the oldest one.

    ``ListMultipartUploads`` does not return part sizes, so the bytes come from one
    ``ListParts`` walk per upload. That is the only way to price this exposure, and it
    is why ``max_uploads`` exists.
    """
    s3 = _client(session, "s3", region)
    uploads: List[Dict[str, Any]] = []
    try:
        paginator = s3.get_paginator("list_multipart_uploads")
        for page in paginator.paginate(Bucket=name):
            uploads.extend(page.get("Uploads") or [])
            if len(uploads) >= max_uploads:
                break
    except Exception as error:  # noqa: BLE001
        if _code(error) == "AccessDenied":
            return {"upload_count": 0, "part_bytes": 0, "part_bytes_known": False,
                     "oldest_initiated": None, "unknown": True}
        raise

    truncated = len(uploads) > max_uploads
    uploads = uploads[:max_uploads]
    part_bytes = 0
    known = True
    oldest: Optional[dt.datetime] = None
    for upload in uploads:
        initiated = upload.get("Initiated")
        if isinstance(initiated, dt.datetime):
            stamp = initiated if initiated.tzinfo else initiated.replace(tzinfo=dt.timezone.utc)
            if oldest is None or stamp < oldest:
                oldest = stamp
        try:
            parts = s3.get_paginator("list_parts")
            for page in parts.paginate(Bucket=name, Key=upload["Key"], UploadId=upload["UploadId"]):
                for part in page.get("Parts") or []:
                    part_bytes += int(part.get("Size") or 0)
        except Exception as error:  # noqa: BLE001
            if _code(error) in ("AccessDenied", "NoSuchUpload"):
                known = False
                continue
            raise

    out: Dict[str, Any] = {
        "upload_count": len(uploads),
        "part_bytes": part_bytes,
        "part_bytes_known": known,
        "oldest_initiated": oldest.isoformat() if oldest else None,
        "truncated": truncated,
    }
    if oldest is not None:
        reference = now or dt.datetime.now(dt.timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=dt.timezone.utc)
        out["oldest_age_days"] = max(0, (reference - oldest).days)
    return out


def _metric(cw, name: str, metric: str, storage_type: str, now: dt.datetime) -> Optional[float]:
    try:
        response = cw.get_metric_statistics(
            Namespace="AWS/S3",
            MetricName=metric,
            Dimensions=[
                {"Name": "BucketName", "Value": name},
                {"Name": "StorageType", "Value": storage_type},
            ],
            StartTime=now - dt.timedelta(days=METRIC_LOOKBACK_DAYS),
            EndTime=now,
            Period=METRIC_PERIOD_SECONDS,
            Statistics=["Average"],
        )
    except Exception as error:  # noqa: BLE001
        if _code(error) in ("AccessDenied", "AccessDeniedException"):
            return None
        raise
    points = sorted(response.get("Datapoints") or [], key=lambda p: p["Timestamp"])
    if not points:
        return None
    return float(points[-1]["Average"])


def metrics(session, name: str, region: Optional[str], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Current bytes and object count from CloudWatch daily storage metrics.

    ``BucketSizeBytes`` has no noncurrent-version storage type, so noncurrent bytes are
    left as ``None`` here and only filled in by ``deep_noncurrent_bytes``.
    """
    cw = _client(session, "cloudwatch", region)
    reference = now or dt.datetime.now(dt.timezone.utc)
    standard = _metric(cw, name, "BucketSizeBytes", "StandardStorage", reference)
    objects = _metric(cw, name, "NumberOfObjects", "AllStorageTypes", reference)
    return {
        "bytes_standard": int(standard) if standard is not None else 0,
        "bytes_standard_known": standard is not None,
        "bytes_noncurrent": None,
        "objects": int(objects) if objects is not None else None,
    }


def deep_noncurrent_bytes(
    session, name: str, region: Optional[str], max_keys: int = DEFAULT_MAX_VERSION_KEYS
) -> Dict[str, Any]:
    """Sum the versions that are not the latest, by walking ListObjectVersions.

    Expensive and exact, which is the trade --deep makes. Past ``max_keys`` the number
    is a floor and ``truncated`` says so.
    """
    s3 = _client(session, "s3", region)
    total = 0
    count = 0
    seen = 0
    truncated = False
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            for version in page.get("Versions") or []:
                seen += 1
                if not version.get("IsLatest"):
                    total += int(version.get("Size") or 0)
                    count += 1
            seen += len(page.get("DeleteMarkers") or [])
            if seen >= max_keys:
                truncated = True
                break
    except Exception as error:  # noqa: BLE001
        if _code(error) == "AccessDenied":
            return {"bytes_noncurrent": None, "noncurrent_version_count": None}
        raise
    return {
        "bytes_noncurrent": total,
        "noncurrent_version_count": count,
        "noncurrent_truncated": truncated,
    }


def collect(
    session,
    regions: Sequence[str] = (),
    ignore_buckets: Sequence[str] = (),
    deep: bool = False,
    max_mpu_uploads: int = DEFAULT_MAX_MPU_UPLOADS,
    max_version_keys: int = DEFAULT_MAX_VERSION_KEYS,
    now: Optional[dt.datetime] = None,
    on_bucket=None,
) -> List[Dict[str, Any]]:
    """Walk the account and return one dict per bucket, ready for the rule engine."""
    wanted = {r.strip() for r in regions if r and r.strip()}
    skip = {b.strip() for b in ignore_buckets if b and b.strip()}
    out: List[Dict[str, Any]] = []
    for entry in list_buckets(session):
        name = entry["name"]
        if name in skip:
            continue
        region = bucket_region(session, name)
        if wanted and region not in wanted:
            continue
        bucket: Dict[str, Any] = {"name": name, "region": region}
        if entry.get("created") is not None:
            created = entry["created"]
            bucket["created"] = created.isoformat() if hasattr(created, "isoformat") else str(created)
        bucket.update(lifecycle(session, name, region))
        bucket["versioning"] = versioning(session, name, region)
        bucket["metrics"] = metrics(session, name, region, now)
        bucket["multipart"] = multipart(session, name, region, max_mpu_uploads, now)
        if deep and str(bucket["versioning"]).lower() == "enabled":
            bucket["metrics"].update(deep_noncurrent_bytes(session, name, region, max_version_keys))
        out.append(bucket)
        if on_bucket is not None:
            on_bucket(bucket)
    return out


def default_session(profile: Optional[str] = None, region: Optional[str] = None):
    """A boto3 session. Imported here so the rest of the package needs no SDK."""
    import boto3  # noqa: PLC0415 - deliberately lazy

    kwargs: Dict[str, Any] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.session.Session(**kwargs)
