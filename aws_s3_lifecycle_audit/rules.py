"""The rule engine: plain dicts in, findings out.

Nothing here touches AWS, the clock, the filesystem or argv. A bucket is a dict
shaped like this (every key optional except ``name``)::

    {
      "name": "build-artifacts",
      "region": "eu-central-1",
      "lifecycle_present": True,
      "lifecycle": [ {"ID": "...", "Status": "Enabled", ...} ],   # raw S3 rule dicts
      "versioning": "Enabled",                                    # Enabled|Suspended|Disabled
      "metrics": {"bytes_standard": 0, "bytes_noncurrent": None, "objects": 0},
      "multipart": {"upload_count": 0, "part_bytes": 0,
                    "oldest_initiated": "2025-01-01T00:00:00Z", "part_bytes_known": True},
    }

``collect.py`` builds those dicts from boto3; the tests build them by hand. That split
is the whole point: the rules are testable with no credentials and no network.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .pricing import (
    DEFAULT_STANDARD_IA_USD_PER_GB_MONTH,
    DEFAULT_STANDARD_USD_PER_GB_MONTH,
    human_bytes,
    monthly_usd,
    savings_usd,
)

RULE_NO_ABORT_MPU = "no-abort-mpu"
RULE_NO_NONCURRENT_EXPIRY = "no-noncurrent-expiry"
RULE_NO_TRANSITION = "no-transition"
RULE_ALL_RULES_DISABLED = "all-rules-disabled"

ALL_RULES: Sequence[str] = (
    RULE_NO_ABORT_MPU,
    RULE_NO_NONCURRENT_EXPIRY,
    RULE_NO_TRANSITION,
    RULE_ALL_RULES_DISABLED,
)

SEVERITIES: Sequence[str] = ("low", "medium", "high")
_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# Dollars per month at which a finding stops being paperwork.
_SEVERITY_HIGH_USD = 10.0
_SEVERITY_MEDIUM_USD = 1.0


@dataclass
class Finding:
    """One missing lifecycle rule on one bucket."""

    bucket: str
    rule: str
    severity: str
    detail: str
    region: Optional[str] = None
    wasted_bytes: int = 0
    monthly_usd: float = 0.0
    facts: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "bucket": self.bucket,
            "region": self.region,
            "rule": self.rule,
            "severity": self.severity,
            "detail": self.detail,
            "wasted_bytes": int(self.wasted_bytes),
            "monthly_usd": round(float(self.monthly_usd), 2),
            "facts": dict(self.facts),
        }


def severity_for(usd: float, floor: str = "low") -> str:
    """Severity from estimated monthly dollars, never below ``floor``."""
    if usd >= _SEVERITY_HIGH_USD:
        guess = "high"
    elif usd >= _SEVERITY_MEDIUM_USD:
        guess = "medium"
    else:
        guess = "low"
    if _SEVERITY_RANK[floor] > _SEVERITY_RANK[guess]:
        return floor
    return guess


def _lifecycle_rules(bucket: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(bucket.get("lifecycle") or [])


def _enabled(rules: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rules if str(r.get("Status", "")).strip().lower() == "enabled"]


def has_abort_mpu(rules: Iterable[Dict[str, Any]]) -> bool:
    for rule in rules:
        abort = rule.get("AbortIncompleteMultipartUpload")
        if isinstance(abort, dict) and abort.get("DaysAfterInitiation") is not None:
            return True
    return False


def has_noncurrent_expiry(rules: Iterable[Dict[str, Any]]) -> bool:
    for rule in rules:
        expiry = rule.get("NoncurrentVersionExpiration")
        if isinstance(expiry, dict) and expiry:
            return True
    return False


def has_transition(rules: Iterable[Dict[str, Any]]) -> bool:
    for rule in rules:
        if rule.get("Transitions") or rule.get("NoncurrentVersionTransitions"):
            return True
        # The XML-ish single-transition shape some tools and older configs emit.
        if isinstance(rule.get("Transition"), dict) and rule["Transition"]:
            return True
    return False


def parse_timestamp(value: Any) -> Optional[dt.datetime]:
    """ISO-8601 (or a datetime) to an aware UTC datetime. ``None`` when unparseable."""
    if isinstance(value, dt.datetime):
        stamp = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            stamp = dt.datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.timezone.utc)
    return stamp.astimezone(dt.timezone.utc)


def oldest_upload_age_days(
    multipart: Dict[str, Any], now: Optional[dt.datetime] = None
) -> Optional[int]:
    """Age of the oldest incomplete upload, in whole days.

    A collector that already did the arithmetic can pass ``oldest_age_days``; otherwise
    the age comes from ``oldest_initiated`` against ``now`` (UTC, injected so the tests
    are not a function of today's date).
    """
    direct = multipart.get("oldest_age_days")
    if direct is not None:
        try:
            return int(direct)
        except (TypeError, ValueError):
            return None
    started = parse_timestamp(multipart.get("oldest_initiated"))
    if started is None:
        return None
    reference = now or dt.datetime.now(dt.timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=dt.timezone.utc)
    return max(0, (reference - started).days)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def evaluate(
    bucket: Dict[str, Any],
    standard_rate: float = DEFAULT_STANDARD_USD_PER_GB_MONTH,
    ia_rate: float = DEFAULT_STANDARD_IA_USD_PER_GB_MONTH,
    now: Optional[dt.datetime] = None,
) -> List[Finding]:
    """Every finding for one bucket, in a stable order."""
    name = bucket["name"]
    region = bucket.get("region")
    rules = _lifecycle_rules(bucket)
    enabled = _enabled(rules)
    present = bucket.get("lifecycle_present", bool(rules))
    versioning = str(bucket.get("versioning") or "Disabled")
    metrics = bucket.get("metrics") or {}
    multipart = bucket.get("multipart") or {}

    findings: List[Finding] = []

    def add(rule: str, detail: str, wasted: int, usd: float, floor: str, **facts: Any) -> None:
        findings.append(
            Finding(
                bucket=name,
                rule=rule,
                severity=severity_for(usd, floor),
                detail=detail,
                region=region,
                wasted_bytes=wasted,
                monthly_usd=usd,
                facts=facts,
            )
        )

    # 1. Incomplete multipart uploads that nothing will ever clean up.
    if not has_abort_mpu(enabled):
        part_bytes = _int(multipart.get("part_bytes"))
        uploads = _int(multipart.get("upload_count"))
        known = multipart.get("part_bytes_known", True)
        age = oldest_upload_age_days(multipart, now)
        usd = monthly_usd(part_bytes, standard_rate)
        if uploads == 0:
            detail = "no AbortIncompleteMultipartUpload rule; no incomplete uploads right now"
        elif not known:
            detail = "no AbortIncompleteMultipartUpload rule; %d incomplete upload(s), part size not readable" % uploads
        else:
            detail = "no AbortIncompleteMultipartUpload rule; %d incomplete upload(s) holding %s" % (
                uploads,
                human_bytes(part_bytes),
            )
        if age is not None and uploads:
            detail += ", oldest %d day(s) old" % age
        add(
            RULE_NO_ABORT_MPU,
            detail,
            part_bytes,
            usd,
            "low",
            upload_count=uploads,
            part_bytes=part_bytes,
            part_bytes_known=bool(known),
            oldest_age_days=age,
        )

    # 2. Versioning on, nothing expiring the old versions.
    if versioning.strip().lower() == "enabled" and not has_noncurrent_expiry(enabled):
        noncurrent = metrics.get("bytes_noncurrent")
        if noncurrent is None:
            detail = (
                "versioning enabled, no NoncurrentVersionExpiration rule; "
                "noncurrent bytes unknown (run with --deep)"
            )
            add(
                RULE_NO_NONCURRENT_EXPIRY,
                detail,
                0,
                0.0,
                "medium",
                noncurrent_bytes=None,
                versioning=versioning,
            )
        else:
            nbytes = _int(noncurrent)
            usd = monthly_usd(nbytes, standard_rate)
            detail = "versioning enabled, no NoncurrentVersionExpiration rule; %s in noncurrent versions" % human_bytes(
                nbytes
            )
            add(
                RULE_NO_NONCURRENT_EXPIRY,
                detail,
                nbytes,
                usd,
                "medium",
                noncurrent_bytes=nbytes,
                noncurrent_version_count=metrics.get("noncurrent_version_count"),
                versioning=versioning,
            )

    # 3. Everything sitting in STANDARD forever.
    if not has_transition(enabled):
        current = _int(metrics.get("bytes_standard"))
        usd = savings_usd(current, standard_rate, ia_rate)
        detail = "no transition rule; %s in STANDARD, ~$%.2f/mo cheaper in STANDARD_IA" % (
            human_bytes(current),
            usd,
        )
        add(
            RULE_NO_TRANSITION,
            detail,
            current,
            usd,
            "low",
            standard_bytes=current,
            standard_rate=standard_rate,
            ia_rate=ia_rate,
        )

    # 4. Config theater: a lifecycle config that exists and does nothing.
    if present and rules and not enabled:
        detail = "lifecycle config has %d rule(s), every one Status=Disabled" % len(rules)
        add(
            RULE_ALL_RULES_DISABLED,
            detail,
            0,
            0.0,
            "medium",
            rule_count=len(rules),
            rule_ids=[r.get("ID") for r in rules],
        )

    order = {rule: i for i, rule in enumerate(ALL_RULES)}
    findings.sort(key=lambda f: order.get(f.rule, len(order)))
    return findings


def evaluate_all(
    buckets: Iterable[Dict[str, Any]],
    standard_rate: float = DEFAULT_STANDARD_USD_PER_GB_MONTH,
    ia_rate: float = DEFAULT_STANDARD_IA_USD_PER_GB_MONTH,
    now: Optional[dt.datetime] = None,
    ignore_buckets: Sequence[str] = (),
    ignore_rules: Sequence[str] = (),
    min_monthly_usd: float = 0.0,
    min_severity: str = "low",
) -> List[Finding]:
    """Findings for many buckets, with the exemptions applied.

    An ignored bucket is skipped before evaluation, so it cannot produce a finding by
    any path — that is stronger than filtering the output and easier to trust.
    """
    skip = {b.strip() for b in ignore_buckets if b and b.strip()}
    muted = {r.strip() for r in ignore_rules if r and r.strip()}
    floor = _SEVERITY_RANK[min_severity]
    out: List[Finding] = []
    for bucket in buckets:
        if bucket.get("name") in skip:
            continue
        for finding in evaluate(bucket, standard_rate, ia_rate, now):
            if finding.rule in muted:
                continue
            if finding.monthly_usd < min_monthly_usd:
                continue
            if _SEVERITY_RANK[finding.severity] < floor:
                continue
            out.append(finding)
    return out


def summarize(findings: Sequence[Finding], buckets_scanned: int = 0) -> Dict[str, Any]:
    """Counts per rule plus the account-wide waste rollup, worst bucket first."""
    by_rule: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    per_bucket: Dict[str, float] = {}
    total = 0.0
    for finding in findings:
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        per_bucket[finding.bucket] = round(
            per_bucket.get(finding.bucket, 0.0) + finding.monthly_usd, 2
        )
        total += finding.monthly_usd
    worst = sorted(per_bucket.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "buckets_scanned": buckets_scanned,
        "buckets_with_findings": len(per_bucket),
        "findings": len(findings),
        "estimated_monthly_usd": round(total, 2),
        "by_rule": by_rule,
        "by_severity": by_severity,
        "worst_buckets": [{"bucket": b, "monthly_usd": usd} for b, usd in worst],
    }


def should_fail(findings: Sequence[Finding], fail_on: Sequence[str]) -> bool:
    """True when any finding matches ``fail_on``. ``all`` matches every rule."""
    wanted = {r.strip() for r in fail_on if r and r.strip()}
    if not wanted:
        return False
    if "all" in wanted:
        return bool(findings)
    return any(f.rule in wanted for f in findings)


def unknown_rules(names: Iterable[str]) -> List[str]:
    known = set(ALL_RULES) | {"all"}
    return [n for n in names if n and n.strip() and n.strip() not in known]


# Defaults the suggester writes into generated lifecycle rules. Conservative on
# purpose: 7 days for abandoned parts, 30 for old versions and cold objects. The
# shortest transition S3 accepts is 30 days, so that number is not a taste call.
SUGGEST_ABORT_DAYS = 7
SUGGEST_NONCURRENT_DAYS = 30
SUGGEST_TRANSITION_DAYS = 30


def suggest_lifecycle(findings: Sequence[Finding]) -> Dict[str, Any]:
    """A ready-to-apply ``LifecycleConfiguration`` adding only the missing rules."""
    rules: List[Dict[str, Any]] = []
    fired = {f.rule for f in findings}
    if RULE_NO_ABORT_MPU in fired:
        rules.append(
            {
                "ID": "abort-incomplete-multipart-upload",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": SUGGEST_ABORT_DAYS},
            }
        )
    if RULE_NO_NONCURRENT_EXPIRY in fired:
        rules.append(
            {
                "ID": "expire-noncurrent-versions",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "NoncurrentVersionExpiration": {"NoncurrentDays": SUGGEST_NONCURRENT_DAYS},
            }
        )
    if RULE_NO_TRANSITION in fired:
        rules.append(
            {
                "ID": "transition-to-standard-ia",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Transitions": [
                    {"Days": SUGGEST_TRANSITION_DAYS, "StorageClass": "STANDARD_IA"}
                ],
            }
        )
    return {"Rules": rules}
