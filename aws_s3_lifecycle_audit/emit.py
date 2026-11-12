"""``--emit-lifecycle``: findings to lifecycle configs on disk, as JSON or Terraform.

Both shapes replace the bucket's whole lifecycle config when applied
(PutBucketLifecycleConfiguration and ``aws_s3_bucket_lifecycle_configuration`` work
that way), so without ``merge`` they are only safe on a bucket that has no rules yet.
With ``merge`` the existing rules are written back alongside the new ones.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Sequence

from .rules import Finding, merge_lifecycle, parse_timestamp, suggest_lifecycle

EMIT_FORMATS: Sequence[str] = ("json", "terraform")

_EXTENSIONS = {"json": "json", "terraform": "tf"}

#: The non-default TransitionDefaultMinimumObjectSize; the other value is the default.
_NON_DEFAULT_MIN_SIZE = "varies_by_storage_class"


def _date(value: Any) -> Any:
    """Lifecycle dates as RFC 3339 UTC, the form both the AWS CLI and Terraform take."""
    if isinstance(value, (dt.datetime, str)):
        stamp = parse_timestamp(value)
        if stamp is not None:
            return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return value


def _clean_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of one rule with any ``Date`` turned into a JSON-safe string."""
    out = dict(rule)
    if isinstance(out.get("Expiration"), dict) and "Date" in out["Expiration"]:
        out["Expiration"] = dict(out["Expiration"], Date=_date(out["Expiration"]["Date"]))
    if isinstance(out.get("Transitions"), list):
        out["Transitions"] = [
            dict(t, Date=_date(t["Date"])) if isinstance(t, dict) and "Date" in t else t
            for t in out["Transitions"]
        ]
    if isinstance(out.get("Transition"), dict) and "Date" in out["Transition"]:
        out["Transition"] = dict(out["Transition"], Date=_date(out["Transition"]["Date"]))
    return out


# --- Terraform -------------------------------------------------------------------

_RULE_KEYS = {
    "ID",
    "Status",
    "Prefix",
    "Filter",
    "Expiration",
    "Transitions",
    "Transition",
    "NoncurrentVersionTransitions",
    "NoncurrentVersionExpiration",
    "AbortIncompleteMultipartUpload",
}


def _hcl_string(value: Any) -> str:
    # JSON string escapes are valid HCL; template sequences are not literal in HCL.
    return json.dumps(str(value)).replace("${", "$${").replace("%{", "%%{")


def _hcl_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return _hcl_string(value)


def resource_name(bucket: str) -> str:
    """A Terraform identifier from a bucket name. Bucket names have no ``_``, so
    turning dots into ``_`` cannot make two buckets collide."""
    name = re.sub(r"[^A-Za-z0-9_-]", "_", bucket)
    if not re.match(r"[A-Za-z_]", name):
        name = "bucket_" + name
    return name


class _Block:
    """An HCL block: attributes first, then nested blocks separated by blank lines.

    Single-line attributes get their ``=`` aligned the way ``terraform fmt`` does it.
    ``fmt`` leaves a multi-line value (the ``tags`` map) unaligned, and it is always
    the last attribute of its block, so it does not split an alignment group.
    """

    def __init__(self, header: str):
        self.header = header
        self.attrs: List[tuple] = []
        self.blocks: List["_Block"] = []

    def attr(self, key: str, value: Any) -> None:
        if value is not None:
            self.attrs.append((key, value))

    def block(self, header: str) -> "_Block":
        child = _Block(header)
        self.blocks.append(child)
        return child

    def lines(self, indent: str = "") -> List[str]:
        inner = indent + "  "
        if not self.attrs and not self.blocks:
            return [indent + self.header + " {}"]
        out = [indent + self.header + " {"]
        width = max((len(k) for k, v in self.attrs if not isinstance(v, dict)), default=0)
        for key, value in self.attrs:
            if isinstance(value, dict):
                out.append("%s%s = {" % (inner, key))
                tag_width = max((len(_hcl_string(k)) for k in value), default=0)
                for tag_key, tag_value in value.items():
                    out.append(
                        "%s  %s = %s"
                        % (inner, _hcl_string(tag_key).ljust(tag_width), _hcl_string(tag_value))
                    )
                out.append(inner + "}")
            else:
                out.append("%s%s = %s" % (inner, key.ljust(width), _hcl_value(value)))
        for i, child in enumerate(self.blocks):
            if self.attrs or i:
                out.append("")
            out.extend(child.lines(inner))
        out.append(indent + "}")
        return out


def _filter_block(parent: _Block, rule: Dict[str, Any]) -> None:
    rule_filter = rule.get("Filter")
    target = parent.block("filter")
    if rule_filter is None:
        # The deprecated top-level Prefix means the same as a prefix filter, and an
        # absent filter means the whole bucket, which is an empty filter block.
        if "Prefix" in rule:
            target.attr("prefix", rule["Prefix"])
        return
    for key in rule_filter:
        if key not in ("Prefix", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan", "And"):
            raise ValueError("rule %r: unknown Filter key %s" % (rule.get("ID"), key))
    target.attr("object_size_greater_than", rule_filter.get("ObjectSizeGreaterThan"))
    target.attr("object_size_less_than", rule_filter.get("ObjectSizeLessThan"))
    target.attr("prefix", rule_filter.get("Prefix"))
    both = rule_filter.get("And")
    if isinstance(both, dict):
        block = target.block("and")
        block.attr("object_size_greater_than", both.get("ObjectSizeGreaterThan"))
        block.attr("object_size_less_than", both.get("ObjectSizeLessThan"))
        block.attr("prefix", both.get("Prefix"))
        tags = both.get("Tags")
        if tags:
            block.attr("tags", {t["Key"]: t["Value"] for t in tags})
    tag = rule_filter.get("Tag")
    if isinstance(tag, dict):
        block = target.block("tag")
        block.attr("key", tag["Key"])
        block.attr("value", tag["Value"])


def _rule_block(parent: _Block, rule: Dict[str, Any]) -> None:
    unknown = sorted(set(rule) - _RULE_KEYS)
    if unknown:
        # Dropping a field we cannot render would silently change the owner's rule.
        raise ValueError(
            "rule %r: cannot render %s as Terraform" % (rule.get("ID"), ", ".join(unknown))
        )
    block = parent.block("rule")
    block.attr("id", rule.get("ID"))
    block.attr("status", rule.get("Status"))

    abort = rule.get("AbortIncompleteMultipartUpload")
    if isinstance(abort, dict):
        block.block("abort_incomplete_multipart_upload").attr(
            "days_after_initiation", abort.get("DaysAfterInitiation")
        )

    expiration = rule.get("Expiration")
    if isinstance(expiration, dict):
        child = block.block("expiration")
        child.attr("date", _date(expiration.get("Date")))
        child.attr("days", expiration.get("Days"))
        child.attr("expired_object_delete_marker", expiration.get("ExpiredObjectDeleteMarker"))

    _filter_block(block, rule)

    noncurrent = rule.get("NoncurrentVersionExpiration")
    if isinstance(noncurrent, dict):
        child = block.block("noncurrent_version_expiration")
        child.attr("newer_noncurrent_versions", noncurrent.get("NewerNoncurrentVersions"))
        child.attr("noncurrent_days", noncurrent.get("NoncurrentDays"))

    for move in rule.get("NoncurrentVersionTransitions") or []:
        child = block.block("noncurrent_version_transition")
        child.attr("newer_noncurrent_versions", move.get("NewerNoncurrentVersions"))
        child.attr("noncurrent_days", move.get("NoncurrentDays"))
        child.attr("storage_class", move.get("StorageClass"))

    transitions = list(rule.get("Transitions") or [])
    if isinstance(rule.get("Transition"), dict):
        transitions.append(rule["Transition"])
    for move in transitions:
        child = block.block("transition")
        child.attr("date", _date(move.get("Date")))
        child.attr("days", move.get("Days"))
        child.attr("storage_class", move.get("StorageClass"))


def terraform_config(
    bucket: str, config: Dict[str, Any], transition_min_size: Optional[str] = None
) -> str:
    """One ``aws_s3_bucket_lifecycle_configuration`` resource for one bucket."""
    resource = _Block(
        'resource "aws_s3_bucket_lifecycle_configuration" %s' % _hcl_string(resource_name(bucket))
    )
    resource.attr("bucket", bucket)
    resource.attr("transition_default_minimum_object_size", transition_min_size)
    for rule in config["Rules"]:
        _rule_block(resource, rule)
    return "\n".join(resource.lines()) + "\n"


# --- Writing files -----------------------------------------------------------------


def write_emitted(
    directory: str,
    findings: Sequence[Finding],
    buckets: Sequence[Dict[str, Any]],
    fmt: str = "json",
    merge: bool = False,
    warn: Callable[[str], None] = lambda _message: None,
) -> Dict[str, Any]:
    """Write one file per flagged bucket. Returns counts and the buckets skipped.

    ``warn`` gets one line per thing the reader has to know before applying a file.
    """
    if fmt not in EMIT_FORMATS:
        raise ValueError("unknown emit format: %s" % fmt)
    os.makedirs(directory, exist_ok=True)
    known = {b.get("name"): b for b in buckets}
    by_bucket: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_bucket.setdefault(finding.bucket, []).append(finding)

    written = 0
    skipped: List[str] = []
    for name, items in sorted(by_bucket.items()):
        config = suggest_lifecycle(items)
        if not config["Rules"]:
            continue
        bucket = known.get(name) or {}
        existing = [_clean_rule(r) for r in bucket.get("lifecycle") or []]
        min_size = bucket.get("lifecycle_transition_min_size")

        if merge:
            if bucket.get("lifecycle_unknown"):
                warn("%s: lifecycle config not readable (AccessDenied); nothing to merge "
                     "into, skipped" % name)
                skipped.append(name)
                continue
            try:
                config = merge_lifecycle(existing, config)
            except ValueError as error:
                warn("%s: %s; skipped" % (name, error))
                skipped.append(name)
                continue
        elif existing or bucket.get("lifecycle_unknown"):
            what = ("%d existing rule(s)" % len(existing)) if existing else "an unreadable config"
            warn("%s: has %s; applying this file replaces them, use --merge to keep them"
                 % (name, what))

        try:
            if fmt == "terraform":
                body = terraform_config(name, config, min_size if merge else None)
            else:
                body = json.dumps(config, indent=2) + "\n"
        except ValueError as error:
            warn("%s: %s; skipped" % (name, error))
            skipped.append(name)
            continue

        if merge and fmt == "json" and min_size == _NON_DEFAULT_MIN_SIZE:
            warn("%s: TransitionDefaultMinimumObjectSize is %s; pass "
                 "--transition-default-minimum-object-size %s to put-bucket-lifecycle-"
                 "configuration to keep it" % (name, min_size, min_size))

        path = os.path.join(directory, "%s.%s" % (name, _EXTENSIONS[fmt]))
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        written += 1
    return {"written": written, "skipped": skipped}
