"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .pricing import (
    DEFAULT_STANDARD_IA_USD_PER_GB_MONTH,
    DEFAULT_STANDARD_USD_PER_GB_MONTH,
)
from .report import render
from .rules import (
    ALL_RULES,
    SEVERITIES,
    evaluate_all,
    should_fail,
    suggest_lifecycle,
    unknown_rules,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def _csv(values: Sequence[str]) -> List[str]:
    """``--flag a,b --flag c`` and ``--flag a --flag b`` mean the same thing."""
    out: List[str] = []
    for value in values or ():
        out.extend(part.strip() for part in str(value).split(",") if part.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-s3-lifecycle-audit",
        description="Report the S3 lifecycle rules your buckets are missing, with the bytes "
        "and the monthly dollars behind each one.",
        epilog="rules: " + ", ".join(ALL_RULES),
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--region",
        action="append",
        default=[],
        metavar="REGION",
        help="only buckets in this region; repeatable or comma-separated",
    )
    parser.add_argument(
        "--ignore-bucket",
        action="append",
        default=[],
        metavar="BUCKET",
        help="bucket that is deliberately exempt; repeatable or comma-separated",
    )
    parser.add_argument(
        "--ignore-rule", action="append", default=[], metavar="RULE", help="rule to mute"
    )
    parser.add_argument(
        "--fail-on",
        action="append",
        default=[],
        metavar="RULES",
        help="exit 1 when one of these rules fires; 'all' means any finding",
    )
    parser.add_argument("--min-monthly-usd", type=float, default=0.0, metavar="USD")
    parser.add_argument("--severity", choices=SEVERITIES, default="low", help="minimum severity")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="walk object versions to measure noncurrent bytes exactly (slow, extra API calls)",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--standard-rate",
        type=float,
        default=DEFAULT_STANDARD_USD_PER_GB_MONTH,
        metavar="USD",
        help="STANDARD $/GB-month (default %(default)s, us-east-1 list price)",
    )
    parser.add_argument(
        "--ia-rate",
        type=float,
        default=DEFAULT_STANDARD_IA_USD_PER_GB_MONTH,
        metavar="USD",
        help="STANDARD_IA $/GB-month (default %(default)s)",
    )
    parser.add_argument(
        "--input",
        metavar="FILE",
        help="score a collected snapshot instead of calling AWS ('-' for stdin)",
    )
    parser.add_argument(
        "--dump-input",
        metavar="FILE",
        help="write the collected snapshot here, so a later run can be replayed offline",
    )
    parser.add_argument(
        "--emit-lifecycle",
        metavar="DIR",
        help="write <bucket>.json per flagged bucket: a lifecycle config adding only "
        "the missing rules",
    )
    return parser


def _load_snapshot(path: str) -> List[Dict[str, Any]]:
    if path == "-":
        data = json.load(sys.stdin)
    else:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    if isinstance(data, dict):
        data = data.get("buckets", data.get("Buckets", []))
    if not isinstance(data, list):
        raise ValueError("snapshot must be a list of buckets or {'buckets': [...]}")
    for bucket in data:
        if not isinstance(bucket, dict) or "name" not in bucket:
            raise ValueError("every bucket in the snapshot needs a 'name'")
    return data


def _write_emitted(directory: str, findings) -> int:
    os.makedirs(directory, exist_ok=True)
    by_bucket: Dict[str, List[Any]] = {}
    for finding in findings:
        by_bucket.setdefault(finding.bucket, []).append(finding)
    written = 0
    for bucket, items in sorted(by_bucket.items()):
        config = suggest_lifecycle(items)
        if not config["Rules"]:
            continue
        path = os.path.join(directory, "%s.json" % bucket)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
            handle.write("\n")
        written += 1
    return written


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    fail_on = _csv(args.fail_on)
    ignore_rules = _csv(args.ignore_rule)
    bad = unknown_rules(fail_on + ignore_rules)
    if bad:
        parser.error("unknown rule(s): %s" % ", ".join(sorted(set(bad))))

    regions = _csv(args.region)
    ignore_buckets = _csv(args.ignore_bucket)

    try:
        if args.input:
            buckets = _load_snapshot(args.input)
            if regions:
                buckets = [b for b in buckets if b.get("region") in set(regions)]
        else:
            from .collect import collect, default_session

            session = default_session(args.profile, regions[0] if len(regions) == 1 else None)
            buckets = collect(
                session,
                regions=regions,
                ignore_buckets=ignore_buckets,
                deep=args.deep,
            )
    except Exception as error:  # noqa: BLE001 - one message beats a traceback
        sys.stderr.write("error: %s\n" % error)
        return EXIT_ERROR

    if args.dump_input:
        with open(args.dump_input, "w", encoding="utf-8") as handle:
            json.dump({"buckets": buckets}, handle, indent=2, default=str)
            handle.write("\n")

    findings = evaluate_all(
        buckets,
        standard_rate=args.standard_rate,
        ia_rate=args.ia_rate,
        ignore_buckets=ignore_buckets,
        ignore_rules=ignore_rules,
        min_monthly_usd=args.min_monthly_usd,
        min_severity=args.severity,
    )

    extra = None
    if args.emit_lifecycle:
        written = _write_emitted(args.emit_lifecycle, findings)
        extra = {"emitted_lifecycle_files": written, "emitted_lifecycle_dir": args.emit_lifecycle}

    sys.stdout.write(render(findings, args.format, len(buckets), extra))

    if should_fail(findings, fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
