"""Rendering: findings to a text table or to JSON."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from .pricing import human_bytes
from .rules import Finding, summarize

_COLUMNS = ("BUCKET", "RULE", "SEV", "WASTED", "$/MO", "DETAIL")


def _rows(findings: Sequence[Finding]) -> List[List[str]]:
    rows = []
    for finding in findings:
        rows.append(
            [
                finding.bucket,
                finding.rule,
                finding.severity,
                human_bytes(finding.wasted_bytes) if finding.wasted_bytes else "-",
                "%.2f" % finding.monthly_usd if finding.monthly_usd else "-",
                finding.detail,
            ]
        )
    return rows


def text_report(findings: Sequence[Finding], buckets_scanned: int = 0, show_summary: bool = True) -> str:
    """A padded table plus the account rollup. The last column is left unpadded."""
    if not findings:
        return "No lifecycle findings across %d bucket(s).\n" % buckets_scanned

    rows = _rows(findings)
    widths = [len(c) for c in _COLUMNS]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: Sequence[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            parts.append(cell if i == len(cells) - 1 else cell.ljust(widths[i]))
        return "  ".join(parts).rstrip()

    out = [line(_COLUMNS), line(["-" * w for w in widths])]
    out.extend(line(row) for row in rows)

    if show_summary:
        stats = summarize(findings, buckets_scanned)
        out.append("")
        out.append(
            "%d finding(s) on %d of %d bucket(s); estimated waste $%.2f/mo"
            % (
                stats["findings"],
                stats["buckets_with_findings"],
                buckets_scanned,
                stats["estimated_monthly_usd"],
            )
        )
        for rule, count in sorted(stats["by_rule"].items()):
            out.append("  %-24s %d" % (rule, count))
        worst = [b for b in stats["worst_buckets"] if b["monthly_usd"] > 0][:5]
        if worst:
            out.append("worst buckets:")
            for item in worst:
                out.append("  %-40s $%.2f/mo" % (item["bucket"], item["monthly_usd"]))
    return "\n".join(out) + "\n"


def json_report(
    findings: Sequence[Finding], buckets_scanned: int = 0, extra: Dict[str, Any] = None
) -> str:
    payload: Dict[str, Any] = {
        "summary": summarize(findings, buckets_scanned),
        "findings": [f.as_dict() for f in findings],
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2, sort_keys=False, default=str) + "\n"


def render(
    findings: Sequence[Finding],
    fmt: str = "text",
    buckets_scanned: int = 0,
    extra: Dict[str, Any] = None,
) -> str:
    if fmt == "json":
        return json_report(findings, buckets_scanned, extra)
    if fmt == "text":
        return text_report(findings, buckets_scanned)
    raise ValueError("unknown format: %s" % fmt)
