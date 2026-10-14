"""Sizes and prices.

Rates are AWS S3 list prices for ``us-east-1``, first 50 TB/month tier, as published
on https://aws.amazon.com/s3/pricing/ and checked 2026-10. They are defaults, not
truth: every rate is overridable from the CLI (``--standard-rate``, ``--ia-rate``),
and a bucket in another region or on a negotiated contract will differ. All dollar
figures this tool prints are estimates derived from bytes times a rate, nothing else.

AWS bills storage per GB where one GB is 2**30 bytes, so that is what ``gib()`` uses.
"""

from __future__ import annotations

GIB = 1024 ** 3

DEFAULT_STANDARD_USD_PER_GB_MONTH = 0.023
DEFAULT_STANDARD_IA_USD_PER_GB_MONTH = 0.0125

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def gib(nbytes: float) -> float:
    """Bytes as GB-months-billable units (2**30 bytes)."""
    return float(nbytes) / GIB


def monthly_usd(nbytes: float, usd_per_gb_month: float) -> float:
    """Monthly dollars for ``nbytes`` held at ``usd_per_gb_month``."""
    return round(gib(nbytes) * float(usd_per_gb_month), 2)


def savings_usd(nbytes: float, from_rate: float, to_rate: float) -> float:
    """Monthly delta from moving ``nbytes`` between two rates. Never negative."""
    delta = float(from_rate) - float(to_rate)
    if delta <= 0:
        return 0.0
    return round(gib(nbytes) * delta, 2)


def human_bytes(nbytes: float) -> str:
    """4096 -> '4.0 KiB'. Used in report text, never in machine output."""
    value = float(nbytes)
    for unit in _UNITS:
        if abs(value) < 1024.0 or unit == _UNITS[-1]:
            if unit == "B":
                return "%d B" % int(value)
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    raise AssertionError("unreachable")
