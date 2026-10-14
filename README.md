# aws-s3-lifecycle-audit

[![CI](https://github.com/moveeeax/aws-s3-lifecycle-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-s3-lifecycle-audit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Report the S3 lifecycle rules your buckets are **missing**, with the bytes and the
estimated monthly dollars behind each one.

Lifecycle configuration is the one S3 setting nobody sets at creation time, because an
empty bucket costs nothing and the bill arrives much later. Three failures repeat in
every account:

- a 5 GB upload dies halfway, the parts stay, they are invisible in the console object
  list, and they are billed forever;
- somebody enables versioning for safety, overwrites the same key daily for two years,
  and now pays for 700 copies;
- log and backup prefixes nobody has read since last quarter sit in `STANDARD` at full
  price.

`s3api` can answer each question, one bucket at a time, with a different call and a
different error when the config is absent. This does the whole account in one pass.

## Rules

| rule | fires when | sized from |
| --- | --- | --- |
| `no-abort-mpu` | no enabled `AbortIncompleteMultipartUpload` rule | part bytes of the incomplete uploads + age of the oldest |
| `no-noncurrent-expiry` | versioning is `Enabled` and no enabled `NoncurrentVersionExpiration` rule | noncurrent bytes (`--deep`) |
| `no-transition` | no enabled `Transitions` or `NoncurrentVersionTransitions` rule anywhere | current `STANDARD` bytes, priced as the `STANDARD_IA` delta |
| `all-rules-disabled` | a lifecycle config exists and every rule is `Status=Disabled` | — |

A rule with `Status=Disabled` protects nothing, so it counts as absent. That is why a
bucket whose whole config is disabled reports `all-rules-disabled` **and** the three
hygiene rules: the config theater is one problem, the unguarded bytes are another.

## Install

```shell
pip install git+https://github.com/moveeeax/aws-s3-lifecycle-audit
```

## Usage

```shell
aws-s3-lifecycle-audit
aws-s3-lifecycle-audit --format json | jq '.findings[] | select(.rule=="no-abort-mpu")'
aws-s3-lifecycle-audit --ignore-bucket my-archive --fail-on no-abort-mpu,no-noncurrent-expiry
```

Against the bundled snapshot, no AWS account needed:

```console
$ aws-s3-lifecycle-audit --input examples/snapshot.json
BUCKET           RULE                  SEV     WASTED     $/MO   DETAIL
---------------  --------------------  ------  ---------  -----  ----------------------------------------------------------------------
build-artifacts  no-abort-mpu          low     11.0 GiB   0.25   no AbortIncompleteMultipartUpload rule; 4 incomplete upload(s) ...
build-artifacts  no-transition         high    3.0 TiB    32.26  no transition rule; 3.0 TiB in STANDARD, ~$32.26/mo cheaper in ...
config-store     no-noncurrent-expiry  medium  420.0 GiB  9.66   versioning enabled, no NoncurrentVersionExpiration rule; 420.0 ...
access-logs      all-rules-disabled    medium  -          -      lifecycle config has 2 rule(s), every one Status=Disabled

8 finding(s) on 4 of 5 bucket(s); estimated waste $70.20/mo
worst buckets:
  build-artifacts                          $32.51/mo
  media-cold                               $16.13/mo
```

### Flags

| flag | what it does |
| --- | --- |
| `--format text\|json` | table for humans, JSON for everything else |
| `--region REGION` | scope the scan; repeatable or comma-separated |
| `--ignore-bucket NAME` | deliberately exempt bucket, skipped before evaluation |
| `--ignore-rule RULE` | mute one rule everywhere |
| `--fail-on RULES` | exit 1 when one of these fires; `all` means any finding |
| `--severity low\|medium\|high` | drop findings below this severity |
| `--min-monthly-usd USD` | drop findings cheaper than this |
| `--deep` | walk object versions to measure noncurrent bytes exactly |
| `--standard-rate` / `--ia-rate` | override the $/GB-month assumptions |
| `--input FILE` | score a collected snapshot instead of calling AWS (`-` for stdin) |
| `--dump-input FILE` | save the snapshot so a later run can be replayed offline |
| `--emit-lifecycle DIR` | write `<bucket>.json` adding only the missing rules |

Exit codes: `0` clean (or findings without `--fail-on`), `1` a `--fail-on` rule fired,
`2` bad usage, `3` an AWS or input error.

## How it works

The rule engine is a pure module: a plain dict per bucket goes in, findings come out.
No clock, no network, no argv — which is why every rule is table-driven testable with no
AWS at all, and why `--input` works. The boto3 collector is a thin adapter that fills
those dicts in, and an `AccessDenied` on any single fact degrades to *unknown* instead of
killing the scan.

Two numbers need honesty about where they come from:

- **Part bytes.** `ListMultipartUploads` does not return sizes, so the bytes come from one
  `ListParts` walk per upload, capped at 200 uploads per bucket.
- **Noncurrent bytes.** CloudWatch's `BucketSizeBytes` has no noncurrent-version storage
  type, so there is no cheap way to get this. Without `--deep` the finding still fires —
  the rule is missing either way — but it is priced at `$0` and says
  `noncurrent bytes unknown`. With `--deep` the tool walks `ListObjectVersions` and sums
  the versions that are not the latest, which is exact and slow.

Dollar figures are bytes times a rate, nothing more. The defaults (`$0.023`/GB-month
`STANDARD`, `$0.0125` `STANDARD_IA`) are AWS `us-east-1` list prices for the first 50 TB
tier, checked 2026-10 against <https://aws.amazon.com/s3/pricing/>. Another region or a
negotiated contract will differ — pass `--standard-rate` and `--ia-rate`.

## Fixing what it finds

```shell
aws-s3-lifecycle-audit --emit-lifecycle ./fixes
aws s3api put-bucket-lifecycle-configuration \
  --bucket build-artifacts \
  --lifecycle-configuration file://fixes/build-artifacts.json
```

The emitted config contains only the rules that were missing — 7 days for abandoned
parts, 30 days for noncurrent versions, a 30-day `STANDARD_IA` transition. Read it before
you apply it; a transition is a billing decision, not a lint fix.

## In CI

```yaml
- name: S3 lifecycle hygiene
  run: aws-s3-lifecycle-audit --fail-on no-abort-mpu,no-noncurrent-expiry
```

## IAM

Read-only, nothing more:

```
s3:ListAllMyBuckets
s3:GetBucketLocation
s3:GetLifecycleConfiguration
s3:GetBucketVersioning
s3:ListBucketMultipartUploads
s3:ListMultipartUploadParts
s3:ListBucketVersions          # only with --deep
cloudwatch:GetMetricStatistics
```

## Development

```shell
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check .
```

The suite runs with no credentials and no network: the rules are tested from hand-built
dicts, the CLI from `examples/snapshot.json`, and the collector against a fake session
that speaks the slice of boto3 it uses.

## License

MIT
