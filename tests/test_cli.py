"""CLI tests. They run the real entry point against the snapshot fixture, so no AWS."""

from __future__ import annotations

import json
import os

import pytest

from aws_s3_lifecycle_audit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "snapshot.json")


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_text_report_lists_every_bucket_with_a_problem(capsys):
    code, out, _ = run(capsys, "--input", FIXTURE)
    assert code == EXIT_OK
    assert "build-artifacts" in out
    assert "no-abort-mpu" in out
    assert "config-store" in out
    assert "no-noncurrent-expiry" in out
    assert "estimated waste $" in out
    # The clean bucket never appears.
    assert "tf-state-prod" not in out


def test_json_report_is_machine_shaped(capsys):
    code, out, _ = run(capsys, "--input", FIXTURE, "--format", "json")
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["summary"]["buckets_scanned"] == 5
    assert data["summary"]["findings"] == len(data["findings"])
    assert data["summary"]["estimated_monthly_usd"] > 0
    rules = {f["rule"] for f in data["findings"]}
    assert rules == {
        "no-abort-mpu",
        "no-noncurrent-expiry",
        "no-transition",
        "all-rules-disabled",
    }
    worst = data["summary"]["worst_buckets"]
    assert worst == sorted(worst, key=lambda b: -b["monthly_usd"])


def test_fail_on_a_rule_that_fired_exits_one(capsys):
    code, _, _ = run(capsys, "--input", FIXTURE, "--fail-on", "no-abort-mpu")
    assert code == EXIT_FINDINGS


def test_fail_on_a_rule_that_did_not_fire_exits_zero(capsys):
    code, _, _ = run(
        capsys, "--input", FIXTURE, "--ignore-rule", "no-abort-mpu", "--fail-on", "no-abort-mpu"
    )
    assert code == EXIT_OK


def test_fail_on_accepts_comma_separated_and_repeated_flags(capsys):
    code, _, _ = run(capsys, "--input", FIXTURE, "--fail-on", "no-abort-mpu,all-rules-disabled")
    assert code == EXIT_FINDINGS
    code, _, _ = run(capsys, "--input", FIXTURE, "--fail-on", "all")
    assert code == EXIT_FINDINGS


def test_unknown_rule_name_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--input", FIXTURE, "--fail-on", "no-abort-mpus"])
    assert excinfo.value.code == EXIT_USAGE
    assert "unknown rule" in capsys.readouterr().err


def test_ignored_bucket_disappears_completely(capsys):
    code, out, _ = run(capsys, "--input", FIXTURE, "--ignore-bucket", "build-artifacts")
    assert code == EXIT_OK
    assert "build-artifacts" not in out


def test_region_scope(capsys):
    code, out, _ = run(capsys, "--input", FIXTURE, "--region", "eu-central-1", "--format", "json")
    data = json.loads(out)
    assert data["summary"]["buckets_scanned"] == 2
    assert {f["region"] for f in data["findings"]} == {"eu-central-1"}


def test_min_monthly_usd_keeps_only_the_expensive_findings(capsys):
    code, out, _ = run(capsys, "--input", FIXTURE, "--min-monthly-usd", "5", "--format", "json")
    data = json.loads(out)
    assert data["findings"]
    assert all(f["monthly_usd"] >= 5 for f in data["findings"])


def test_severity_filter(capsys):
    _, out, _ = run(capsys, "--input", FIXTURE, "--severity", "high", "--format", "json")
    data = json.loads(out)
    assert {f["severity"] for f in data["findings"]} == {"high"}


def test_rates_are_overridable(capsys):
    _, cheap, _ = run(capsys, "--input", FIXTURE, "--format", "json")
    _, dear, _ = run(capsys, "--input", FIXTURE, "--standard-rate", "0.5", "--format", "json")
    assert (
        json.loads(dear)["summary"]["estimated_monthly_usd"]
        > json.loads(cheap)["summary"]["estimated_monthly_usd"]
    )


def test_clean_account_says_so(capsys, tmp_path):
    snapshot = tmp_path / "clean.json"
    snapshot.write_text(
        json.dumps(
            {
                "buckets": [
                    {
                        "name": "ok",
                        "region": "us-east-1",
                        "lifecycle_present": True,
                        "versioning": "Suspended",
                        "lifecycle": [
                            {
                                "ID": "all",
                                "Status": "Enabled",
                                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                                "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "--input", str(snapshot))
    assert code == EXIT_OK
    assert out.strip() == "No lifecycle findings across 1 bucket(s)."


def test_emit_lifecycle_writes_only_the_missing_rules(capsys, tmp_path):
    outdir = tmp_path / "fixes"
    code, _, _ = run(capsys, "--input", FIXTURE, "--emit-lifecycle", str(outdir))
    assert code == EXIT_OK
    written = sorted(p.name for p in outdir.iterdir())
    assert "build-artifacts.json" in written
    assert "tf-state-prod.json" not in written
    config = json.loads((outdir / "config-store.json").read_text(encoding="utf-8"))
    ids = [r["ID"] for r in config["Rules"]]
    assert "expire-noncurrent-versions" in ids
    for rule in config["Rules"]:
        assert rule["Status"] == "Enabled"


def test_dump_input_round_trips(capsys, tmp_path):
    dumped = tmp_path / "snap.json"
    run(capsys, "--input", FIXTURE, "--dump-input", str(dumped), "--format", "json")
    _, first, _ = run(capsys, "--input", FIXTURE, "--format", "json")
    _, second, _ = run(capsys, "--input", str(dumped), "--format", "json")
    assert json.loads(first)["findings"] == json.loads(second)["findings"]


def test_a_broken_snapshot_is_an_error_not_a_traceback(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('[{"no_name": true}]', encoding="utf-8")
    code, _, err = run(capsys, "--input", str(bad))
    assert code == EXIT_ERROR
    assert "name" in err


def test_missing_snapshot_file_is_an_error(capsys, tmp_path):
    code, _, err = run(capsys, "--input", str(tmp_path / "nope.json"))
    assert code == EXIT_ERROR
    assert err.startswith("error:")
