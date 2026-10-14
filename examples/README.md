# examples

`snapshot.json` is a collected account snapshot — the exact shape `--dump-input` writes
and `--input` reads. Five buckets, chosen so every rule fires at least once:

| bucket | what is wrong with it |
| --- | --- |
| `build-artifacts` | no lifecycle config at all, 4 abandoned multipart uploads, 3 TiB in `STANDARD` |
| `config-store` | versioning on, abort and transition rules present, nothing expires old versions |
| `access-logs` | a lifecycle config whose every rule is `Status=Disabled` |
| `tf-state-prod` | fully configured — it never appears in the report |
| `media-cold` | abort rule only, 1.5 TiB that has never moved out of `STANDARD` |

Run the audit against it with no AWS credentials:

```shell
aws-s3-lifecycle-audit --input snapshot.json
aws-s3-lifecycle-audit --input snapshot.json --format json | jq '.summary'
aws-s3-lifecycle-audit --input snapshot.json --severity high
aws-s3-lifecycle-audit --input snapshot.json --emit-lifecycle ./fixes && cat ./fixes/config-store.json
```

To capture your own snapshot and replay it later:

```shell
aws-s3-lifecycle-audit --deep --dump-input my-account.json
aws-s3-lifecycle-audit --input my-account.json --min-monthly-usd 10
```

The `oldest N day(s) old` figure in the report is computed against today, so it grows as
this fixture ages. That is the collector's behaviour, not a bug in the fixture.
