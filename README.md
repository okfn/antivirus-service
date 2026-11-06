# antivirus-service

Prototype of a small HTTP antivirus service. It receives a file, answers right away with a `scan_id`, scans the file in the background and reports the result. It knows nothing about CKAN.

It runs next to the official [`clamav/clamav`](https://hub.docker.com/r/clamav/clamav) image, unchanged. That image provides the scanner and keeps its signatures up to date, so we don't maintain any of that.

```
CKAN job --HTTP--> antivirus-service --clamd protocol--> clamav/clamav
```

## Files

- `app.py`: HTTP API, queue and state.
- `clamd_engine.py`: the only file that knows about ClamAV. Another engine only needs `scan(path)` and `version()`.
- `demo_client.py`: what the CKAN job would do.
- `k8s-example.yaml.tpl`: Kubernetes example.

## Try it

    docker compose up --build -d
    curl http://127.0.0.1:8088/health
    printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
    python3 demo_client.py eicar.txt
    rm eicar.txt
    docker compose down -v

## API

| Request                | Response                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------- |
| `POST /scans`          | `202` with the scan. The body is the file. `411`, `413`, `429` or `507` if it can't be taken. |
| `GET /scans/<scan_id>` | `200` with the scan. `404` if unknown, for example after a restart: send the file again.      |
| `GET /health`          | `200` with the engine and signature version. `503` if the engine is not available.            |

A verdict is `clean` only when clamd explicitly answers OK. Anything else that isn't malware is an `error`, including exceeded limits and lost connections.

## Settings

| Variable                | Default       | Description                                     |
| ----------------------- | ------------- | ----------------------------------------------- |
| `CLAMD_HOST`            | `localhost`   | clamd host                                      |
| `CLAMD_PORT`            | `3310`        | clamd port                                      |
| `CLAMD_TIMEOUT_SECONDS` | `1800`        | Time allowed for clamd to answer                |
| `MAX_FILE_SIZE_MB`      | `1600`        | Keep it at or below the clamd limits            |
| `MAX_ACTIVE_SCANS`      | `5`           | Above this, `POST /scans` answers `429`         |
| `SCAN_CONCURRENCY`      | `1`           | Scans at the same time                          |
| `MIN_FREE_DISK_MB`      | `500`         | Free disk to keep, otherwise answers `507`      |
| `RESULT_TTL_SECONDS`    | `3600`        | How long finished results are kept              |
| `TMP_DIR`               | `/scans`      | Where files wait for their scan                 |

## Measurements

Local machine, ClamAV 1.5.4, 2026-11-06. Fargate will be slower.

| File                                 | Result                     | Scan time |
| ------------------------------------ | -------------------------- | --------- |
| EICAR                                | `infected`                 | < 0.1 s   |
| EICAR in a zip                       | `infected`                 | < 0.1 s   |
| 1.5 GB random data                   | `clean`                    | 46 s      |
| 1.5 GB random data + test signature at the end | `infected`       | 45 s      |
| 1.5 GB CSV                           | `clean`                    | 34 s      |
| 490 MB zip with that CSV             | `clean`                    | 22 s      |
| File above `MaxFileSize`             | `error`                    | -         |
| File above `StreamMaxLength`         | `error`                    | -         |
| Same 300 MB file again               | `clean` (clamd cache)      | 0.6 s     |
| Same file after a signature reload   | `clean` (scanned again)    | 10 s      |

clamd memory: 950 MiB idle, 1.4 GiB while scanning, 1.9 GiB during a signature reload with a 500 MB scan running. A signature reload doesn't interrupt scans.

## Security checks

`.github/workflows/checks.yml` runs these checks on every push and pull request, and every week to catch new vulnerabilities. Last local run: 2026-11-06.

| Check                                                   | Result  |
| ------------------------------------------------------- | ------- |
| Trivy 0.75.0 `fs`: vuln, secret, misconfig, HIGH+       | 0       |
| Trivy 0.75.0 `fs --ignore-unfixed`, all severities      | 0       |
| Trivy 0.75.0 `image`, HIGH+: this service               | 0       |
| Trivy 0.75.0 `image`, HIGH+: `clamav/clamav`            | 0       |
| Trivy 0.75.0 `config`, HIGH+: rendered k8s example      | 0       |
| ruff 0.17.0 `check` and `format`                        | Pass    |
| pip-audit                                               | 0       |
| Gitleaks 8.30.1                                         | 0       |
| Semgrep, `p/default` rules                              | 0       |

## TODO

- Optional token, for networks that are not closed.
- TLS and documentation for running the service outside a private network.
- Try the k8s example on Fargate, including non-root, read-only filesystem and disk limits.
- Pin the Python base image by digest.
