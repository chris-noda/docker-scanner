# docker-scanner

CLI tool to scan Docker images for vulnerabilities and compliance checks.

## Features

- Scan Docker images for known CVEs
- Check for outdated base images
- Compliance policy validation
- JSON and HTML report output
- Registry authentication support

## Installation

```bash
pip install docker-scanner
```

## Usage

```bash
# Scan an image
docker-scanner scan nginx:latest

# Scan with verbose output
docker-scanner scan nginx:latest --verbose

# Output to file
docker-scanner scan nginx:latest --format json --output report.json

# Skip database update
docker-scanner scan nginx:latest --no-update
```

## Configuration

Create `~/.docker-scanner/config.yaml`:

```yaml
db_path: ~/.docker-scanner/vulndb
max_severity: medium
ignore_cves:
  - CVE-2021-99999
registries:
  docker.io:
    username: ""
    password: ""
```

## License

MIT
