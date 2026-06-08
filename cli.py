"""CLI entry point for docker-scanner."""

import argparse
import logging
import sys
import json
import yaml
from pathlib import Path

from scanner import DockerScanner, ScanResult


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def load_config(config_path: str = "~/.docker-scanner/config.yaml"):
    path = Path(config_path).expanduser()
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def format_report(result: ScanResult, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps({
            "image": result.image,
            "base_image": result.base_image,
            "scan_time": result.scan_time,
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "package": v.package,
                    "version": v.installed_version,
                }
                for v in result.vulnerabilities
            ]
        }, indent=2)
    else:
        lines = [
            f"Image: {result.image}",
            f"Base image: {result.base_image or 'unknown'}",
            f"Scan time: {result.scan_time:.2f}s",
            f"Vulnerabilities found: {len(result.vulnerabilities)}",
        ]
        if result.vulnerabilities:
            lines.append("")
            for v in result.vulnerabilities:
                lines.append(f"  [{v.severity.upper()}] {v.cve_id}  {v.package}@{v.installed_version}")
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="docker-scanner: Scan Docker images for vulnerabilities")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("image", help="Docker image to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--no-update", action="store_true", help="Skip database update")
    parser.add_argument("--config", default="~/.docker-scanner/config.yaml", help="Config file path")

    args = parser.parse_args()

    setup_logging(args.verbose)
    config = load_config(args.config)

    scanner = DockerScanner(config)
    result = scanner.scan(args.image)

    output = format_report(result, args.format)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code based on vulnerabilities
    if result.vulnerabilities:
        sys.exit(1)


if __name__ == "__main__":
    main()
