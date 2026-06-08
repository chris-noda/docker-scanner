"""Core Docker image scanner."""

import subprocess
import json
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    cve_id: str
    severity: str
    package: str
    installed_version: str
    description: str


@dataclass
class ScanResult:
    image: str
    vulnerabilities: list[Vulnerability]
    base_image: Optional[str] = None
    scan_time: float = 0.0


class DockerScanner:
    """Scan Docker images for vulnerabilities."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def pull_image(self, image: str) -> bool:
        """Pull Docker image if not present."""
        try:
            subprocess.run(
                ["docker", "pull", image],
                check=True,
                capture_output=True,
                timeout=300
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to pull {image}: {e.stderr.decode()}")
            return False

    def inspect_image(self, image: str) -> dict:
        """Get image metadata."""
        try:
            result = subprocess.run(
                ["docker", "inspect", image],
                check=True,
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)[0]
        except Exception as e:
            logger.error(f"Failed to inspect {image}: {e}")
            return {}

    def get_base_image(self, image: str) -> Optional[str]:
        """Extract base image from Docker image."""
        inspect = self.inspect_image(image)
        config = inspect.get("Config", {})
        labels = config.get("Labels", {})
        return labels.get("maintainer") or config.get("Env", [""])[0]

    def scan(self, image: str) -> ScanResult:
        """Run vulnerability scan on image."""
        import time
        start = time.time()

        self.pull_image(image)
        base = self.get_base_image(image)

        # Placeholder: real implementation would call trivy/grype
        vulns = []

        return ScanResult(
            image=image,
            vulnerabilities=vulns,
            base_image=base,
            scan_time=time.time() - start
        )

    def print_report(self, result: ScanResult, verbose: bool = False):
        """Print scan report."""
        print(f"\nImage: {result.image}")
        print(f"Base image: {result.base_image or 'unknown'}")
        print(f"Scan time: {result.scan_time:.2f}s")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")

        if verbose:
            for v in result.vulnerabilities:
                print(f"  [{v.severity}] {v.cve_id} - {v.package}@{v.installed_version}")
