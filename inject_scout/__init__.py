"""inject-scout — on-device prompt injection & jailbreak scanner."""

__version__ = "0.1.0"

from inject_scout.engine import ScanResult, scan

__all__ = ["ScanResult", "__version__", "scan"]