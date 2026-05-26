"""hellhound — IoT default-credential scanner.

Scans HTTP/HTTPS endpoints for known IoT device signatures and checks
whether each matched device still authenticates with its factory-default
credentials. Detection-only: hellhound reports default-credential exposure,
it does not exploit it.
"""

__version__ = "0.1.0"
