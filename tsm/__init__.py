"""
TSM — The AI Firewall
=====================
Intercept every AI call. Detect PII. Redact it. Route intelligently.

    from tsm.proxy.server import start
    start()                          # proxy on :8080

    from tsm.detectors.pii import PIIDetector
    d = PIIDetector()
    r = d.scan("My SSN is 123-45-6789")
    print(r.has_critical)            # True
"""

__version__ = "3.3.0"
__all__ = ["__version__"]
