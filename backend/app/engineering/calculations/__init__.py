"""Engineer4Me Phase 7 engineering-calculation package.

Step 89 establishes the import-safe package boundary only. Executable
calculation methods, formula implementations, unit conversion, safety gates,
and public service contracts are introduced by later reviewed Phase 7 steps.

Uploaded, extracted, or AI-generated formula text must never be executed merely
because it is present in Engineer4Me knowledge. Future executable methods must
be explicitly implemented, allow-listed, versioned, reviewed, and tested.
"""

from __future__ import annotations


PHASE_NUMBER = 7
PACKAGE_NAME = "engineering_calculations"
FOUNDATION_VERSION = "0.1.0"
EXECUTABLE_METHODS_ENABLED = False


__all__ = [
    "EXECUTABLE_METHODS_ENABLED",
    "FOUNDATION_VERSION",
    "PACKAGE_NAME",
    "PHASE_NUMBER",
]
