"""Engineer4Me Phase 7 engineering-design package.

Step 89 establishes the import-safe package boundary only. Design cases,
analyzer application assessment, controlled datasheets, persistence, and
export services are introduced by later reviewed Phase 7 steps.

Voice input, speech recognition, voice search, and text-to-speech are not part
of this package. Those capabilities remain scheduled for Phase 10.
"""

from __future__ import annotations


PHASE_NUMBER = 7
PACKAGE_NAME = "engineering_design"
FOUNDATION_VERSION = "0.1.0"
VOICE_FUNCTIONALITY_ENABLED = False


__all__ = [
    "FOUNDATION_VERSION",
    "PACKAGE_NAME",
    "PHASE_NUMBER",
    "VOICE_FUNCTIONALITY_ENABLED",
]
