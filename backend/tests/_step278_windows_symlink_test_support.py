"""Host-capability-neutral final-symlink test support for Step 278."""

from __future__ import annotations

import os
from pathlib import Path
import stat
from types import ModuleType
from typing import Any


EMULATION_COUNT = 0


def create_or_emulate_file_symlink(
    *,
    link: Path,
    target: Path,
    monkeypatch: Any,
    module_os: ModuleType,
) -> bool:
    """Create a file symlink, or emulate only lstat when WinError 1314 applies."""

    try:
        link.symlink_to(target)
        return False
    except (OSError, NotImplementedError) as error:
        if not (
            isinstance(error, OSError)
            and os.name == "nt"
            and getattr(error, "winerror", None) == 1314
        ):
            raise

    global EMULATION_COUNT
    EMULATION_COUNT += 1

    original_lstat = module_os.lstat
    target_metadata = original_lstat(target)
    values = list(target_metadata)
    values[0] = stat.S_IFLNK | stat.S_IMODE(target_metadata.st_mode)
    synthetic_symlink = os.stat_result(values)
    link_value = os.path.normcase(os.path.abspath(os.fspath(link)))

    def guarded_lstat(path: str | os.PathLike[str]) -> os.stat_result:
        candidate = os.path.normcase(os.path.abspath(os.fspath(path)))
        if candidate == link_value:
            return synthetic_symlink
        return original_lstat(path)

    monkeypatch.setattr(module_os, "lstat", guarded_lstat)
    return True
