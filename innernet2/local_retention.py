"""Narrow cleanup for locally generated SYNTHETIC trial payloads only.

Never erase read.secret or reports, and never delete remote stored fragments.
"""
from __future__ import annotations

import os
import stat
import time
from pathlib import Path

SYNTHETIC_NAMES = frozenset({"synthetic-input.bin", "recovered-normal.bin", "recovered-with-outage.bin"})


def local_trial_cleanup(folder: Path, *, older_than_days: int = 30,
                        execute: bool = False, now: float | None = None) -> dict:
    if type(older_than_days) is not int or not 1 <= older_than_days <= 3650:
        raise ValueError("older_than_days must be an integer 1 to 3650")
    base = folder.expanduser().absolute()
    if base.is_symlink():
        raise ValueError("refusing symlink lab folder")
    trials = base / "trials"
    if trials.is_symlink():
        raise ValueError("refusing symlink trials directory")
    if not trials.is_dir():
        return {"mode": "deleted" if execute else "dry-run", "eligible_files": 0,
                "eligible_bytes": 0, "note": "No local trials directory."}
    cutoff = (time.time() if now is None else now) - older_than_days * 86400
    files = 0
    eligible_bytes = 0
    for trial in trials.iterdir():
        if trial.is_symlink() or not trial.is_dir():
            continue
        # Only the v0.3.x generated 12-character hex trial directories.
        if len(trial.name) != 12 or any(c not in "0123456789abcdef" for c in trial.name):
            continue
        for name in SYNTHETIC_NAMES:
            path = trial / name
            try:
                st = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_mtime >= cutoff:
                continue
            files += 1
            eligible_bytes += st.st_size
            if execute:
                # Directory components were checked above. No traversal is accepted.
                path.unlink()
    return {"mode": "deleted" if execute else "dry-run",
            "eligible_files": files, "eligible_bytes": eligible_bytes,
            "retained": "All read.secret files, reports and remotely stored data are preserved",
            "note": "Only local synthetic-input/recovered test .bin copies older than threshold are eligible."}
