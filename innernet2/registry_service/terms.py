"""Provider and client terms (IRM-1 section 4.6, draft). Each version is identified by the SHA-256
of its exact text; providers sign it into their listing, clients into every payment."""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from pathlib import Path

DIR = Path(__file__).with_name("terms")
KINDS = ("provider", "client")


@lru_cache(maxsize=None)
def current(kind: str) -> dict:
    text = (DIR / f"{kind}.md").read_text(encoding="utf-8")
    m = re.search(r"^Version (\S+)", text, re.M)
    return {"version": m.group(1) if m else "unknown", "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text}


def summary() -> dict:
    return {k: {"version": current(k)["version"], "sha256": current(k)["sha256"],
                "url": f"/registry/terms#{k}"} for k in KINDS}
