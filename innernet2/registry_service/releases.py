"""Provider downloads under the network's own address: /registry/dl/latest names the newest
provider release, /registry/dl/<tag>/<file> forwards to the published file, and
/registry/install.sh|ps1 to the installers. Installed providers check these for updates. The
files themselves stay on the release host; the installer and the provider check every download
against the release's SHA256SUMS, so forwarding adds no trust."""
from __future__ import annotations

import re
import threading
import time

import httpx

TAG = re.compile(r"^provider-v(\d+)\.(\d+)\.(\d+)$")
FILES = re.compile(r"^(innernet-provider-(linux|darwin)-(amd64|arm64)|innernet-provider-windows-(amd64|arm64)\.exe|"
                   r"SHA256SUMS|install\.sh|install\.ps1)$")


class Releases:
    def __init__(self, repo: str, ttl: int = 300, get=httpx.get):
        self.repo, self.ttl, self.get = repo, ttl, get
        self._lock = threading.Lock()
        self._latest: tuple[float, str] = (0.0, "")

    def latest(self) -> str:
        """The newest published provider release (cached for five minutes)."""
        with self._lock:
            at, tag = self._latest
            if tag and time.time() - at < self.ttl:
                return tag
        tag = ""
        try:
            r = self.get(f"https://api.github.com/repos/{self.repo}/releases?per_page=50", timeout=10,
                         headers={"Accept": "application/vnd.github+json"})
            if r.status_code == 200:
                tags = [x["tag_name"] for x in r.json() if not x.get("draft") and TAG.match(x.get("tag_name", ""))]
                if tags:
                    tag = max(tags, key=lambda t: tuple(int(n) for n in TAG.match(t).groups()))
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            tag = ""
        if not tag:                       # API limit reached: the LATEST file names the release
            try:
                r = self.get(f"https://raw.githubusercontent.com/{self.repo}/main/provider/LATEST", timeout=10)
                tag = r.text.strip() if r.status_code == 200 and TAG.match(r.text.strip()) else ""
            except httpx.HTTPError:
                tag = ""
        if tag:
            with self._lock:
                self._latest = (time.time(), tag)
        return tag or self._latest[1]

    def file_url(self, tag: str, name: str) -> str | None:
        if not TAG.match(tag) or not FILES.match(name):
            return None
        return f"https://github.com/{self.repo}/releases/download/{tag}/{name}"

    def installer_url(self, name: str) -> str | None:
        if name not in ("install.sh", "install.ps1"):
            return None
        return f"https://raw.githubusercontent.com/{self.repo}/main/provider/{name}"
