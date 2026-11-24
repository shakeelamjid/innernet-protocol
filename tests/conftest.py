from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from innernet2.network import MeshClient
from innernet2.node import create_app, initialize_node


@pytest.fixture
def mesh(tmp_path):
    apps, public, tokens = {}, [], {}
    for i in range(9):
        node_id = f"node-{i+1:02d}"
        url = f"http://127.0.0.1:{9600+i}"
        entry = initialize_node(tmp_path / node_id, node_id, url)
        public.append({k: entry[k] for k in ("id", "url", "public_key")})
        tokens[node_id] = entry["write_token"]
        apps[urllib.parse.urlsplit(url).netloc] = TestClient(create_app(tmp_path / node_id))

    def dispatch(request: httpx.Request) -> httpx.Response:
        api = apps.get(request.url.netloc.decode() if isinstance(request.url.netloc, bytes) else request.url.netloc)
        if api is None:
            return httpx.Response(404)
        r = api.request(request.method, request.url.path, content=request.content, headers=dict(request.headers))
        return httpx.Response(r.status_code, headers=dict(r.headers), content=r.content)

    client = httpx.Client(transport=httpx.MockTransport(dispatch), timeout=1.0)
    result = MeshClient({"nodes": public}, {"tokens": tokens}, http=client)
    yield result, tmp_path, apps
    client.close()
    for c in apps.values():
        c.close()
