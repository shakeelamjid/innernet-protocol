"""GPU-1: detected GPUs, GPU offers, signed hardware in the descriptor, market prices per model."""
import pytest

from innernet2.bulk_v080 import BulkError
from innernet2 import irm_registry as reg
from innernet2.registry_service import offer as offers

NET = "eip155:84532"
BASE = {"name": "gpu-box", "region": "asia-south", "host": "203.0.113.9", "port": 9443, "storage_gib": 0,
        "network": NET, "payout": "0x" + "12" * 20}
L4 = {"vendor": "NVIDIA", "model": "NVIDIA L4", "vram_mib": 23034, "api": "cuda", "driver": "550.54.14"}
INTEL = {"vendor": "Intel", "model": "Intel UHD Graphics 770", "api": "none"}


def test_detected_gpus_validated():
    reg.validate_gpus([L4, INTEL, {"vendor": "Apple", "model": "Apple M1 Pro", "cores": 16, "vram_mib": 16384, "api": "metal"}])
    for bad in ([{"vendor": "NVIDIA"}], [dict(L4, api="vulkan")], [dict(L4, model="<script>")], [L4] * 17,
                [dict(L4, extra=1)], "L4"):
        with pytest.raises(BulkError):
            reg.validate_gpus(bad)


def test_gpu_offer_uses_detected_model():
    det = {"gpus": [L4, L4, INTEL]}
    o = offers.check_offer(dict(BASE, gpu=True, gpus=2, prices={"GPU-1": "0.40"}), {NET}, det)
    e = offers.to_entry(o, "ab" * 32)
    assert e["services"] == ["GPU-1"] and e["limits"]["GPU-1"] == {"max_gpus": 2}
    assert e["hardware"] == {"gpu_vendor": "NVIDIA", "gpu_model": "NVIDIA L4", "gpu_api": "cuda", "gpu_vram_mib": 23034}
    assert e["prices"]["GPU-1"] == {"asset": "USDC", "unit": "GPU-hour", "amount": "0.40"}
    reg._validate_provider(e, registry=False)


def test_gpu_offer_refused_without_usable_gpu_or_too_many():
    with pytest.raises(BulkError, match="no GPU"):
        offers.check_offer(dict(BASE, gpu=True, gpus=1), {NET}, {"gpus": [INTEL]})
    with pytest.raises(BulkError, match="no GPU"):
        offers.check_offer(dict(BASE, gpu=True, gpus=1), {NET}, None)
    with pytest.raises(BulkError, match="reported 2"):
        offers.check_offer(dict(BASE, gpu=True, gpus=3), {NET}, {"gpus": [L4, L4]})


def test_hardware_only_with_gpu_service():
    e = offers.to_entry(offers.check_offer(dict(BASE, storage_gib=10), {NET}, {"gpus": [L4]}), "ab" * 32)
    reg._validate_provider(e, registry=False)
    with pytest.raises(BulkError):
        reg._validate_provider(dict(e, hardware={"gpu_model": "NVIDIA L4"}), registry=False)
    g = offers.to_entry(offers.check_offer(dict(BASE, gpu=True), {NET}, {"gpus": [L4]}), "ab" * 32)
    with pytest.raises(BulkError):
        reg._validate_provider({k: v for k, v in g.items() if k != "hardware"}, registry=False)
    with pytest.raises(BulkError):
        reg._validate_provider(dict(g, hardware=dict(g["hardware"], gpu_api="opencl")), registry=False)


def test_market_groups_gpu_prices_by_model():
    from innernet2.registry_service import presence

    def entry(model, price, cls):
        e = offers.to_entry(offers.check_offer(dict(BASE, gpu=True, prices={"GPU-1": price}), {NET},
                                               {"gpus": [dict(L4, model=model)]}), "ab" * 32)
        return {"entry": dict(e, **{"class": cls})}

    class S:
        def providers(self, state):
            return [entry("NVIDIA L4", "0.40", "server"), entry("NVIDIA L4", "0.60", "server"),
                    entry("NVIDIA GeForce RTX 4090", "0.90", "desktop")]

    m = presence.market(S())["GPU-1"]
    assert m["providers"] == 3 and m["unit"] == "GPU-hour"
    assert m["by_model"]["NVIDIA L4"]["median"] == "0.5" and m["by_model"]["NVIDIA GeForce RTX 4090"]["providers"] == 1
