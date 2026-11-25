"""INNERnetSplit / INNERnetSplitFactory on a local EVM (py-evm). Skipped when the EVM stack is not installed."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("eth_tester")
web3 = pytest.importorskip("web3")
from web3 import EthereumTesterProvider, Web3  # noqa: E402
from web3.exceptions import ContractLogicError  # noqa: E402

from innernet2.registry_service import chain  # noqa: E402

FEE_BPS = 250  # 2.5%
ART = json.loads((Path(__file__).resolve().parents[1] / "contracts" / "build" / "contracts.json").read_text())


def deploy(w3, name, *args, sender=None):
    c = ART["contracts"][name]
    tx = w3.eth.contract(abi=c["abi"], bytecode=c["bytecode"]).constructor(*args).transact({"from": sender or w3.eth.accounts[0]})
    return w3.eth.contract(address=w3.eth.get_transaction_receipt(tx).contractAddress, abi=c["abi"])


def at(w3, name, address):
    return w3.eth.contract(address=address, abi=ART["contracts"][name]["abi"])


@pytest.fixture
def env():
    w3 = Web3(EthereumTesterProvider())
    deployer, fee_wallet, provider, client, stranger = w3.eth.accounts[:5]
    factory = deploy(w3, "INNERnetSplitFactory", fee_wallet, FEE_BPS)
    usdc = deploy(w3, "MockUSDC")
    usdt = deploy(w3, "MockUSDT")
    return w3, factory, usdc, usdt, dict(deployer=deployer, fee=fee_wallet, provider=provider, client=client, stranger=stranger)


def test_create_predict_and_registry_checks(env):
    w3, factory, usdc, usdt, a = env
    predicted = factory.functions.predict(a["provider"]).call()
    factory.functions.create(a["provider"]).transact({"from": a["stranger"]})       # anyone may create it
    split_addr = factory.functions.splitOf(a["provider"]).call()
    assert split_addr == predicted
    assert factory.functions.isSplit(split_addr).call() is True
    assert factory.functions.isSplit(a["provider"]).call() is False
    split = at(w3, "INNERnetSplit", split_addr)
    assert split.functions.provider().call() == a["provider"]
    assert split.functions.feeRecipient().call() == a["fee"]
    assert split.functions.feeBps().call() == FEE_BPS
    assert split.functions.factory().call() == factory.address
    with pytest.raises((ContractLogicError, Exception), match="0x6b04142c|k\\x04\\x14|AlreadyCreated|reverted"):
        factory.functions.create(a["provider"]).transact({"from": a["provider"]})   # one per provider


@pytest.mark.parametrize("amount", [2_500_000, 1_000_001, 99, 1, 0])
def test_release_matches_registry_math(env, amount):
    w3, factory, usdc, usdt, a = env
    factory.functions.create(a["provider"]).transact()
    split = at(w3, "INNERnetSplit", factory.functions.splitOf(a["provider"]).call())
    usdc.functions.mint(split.address, amount).transact()
    expected_provider, expected_fee = chain.split(amount, FEE_BPS)
    assert tuple(split.functions.preview(usdc.address).call()) == (expected_provider, expected_fee)
    split.functions.release(usdc.address).transact({"from": a["stranger"]})        # anyone may trigger it
    assert usdc.functions.balanceOf(a["provider"]).call() == expected_provider
    assert usdc.functions.balanceOf(a["fee"]).call() == expected_fee
    assert usdc.functions.balanceOf(split.address).call() == 0


def test_tokens_without_return_value_and_no_ether(env):
    w3, factory, usdc, usdt, a = env
    factory.functions.create(a["provider"]).transact()
    split = at(w3, "INNERnetSplit", factory.functions.splitOf(a["provider"]).call())
    usdt.functions.mint(split.address, 10_000).transact()
    split.functions.release(usdt.address).transact()
    assert usdt.functions.balanceOf(a["provider"]).call() == 9_750
    assert usdt.functions.balanceOf(a["fee"]).call() == 250
    with pytest.raises(Exception):
        w3.eth.send_transaction({"from": a["client"], "to": split.address, "value": 1})


def test_constructor_guards(env):
    w3, factory, usdc, usdt, a = env
    with pytest.raises(Exception):
        deploy(w3, "INNERnetSplitFactory", "0x" + "00" * 20, FEE_BPS)
    with pytest.raises(Exception):
        deploy(w3, "INNERnetSplitFactory", a["fee"], 1001)


def test_registry_reads_contract_over_rpc(env):
    """The registry's own eth_call helpers agree with the contract."""
    w3, factory, usdc, usdt, a = env
    factory.functions.create(a["provider"]).transact()
    split_addr = factory.functions.splitOf(a["provider"]).call()

    def rpc(url, method, params):
        if method == "eth_call":
            return w3.eth.call(params[0]).to_0x_hex() if hasattr(w3.eth.call(params[0]), "to_0x_hex") else "0x" + w3.eth.call(params[0]).hex()
        if method == "eth_getCode":
            return "0x" + bytes(w3.eth.get_code(Web3.to_checksum_address(params[0]))).hex()
        raise AssertionError(method)

    from innernet2.registry_service.config import Settings
    s = Settings(rpc={"eip155:84532": "x"}, fee_payto={"eip155:84532": a["fee"]}, fee_bps=FEE_BPS,
                 split_factory={"eip155:84532": factory.address})
    assert chain.payout_check(s, "eip155:84532", split_addr, rpc) == (True, "")
    ok, why = chain.payout_check(s, "eip155:84532", a["provider"], rpc)            # a plain wallet
    assert not ok and "not a contract" in why
    other = deploy(w3, "INNERnetSplitFactory", a["stranger"], FEE_BPS)                  # look-alike factory
    other.functions.create(a["provider"]).transact()
    fake = other.functions.splitOf(a["provider"]).call()
    ok, why = chain.payout_check(s, "eip155:84532", fake, rpc)
    assert not ok and "not created by the INNERnet split factory" in why
    s.fee_bps = 100
    ok, why = chain.payout_check(s, "eip155:84532", split_addr, rpc)
    assert not ok and "fee share" in why
