// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title INNERnet payout split (IRM-1 section 4.3)
/// @notice One contract per provider. Clients pay this address. Anyone may call
///         release(token) to send the balance on: (10000 - feeBps)/10000 to the
///         provider (rounded down), the rest to the network fee wallet.
///         No owner, no admin, no upgrade, no way to change any address or share.
contract INNERnetSplit {
    address public immutable provider;
    address public immutable feeRecipient;
    uint16 public immutable feeBps;
    address public immutable factory;

    event Released(address indexed token, uint256 toProvider, uint256 toFee);

    error ZeroAddress();
    error FeeTooHigh();
    error TransferFailed();
    error NoEther();

    constructor(address provider_, address feeRecipient_, uint16 feeBps_) {
        if (provider_ == address(0) || feeRecipient_ == address(0)) revert ZeroAddress();
        if (feeBps_ > 1000) revert FeeTooHigh(); // hard cap 10%
        provider = provider_;
        feeRecipient = feeRecipient_;
        feeBps = feeBps_;
        factory = msg.sender;
    }

    /// @notice Split this contract's whole balance of `token`. Callable by anyone.
    function release(address token) external returns (uint256 toProvider, uint256 toFee) {
        uint256 balance = _balanceOf(token);
        toProvider = (balance * (10_000 - feeBps)) / 10_000;
        toFee = balance - toProvider;
        if (toFee != 0) _transfer(token, feeRecipient, toFee);
        if (toProvider != 0) _transfer(token, provider, toProvider);
        emit Released(token, toProvider, toFee);
    }

    /// @notice What release(token) would pay out right now.
    function preview(address token) external view returns (uint256 toProvider, uint256 toFee) {
        uint256 balance = _balanceOf(token);
        toProvider = (balance * (10_000 - feeBps)) / 10_000;
        toFee = balance - toProvider;
    }

    receive() external payable {
        revert NoEther();
    }

    function _balanceOf(address token) private view returns (uint256) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || data.length < 32) revert TransferFailed();
        return abi.decode(data, (uint256));
    }

    // Works with tokens that return true and with tokens that return nothing (USDT).
    function _transfer(address token, address to, uint256 amount) private {
        (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, amount));
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}

/// @title Factory for INNERnet payout splits
/// @notice Fixes the fee wallet and fee share for every split it creates. Creates at
///         most one split per provider address, at a deterministic address (CREATE2).
///         The registry accepts a payout address only if isSplit() returns true here.
contract INNERnetSplitFactory {
    address public immutable feeRecipient;
    uint16 public immutable feeBps;

    mapping(address => address) public splitOf;
    mapping(address => bool) public isSplit;

    event SplitCreated(address indexed provider, address indexed split);

    error AlreadyCreated();

    constructor(address feeRecipient_, uint16 feeBps_) {
        if (feeRecipient_ == address(0)) revert INNERnetSplit.ZeroAddress();
        if (feeBps_ > 1000) revert INNERnetSplit.FeeTooHigh();
        feeRecipient = feeRecipient_;
        feeBps = feeBps_;
    }

    /// @notice Create the split that pays `provider`. Anyone may call; the money can only go to `provider`.
    function create(address provider) external returns (address split) {
        if (splitOf[provider] != address(0)) revert AlreadyCreated();
        split = address(new INNERnetSplit{salt: bytes32(uint256(uint160(provider)))}(provider, feeRecipient, feeBps));
        splitOf[provider] = split;
        isSplit[split] = true;
        emit SplitCreated(provider, split);
    }

    /// @notice The address create(provider) gives, before or after it is created.
    function predict(address provider) external view returns (address) {
        bytes32 codeHash = keccak256(
            abi.encodePacked(type(INNERnetSplit).creationCode, abi.encode(provider, feeRecipient, feeBps)));
        bytes32 salt = bytes32(uint256(uint160(provider)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash)))));
    }
}
