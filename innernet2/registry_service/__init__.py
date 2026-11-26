"""INNERNET provider registry service (IRM-1 draft, M1 part 2, testnet first).

Accepts signed provider descriptors, publishes the signed REG-1 registry document,
probes providers, reads payments to payout contracts from the chain, and serves
the provider dashboard with passkey (WebAuthn) login.
"""
