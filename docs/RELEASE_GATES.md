# INNERnet v1.0.0 — release evidence and independent assurance status

This is the first **scoped core software release**. The stable software tag designates the ST81, OB80-2, R90-ROUTE-1 and UV10-1 core implementation/API under the documented compatibility policy. It does **not** imply independent cryptographic certification or universal interoperability.

| Gate | Evidence | Status |
|---|---|---|
| Release archive and file manifest | Regenerated for v1.0.0 and checked before publishing | Verify in GitHub CI |
| Local functional regression suite | Previous RC5 dev4 Revision 2 clean repo passed 363 tests; release-version changes require rerun | Run against exact v1.0.0 source |
| Python 3.11/3.12, Go UV10, Docker CI | Prior dev3 CI success is not proof for v1.0.0 | Must pass for exact v1.0.0 commit before tag |
| Mac/native WAN and failover | Previous dev3 Mac / Contabo / Railway evidence | Historical only; not requalified on v1.0.0 |
| Independent full-stack ST81/OB80-2/R90 implementation | Only UV10 Go verifier currently exists | Not established |
| Independent human cryptographic review | AI-assisted source review, no outside certificate | Not established |
| Full provider-level outage | Only disposable primary stopped, Railway via SSH | Not established |

## Known limitations for the scoped release

- R90-ROUTE-1 has no monotonic route sequence / anti-rollback; a signed but older unexpired plan can be replayed if the delivery channel is compromised.
- Public ST81 listeners remain susceptible to resource-exhaustion under sufficiently large multi-address floods; use network allowlists and front-end protections.
- HTTP-v3 `inn3_` is **experimental**, and direct use of its low-level root/key API to encrypt distinct objects with a reused root can reuse a ChaCha20-Poly1305 key/nonce. Use only the safe high-level fresh-credential upload path and never reuse roots.
- No universal automatic provider discovery, lease marketplace, x402, paid compute, account federation, or enterprise availability guarantee in v1.0.0.
- UV10 framing is plaintext until sealed as an OB80 encrypted object.

## Release tag policy

For a **single-branch release**, commit the validated source update directly to `main` using GitHub Desktop. Require a green GitHub Actions run on the **exact `main` commit** (Python 3.11/3.12, Go verifier, Docker builds, release manifest), and then create an annotated `v1.0.0` Git tag and the GitHub Release for that same commit. The tag is not a branch. Do not tag if CI is red. Before changing a private repository to public, separately scan historical commits for secrets and unpublished credentials.

See [scope and limitations](STABLE_CORE_SCOPE_AND_LIMITATIONS.md).
