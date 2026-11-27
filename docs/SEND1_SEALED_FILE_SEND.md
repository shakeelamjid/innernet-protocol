# SEND-1: sealed file send (draft)

Status: draft, first implementation. Not independently audited; use test data until it is.

INNERNET Send hands one sealed file to one person under rules the sender sets. It is the first application built on the protocol's idea: the data is sealed where it is made, and the network only ever holds what it cannot read.

## What each party holds

| Party | Holds | Never holds |
|---|---|---|
| Sender's browser | the file, the link secret, the PIN, a device key | |
| Keeper (today: the registry) | sealed bytes, the keeper share, the rules, a check value for the PIN | the link secret, the PIN, the file key |
| Receiver's browser | the link (with the link secret), the PIN, a device key | |

The file key is made from three parts, and all three are needed:

```
file key = HKDF-SHA-256( link secret || keeper share || PBKDF2-SHA-256(PIN, 200 000 rounds) )
```

- **Link secret**: 32 random bytes in the link's `#fragment`. Browsers do not send the fragment to a server.
- **Keeper share**: 32 random bytes the sender deposits with the keeper. The keeper releases it only while the rules allow, and deletes it when they end.
- **PIN**: 6 random digits the sender tells the receiver by another channel.

The file is cut into 4 MiB parts, each sealed with AES-256-GCM. The part number and a last-part flag are bound into each part, so parts cannot be reordered, dropped or cut short unnoticed. The file's name, type and size are sealed with the file key; the sender's name and note are sealed with a key from the link secret alone, so a receiver can see who a file is from before entering the PIN.

## Free, and paid additions

- **Free:** one file up to 10 MB, or one note up to 500 words (shown on screen, not downloaded). Link and PIN, one opening on the first device that proves both, then destroyed; destroyed after 7 days if unopened. No settings. The sender sees that it was opened, not when.
- **Paid additions**, each priced, the whole price paid before the upload, in USDC on Base, to the operator's public receiving address (`INNERNET_SEND_PAYTO`, default the registry's fee wallet on Base). Prices in USDC: up to 100 MB 0.05, up to 1 GB 0.25; each 30 days of life 0.05 per 100 MB; each opening after the first 0.01, any number 0.25; opening on more than one device 0.05; open only after a date 0.05; read receipt with time 0.03; one sealed reply 0.05; take it back 0.05.
- **How the payment is found:** the price carries a few random last digits (under 0.001 USDC). The service reads USDC Transfer events to the receiving address and accepts exactly that amount once. It holds no wallet and no key. A price is held 30 minutes.
- **Extend or destroyed:** before its end the sender can buy more days (same price as life, paid the same way). Unextended, a send is destroyed at its end.
- **Planned, not built:** storage on N machines with a half-life (half the machines drop each half-life; any 4 shards restore the file, so lifetime = half-life x log2(N / 4)), joint opening, named recipients, pay to open, request links. These wait for several keepers and an audit.
- `INNERNET_SEND_ALL_RULES=1` allows every rule without payment, for tests.

## Rules (the engine)

| Rule | Values | How the keeper enforces it |
|---|---|---|
| Keep | 1 day, 7 days (30 days later, paid) | At the end the keeper share and the sealed bytes are deleted |
| Fade | half-life 1 day, hard end as Keep | The share is destroyed at a random moment, so the chance the file still opens halves each half-life. Nobody is told the moment |
| Opens | once, 3 times, any number | The share is released that many times; after the last, it is deleted at once and the sealed bytes within 2 hours |
| Passing on | not allowed / allowed | Not allowed: bound to the first device that opens it (a device key signs each request) |
| PIN tries | 5 wrong in a row | The file is destroyed |
| Take back | any time | The sender's device key signs the request; the file is destroyed |

**What the rules cannot do.** They control what the keeper releases. A person who has opened a file can keep what they saw; no rule can undo that. The pages say so.

## Requests (under `/registry/send/api`)

Browser requests carry the header `X-Innernet: 1`. Signed requests are ECDSA P-256 / SHA-256 over `INNERNET/SEND-1/<action>\n<file id>\n<unix time>`, fresh within 300 s.

| Request | Who | What |
|---|---|---|
| `GET /limits` | anyone | largest file, lifetimes offered, part size |
| `POST /files` | sender | deposit the rules, the keeper share, the PIN check value and the sender's device key; returns an upload token |
| `PUT /files/{id}/parts/{n}` | sender (upload token) | one sealed part, in order |
| `POST /files/{id}/info` | holder of the link | the rules, the state and the sealed sender note |
| `POST /files/{id}/open` | holder of link + PIN, signed by the device key | releases the keeper share and a download token, if the rules allow |
| `GET /files/{id}/parts/{n}` | download token | one sealed part |
| `POST /files/{id}/status` | sender's device key | state, openings with times, wrong PIN count |
| `POST /files/{id}/revoke` | sender's device key | take the file back |

## Today and next

- **Today (free burner):** the registry is the one keeper and stores the sealed bytes: up to 10 MB, up to 7 days (`INNERNET_SEND_MAX_MB`, `INNERNET_SEND_MAX_DAYS`, `INNERNET_SEND_TOTAL_GB`, `INNERNET_SEND_PER_IP_DAY`, `INNERNET_SEND=0` switches it off). One keeper means the registry is trusted to follow the rules; it still cannot open a file.
- **Next:** the keeper share is split over several independent keeper machines and the sealed pieces go to storage providers (STO-1), paid in USDC, so no single operator can break a rule. The client and the link format do not change.
- **Later:** sealing to a known receiver's key (contacts), and passing a file on with the sender's permission.

## Operator

The operator cannot read files. `python -m innernet2.registry_service.admin send-list` shows ids, sizes and states; `send-remove <id> <reason>` destroys a file (abuse report, legal request).
