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

## Free, the storage plan, and add-ons

- **Free:** one file up to 10 MB, or one note up to 500 words (shown on screen, not downloaded). Link and PIN, one opening on the first device that proves both, then destroyed; destroyed after 7 days if unopened. The sender sees that it was opened, not when.
- **Storage plan:** one price for a size and a period, paid before the upload (USDC):

  | | 7 days | 30 days | 90 days | 1 year |
  |---|---|---|---|---|
  | Up to 10 MB | free | 0.50 | 1.25 | 4 |
  | Up to 100 MB | 0.50 | 1.50 | 4 | 12 |
  | Up to 1 GB | 2 | 5 | 12 | 40 |

- **Renewal:** before the end, the sender pays the plan price for a further period, which is added to the end date; add-ons carry over. A paid send whose time ends is locked (nobody can open it) for 3 days, during which it can still be renewed, then destroyed. A free send is destroyed at its end.
- **Add-ons**, paid once: a key per person 0.25 each; release if the sender stops checking in 1.00; not before a date 0.10; not after a date 0.10; each opening after the first 0.05, any number 0.50; more than one device 0.10; read receipt with time 0.05; one sealed reply 0.10; take it back 0.10.
- **Key lock (a key per person):** the link secret is split with Shamir's scheme (GF(2^8)) in the sender's browser into N keys (2 to 20), K of which rebuild it; the sender chooses K (all by default). There is one link; its fragment carries the holders' names, K and a room secret. No PIN in this mode: the PIN the key schedule needs is derived from the secret.
- **Opening with keys:** each holder opens the link (at most N places at once) and adds their own key, or several keys are added on one screen. A key leaves the device sealed under the room secret; the keeper holds the hash of each sealed key from the start, so it can check a key is the right person's without reading it. A key counts only while its place stays open. When K keys are in within one 10-minute window, the keeper hands the sealed keys to every place that added one (for 2 minutes); each place unseals them, rebuilds the link secret and opens. One opening is the holders together: each of their places releases once.
- **Check-in release:** the keeper refuses to release its part while the sender checks in (signed with the device key) within each period. After a missed check-in the sender has 24 more hours; then the send is released to whoever holds the link and PIN (or the keys) and cannot be held again.
- **Payment:** USDC on Base to the operator's public receiving address (`INNERNET_SEND_PAYTO`, default the registry's fee wallet on Base). The price carries a few random last digits (under 0.001 USDC); the service reads USDC Transfer events and accepts exactly that amount once. It holds no wallet and no key. A price is held 30 minutes.
- **Changing prices:** `INNERNET_SEND_PRICES` is a JSON object of overrides, e.g. `{"plan_1_30": "2", "holder": "0.5"}` (plan keys are `plan_<size row 0-2>_<days>`).
- `INNERNET_SEND_ALL_RULES=1` allows every rule without payment, for tests.

## General blocks

A send answers five questions; a use case is a combination of answers. The page offers 18 ready-made combinations; none is separate code.

| Question | Blocks |
|---|---|
| Who puts content in | the sender; **others can add** (and replace until it opens) |
| Who can open it | PIN; **a PIN per named person** (with succession); keys, all or K of N; anyone with the link (PIN inside the link); **approvers** who release without reading; **payment** |
| When | not before; not after; check-in release; when N have added; when a payment target is reached |
| How long | storage plan; openings; **view timer**; **shown on screen only**; **visible only while the holders are present**; **new versions on the same link** |
| What comes back | receipt; reply; take back; **signed record**; **witness link**; **alarm**; **recovery code**; **signed origin**; **link name**; **hand-on chain**; **printed seal** |

- **A PIN per named person (0.05 each; succession 0.50):** the content is sealed once with a random content key; each person's PIN opens a wrapped copy of that key. The keeper stores a PIN proof and a wrapped key per person, binds each PIN to its first device, and reports who opened. With succession each person has a time window and the next can open only if nobody before them did.
- **Approvers (0.25 each):** each approver has a link carrying a random token (the keeper holds its hash). Until K have approved, the keeper refuses to release its part. An approver's link contains no part of any key. This is enforced by the keeper, not by cryptography.
- **Payment lock (listing fee 5% of what it can take in, minimum 0.10):** the reader pays the sender's own address in USDC on Base; the keeper recognises the exact amount on the chain and then releases. Modes: each reader once; a crowd target that opens it for everyone; per period. No money passes through the registry.
- **Others can add (0.50 per place):** the sender writes a form (sealed under the link, with the sender's public key inside it). A contribution is the answers and at most one file, up to 4 MB, sealed in the contributor's browser: to the sender's key (ECDH P-256, AES-256-GCM) when only the sender reads, or under a key from the link when everyone reads. The same device may replace its contribution until closing; each submission returns a receipt signed by the registry. If a "not before" time is set, nothing is handed out before it, to the sender either, and nothing is accepted after it. "Open when N have added" gives an exchange. Before the opening time, secrecy rests on the keeper not handing out sealed contributions; a keeper colluding with the sender could read them early.
- **Duress PIN (0.50):** a second PIN with its own keeper part and a decoy sealed by the sender. Using it returns the decoy in exactly the shape of a real opening, records "duress PIN used" and fires the alarm.
- **Signed record (0.10):** the registry signs (Ed25519, its registry key) a JSON statement: sealed time, SHA-256 of the sealed bytes, every event, state and reason. It serves as an opening record, a never-opened proof, and proof the sealed bytes existed at that time. The sender can always fetch it; a witness and (if bought) link holders too.
- **Witness link (0.10), alarm (0.10):** a witness token shows status and the record, never content. The alarm posts `{send, event, at}` to an https address the sender names (public hosts only, no redirects) when it is opened, approved, released, or a duress PIN is used; email too if `INNERNET_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM` are set.
- **Recovery code (0.05):** a random code whose hash the keeper holds; presenting it moves the sender's control to another device key. The backup file exports the sender's list with these codes.
- **Signed origin (0.50):** the sender names a domain; the keeper fetches `https://<domain>/.well-known/innernet-send.txt` and shows the origin only if it contains the sender's device key.
- **Link name (0.25), printed seal (0.10), card (0.05), summary (0.05):** a readable link (`/send/n/<name>`); a QR code of the link for printing; a card design for notes; a short summary sealed under the link that anyone with the link reads before opening.
- **View rules (0.10 each; presence 0.25):** shown on screen only (pictures and text; the sender's name is laid over it), a view timer, and with a key lock, visible only while enough holders still have the link open. These are applied by the page: a reader can still photograph the screen or use a modified page.
- **New versions (0.10 each, bought upfront):** the sender uploads new sealed bytes with a new keeper part behind the same link and PIN.
- **Hand-on chain (0.10):** whoever opened it can seal it on as a new send that names its parent; each send in the chain shows how many hands came before and when it was first sealed.

- **Not built:** several keeper machines each holding a share of the keeper part; storage on N machines with a half-life (any 4 shards restore the file; lifetime = half-life x log2(N / 4)); a time lock that holds even against the keeper; a blind match of two sealed numbers; a proof written on chain by the registry (it has no wallet); SMS; re-issuing keys without a new upload. These need more machines on the network or computing on sealed data.

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
