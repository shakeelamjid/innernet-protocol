# INNERnet provider terms

Version 2026-11-26 (draft for the test network; to be reviewed by a lawyer before real money is used)

These terms are between you, the person or company running a provider machine ("you"), INNERnet ("the network", which runs the registry at innernetcorp.com), and the clients who use your machine. Your machine signs the fingerprint of this version into its listing. You can stop at any time with `innernet-provider leave`.

## 1. What you offer
1.1 You offer only what you choose in setup: storage, bandwidth (relay), CPU time and GPU time, at your own prices.
1.2 You confirm you have the right to offer them: you own or control the machine, and your internet plan, landlord, employer and local law allow it.
1.3 You do not need to be online all the time, but you must be honest about your hours. Missed checks while you said you would be online lower your score and can lead to suspension.

## 2. Storage
2.1 You keep the pieces clients store with you, unchanged, for as long as they pay, and hand them back when asked.
2.2 Pieces are encrypted by the client. You must not try to decrypt, analyse, copy or share them.
2.3 Clients pay after each passing proof. They may hold back up to 20% of each payment until the next proof passes. If your machine loses pieces or fails proofs, the held-back amount is not paid to you; the client uses it to repair the data elsewhere. That is the only penalty for lost data under these terms.
2.4 When you leave, keep serving until clients have moved their pieces, or the leave period ends.

## 3. Bandwidth: relay and VPN exit
3.1 Relay carries sealed INNERnet traffic between INNERnet machines only. You must not try to read or alter it.
3.2 VPN exit is off unless you switch it on. When you do, clients' traffic reaches the internet from your connection and is seen as coming from your address. You confirm that you are allowed to offer internet exit where you operate, including any licence or registration your law requires, and that your internet plan allows it.
3.3 Abuse policy. You keep the exit's built-in protections on: no access to private networks, no mail port (25), your monthly limit. If you receive a credible abuse complaint about traffic through your exit, you may switch the exit off at once (innernet-provider pause, or untick it), and you should tell the network so the client can be identified by the key that paid for the traffic. You must not keep or sell records of what clients visit beyond what the law requires of you.
3.4 Traffic through the exit is sealed between the client and your machine; from your machine to the destination it is as the client sent it (usually HTTPS). You must not read, alter or inject into it.

## 4. CPU and GPU time
4.1 Clients' programs run in the sandbox built into the provider software. You must not weaken it, inspect clients' inputs or outputs beyond what running them needs, or keep copies after a job ends.
4.2 You understand your machine can see what it computes. You must treat it as confidential.
4.3 You are paid per second of use at your listed hourly prices, from credit the client paid in advance. Unused credit belongs to the client.

## 5. Payments and the network fee
5.1 Clients pay your payout contract, which sends your share to your wallet and 2.5% to the network. Nobody holds your money in between.
5.2 On the test network, payments use test USDC with no value.
5.3 You are responsible for your own taxes and for reporting your income where required.

## 6. Conduct and removal
6.1 You must not cheat proofs, report false hardware, run modified software to get paid without doing the work, or attack clients, other providers or the registry.
6.2 The network may suspend or remove a provider that breaks these terms, fails proofs repeatedly, or is required to by law. You can ask for a review.

## 7. No warranty, limits
7.1 The software and the network are provided as is. The network is not liable for loss of income, damage to your machine, or claims by your internet provider.
7.2 Nothing here makes you an employee or agent of the network.

## 8. Changes
8.1 New versions are published at innernetcorp.com/registry/terms. You must agree to the new version before your machine can change or renew its listing.
