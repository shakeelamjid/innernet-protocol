# UV10 application layer quickstart (research only)

## Install and qualify on Mac (no VPS changes)

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e '.[test]'
python -m innernet2.qualify_v1 --mib 10 --window 32
```

## Create a synthetic universal message

```bash
mkdir -p ~/Downloads/uv10-lab
printf 'SYNTHETIC:Hello from INNERnet universal application API\n' > ~/Downloads/uv10-lab/message.txt
python -m innernet2.universal_v1 pack ~/Downloads/uv10-lab/message.txt \
  ~/Downloads/uv10-lab/message.uv10 --kind message --content-type text/plain --name hello.txt
python -m innernet2.universal_v1 inspect ~/Downloads/uv10-lab/message.uv10
python -m innernet2.universal_v1 unpack ~/Downloads/uv10-lab/message.uv10 \
  ~/Downloads/uv10-lab/recovered.txt
```

**The `.uv10` file is plaintext**. Only packaging then sealing over OB80
provides recipient-only encryption. Do NOT publish a bare `.uv10` file as an
encrypted object. The Go reference verifier, if Go is installed:

```bash
(cd interop/go && go run ./uv10verify ~/Downloads/uv10-lab/message.uv10)
```

## Existing signed node publish and receive (research network only)

First provision sender and recipient Ed25519 identities, a signed recipient
IE60 X25519 bundle, authenticated server pin and R90 signed route plan using
existing tools. Do not send private keys. To publish the already-packed file:

```bash
innernet-universal publish --stage /PRIVATE/stage.uv10 \
  --sender-key /PRIVATE/sender.key --recipient-bundle /PUBLIC/bundle.json \
  --host 127.0.0.1 --port 29420 --pinned-node NODE_PUBLIC_KEY_HEX \
  --checkpoint /PRIVATE/sender-checkpoint.json
```

To fetch and unpack with original sender verification:

```bash
innernet-universal receive --routes /PUBLIC/signed-route.json \
  --pinned-publisher PUBLISHER_KEY_HEX --object-id OBJECT_ID_HEX \
  --recipient-key /PRIVATE/recipient-identity.key \
  --recipient-secret /PRIVATE/recipient-x25519.key \
  --expected-sender SENDER_PUBLIC_KEY_HEX --output /PRIVATE/received.txt
```

The commands reject existing output paths; checkpoints contain sensitive
material and should be stored in private directories. This workflow is not a
production account-management solution.
