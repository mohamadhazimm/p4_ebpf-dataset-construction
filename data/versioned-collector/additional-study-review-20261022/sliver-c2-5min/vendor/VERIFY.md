# Sliver binaries — provenance

Downloaded 2026-11-13 from `https://github.com/BishopFox/sliver/releases/download/v1.7.9/` (host-side only;
these binaries run only inside the sealed VM, never on this host except the client for localhost operator gRPC
on the Sink). Git-ignored.

Release v1.7.9, published 2026-10-25.

## Sizes match the GitHub release API metadata exactly

- `sliver-server_linux-amd64` — 301351072 bytes
- `sliver-client_linux-amd64` — 64712864 bytes

## SHA-256

- `sliver-server_linux-amd64` — `6c54ea94961f15de22bb765911b850d054e66f69069e4b799ab7cc3134e8ef36`
- `sliver-client_linux-amd64` — `9f66bd5d55ec190905688184b029032a0e8c454ff83b76c91884f65384207672`

## minisign signatures — verified

Official Sliver public key (from the project repo, `docs/.../Minisign Public Key.md`, v1.7.9):

```
RWTZPg959v3b7tLG7VzKHRB1/QT+d3c71Uzetfa44qAoX5rH7mGoQTTR
```

Key id `d93e0f79f6fddbee` — matches the key id embedded in both `.minisig` files. Verified in Python
(`cryptography` Ed25519): algorithm `ED` (BLAKE2b-512 prehash + Ed25519); both the content signature and the
trusted-comment global signature verify **OK** for the server and the client.
