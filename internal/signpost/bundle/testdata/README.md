# Test fixtures

## `minisign-0.12.tar.gz` and its `.minisig`

A genuine minisign-signed artifact, used as a compatibility test vector for
`minisign.go`.

It is here because a self-consistent round-trip test would not catch the
failure that matters. If signpost's understanding of the minisign byte layout
were wrong, a signer and verifier built on the same wrong understanding would
agree with each other and the test would pass - while rejecting, or worse
wrongly accepting, every real signature. Only a signature produced by the
actual `minisign` implementation can rule that out.

|                |                                                                |
| -------------- | -------------------------------------------------------------- |
| Source         | `https://github.com/jedisct1/minisign/releases/download/0.12/` |
| Public key     | `RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3`     |
| Signature kind | prehashed (`ED`), which is what modern minisign emits          |

The public key is the one published in minisign's own README, and is embedded
in `minisign_test.go` rather than stored here so that a test reading the
fixture cannot accidentally read a key from the same place an attacker could
have replaced both.

The fixture is never executed, parsed as an archive, or served. It is read as
opaque bytes and hashed.
