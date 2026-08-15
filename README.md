# github.com/go-webauthn/x

Low level packages for [github.com/go-webauthn/webauthn](https://github.com/go-webauthn/webauthn).

## Forked Packages

Every package in this repository is a fork of an upstream source, carried in-tree rather than taken as a dependency.
This document is the single record of where each one came from, so that outstanding upstream fixes can be found by
diffing the recorded commit against the upstream branch.

| Package                                                                | Upstream                                                                          | Commit base                                | Local changes              |
|------------------------------------------------------------------------|-----------------------------------------------------------------------------------|--------------------------------------------|----------------------------|
| [crypto/blake256](crypto/blake256)                                     | [decred/dcrd](https://github.com/decred/dcrd) `crypto/blake256`                   | `c32cc6f5cfc72b2b76a38e43d2a702f17e94d248` | Import path rewrite; fixes |
| [crypto/blake256/internal/compress](crypto/blake256/internal/compress) | [decred/dcrd](https://github.com/decred/dcrd) `crypto/blake256/internal/compress` | `d11d77828cd7ffb4e90b41f95bbf188f7d180e4a` | Fixes                      |
| [crypto/blake256/internal/_asm](crypto/blake256/internal/_asm)         | [decred/dcrd](https://github.com/decred/dcrd) `crypto/blake256/internal/_asm`     | `0d2e94857b109d8bcf1056b3d5061ca90f0f8b94` | Module path rewrite only   |
| [crypto/secp256k1](crypto/secp256k1)                                   | [decred/dcrd](https://github.com/decred/dcrd) `dcrec/secp256k1`                   | `085eb08c6b1e3aec6a201fd5ac45c64a2daf9144` | Import path rewrite; fixes |
| [crypto/secp256k1/ecdsa](crypto/secp256k1/ecdsa)                       | [decred/dcrd](https://github.com/decred/dcrd) `dcrec/secp256k1/ecdsa`             | `085eb08c6b1e3aec6a201fd5ac45c64a2daf9144` | Import path rewrite only   |
| [encoding/asn1](encoding/asn1)                                         | [golang/go](https://github.com/golang/go) `src/encoding/asn1`                     | `3e43f48cb6311c3c459f5c7aa69ae7d28b7fc821` | Substantial                |
| [revoke](revoke)                                                       | [cloudflare/cfssl](https://github.com/cloudflare/cfssl)                           | `e6502bb7ffe4ee576227c9123a101deda248884c` | Substantial                |

Each commit base is the most recent upstream commit to touch that path as of the fork, so a base older than the fork
itself simply means upstream had not modified those files since.

Each section below ends with the `git log` command that lists the upstream changes since that base. The paths in those
commands are upstream paths rather than paths in this repository, so each one must be run from a checkout of the
upstream it targets: `decred/dcrd` for `dcrec/secp256k1` and `crypto/blake256`, `golang/go` for `src/encoding/asn1`,
and `cloudflare/cfssl` for `revoke`.

### Local fixes to the dcrd forks

These are the only changes to the `decred/dcrd` sources beyond the import path rewrites. They are not carried upstream,
so they must be reapplied on a resync. `crypto/blake256/fork_test.go` has no upstream counterpart and covers the first
two.

| Location                                  | Change                                                                                                                                                                                                                                                                                                                    |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `blake256/hasher.go` `write`              | Compute the partial block guard in 64-bit arithmetic. A single write of 4 GiB truncated to `uint32`, skipped the pending block, and produced a wrong hash. The guard is extracted to `needsPartialBlockFlush` so it can be tested without a 4 GiB write.                                                                  |
| `blake256/hasher.go` `loadState`          | Reject a serialized state whose buffered byte count is not less than `BlockSize`, and decode into a local value so a rejected state cannot partially overwrite the receiver. Previously such a state panicked on the next write.                                                                                          |
| `blake256/internal/compress`              | Enforce the documented minimum message length in both `Blocks` implementations. The `amd64` assembly does not bounds check, so only the pure Go path panicked as documented. `blocksGeneric` itself returns without touching the chain value, so its comment now says the exported `Blocks` is what enforces the minimum. |
| `blake256/internal/compress` test vectors | Add two salted `blockVecs` entries derived from the salted vectors in `hasher_test.go`. Without them no salt reaches the SSE2, SSE4.1, or AVX compression paths, since `TestBlocksAMD64` is the only test that forces each variant.                                                                                       |
| `blake256/internal/compress/cpu_amd64.s`  | Declare `supportsCPUID` as `$8-1` rather than `$8-4`; a `bool` result is one byte, and `go vet` rejects the mismatch on `amd64`.                                                                                                                                                                                          |
| `secp256k1/doc.go`                        | Drop the references to the excluded `schnorr` subpackage and to per-package `README.md` files, neither of which exist in this fork.                                                                                                                                                                                       |
| `secp256k1/pubkey.go`                     | Document the hybrid format bytes as `0x06`/`0x07` to match `PubKeyFormatHybridEven` and `PubKeyFormatHybridOdd`; the comment said `0x05`/`0x06`.                                                                                                                                                                          |
| `secp256k1/error.go`                      | Spell the curve `secp256k1` in the `Error` doc comment.                                                                                                                                                                                                                                                                   |

### crypto/secp256k1

Provides the secp256k1 curve used by the COSE `ES256K` algorithm and `secp256k1` elliptic curve identifiers.

The `schnorr` subpackage, which implements EC-Schnorr-DCRv0, a signature scheme specific to Decred, is not included as
it has no WebAuthn use. The commit base covers both this package and its `ecdsa` subpackage. Beyond the local fixes
listed below, sources are unmodified apart from rewriting `github.com/decred/dcrd/dcrec/secp256k1/v4` to
`github.com/go-webauthn/x/crypto/secp256k1` and `github.com/decred/dcrd/crypto/blake256` to
`github.com/go-webauthn/x/crypto/blake256`.

```bash
git log --oneline 085eb08c6b1e3aec6a201fd5ac45c64a2daf9144..master -- dcrec/secp256k1
```

### crypto/blake256

The `ecdsa` test vectors of `crypto/secp256k1` are computed over BLAKE-256 hashes, so upstream depends on this package.
It is forked in rather than taken as a dependency to keep it out of this module's dependency graph. Beyond the local
fixes listed below, sources are unmodified apart from rewriting `github.com/decred/dcrd/crypto/blake256` to
`github.com/go-webauthn/x/crypto/blake256`.

The `internal/compress` and `internal/_asm` subpackages record their own bases above because upstream last modified them
earlier than the parent. The leading underscore of `internal/_asm` means the Go tool ignores that directory entirely, so
the nested `go.mod` there and the [avo](https://github.com/mmcloughlin/avo) dependency it pins are never built and form
no part of this module; it is excluded from Renovate via `ignorePaths` in `.renovaterc` for the same reason.

```bash
git log --oneline c32cc6f5cfc72b2b76a38e43d2a702f17e94d248..master -- crypto/blake256
```

### encoding/asn1

Unlike the `crypto` forks, this one diverges from upstream throughout rather than only in its import paths, so upstream
changes cannot be applied wholesale:

- `asn1.go` is renamed to `unmarshal.go` and `asn1_test.go` to `unmarshal_test.go`.
- `common.go`, `marshal.go`, and `unmarshal.go` each carry local modifications threading the marshalling and
  unmarshalling options through the encoder and decoder.
- `ecdsa.go`, `ecdsa_test.go`, `marshal_opts.go`, and `unmarshal_opts.go` have no upstream counterpart.

```bash
git log --oneline 3e43f48cb6311c3c459f5c7aa69ae7d28b7fc821..master -- src/encoding/asn1
```

### revoke

This package reached the repository in two hops, neither of which recorded the commit of the source it was taken from.
Both source commits below were therefore reconstructed after the fact:

1. [github.com/go-webauthn/revoke](https://github.com/go-webauthn/revoke) (now archived) took a snapshot of
   `cloudflare/cfssl` in its initial commit `1edcf14` on 2022-04-04. The newest `cfssl` commit on `master` at that point
   was `e6502bb7ffe4ee576227c9123a101deda248884c` (2022-01-19), which is therefore the upstream base.
2. This repository imported `go-webauthn/revoke` at `dea760d7e233a1a959f1dc5e43f18fd3cd3607e1` (2023-02-09) in commit
   `9ec0dbc` on 2023-02-15, the only difference being the doc comment reformatting `gofmt` applied in Go 1.19.

The fork flattens four separate `cfssl` packages into the single `revoke` package, so upstream changes must be traced
per file rather than against one directory:

| File          | Upstream path            | Last upstream change as of the base |
|---------------|--------------------------|-------------------------------------|
| `revoke.go`   | `revoke/revoke.go`       | `f247e5b` (2021-02-08)              |
| `err.go`      | `errors/error.go`        | `d0cbfb5` (2018-03-22)              |
| `helpers.go`  | `helpers/helpers.go`     | `a8591c3` (2021-09-15)              |
| `pkcs7.go`    | `crypto/pkcs7/pkcs7.go`  | `6ceae7b` (2017-02-07)              |

`doc.go`, `revoke_legacy.go`, and `revoke_modern.go` have no upstream counterpart. The imported files differ from
`cfssl` only by the package renames the flattening requires, the removal of the `cfssl/log` dependency and its logging
calls, and the unqualified references those two changes imply. Local changes made since the import are in this
repository's history under `revoke/`.

```bash
git log --oneline e6502bb7ffe4ee576227c9123a101deda248884c..master -- revoke errors/error.go helpers/helpers.go crypto/pkcs7
```
