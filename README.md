# scure-bip32

Audited & minimal implementation of BIP32 hierarchical deterministic (HD) wallets over secp256k1.

- 🔒 [Audited](#security) by an independent security firm
- 🔻 Tree-shakeable: unused code is excluded from your builds
- 📦 ESM
- ➰ Only 3 audited dependencies by the same author:
  [noble-curves](https://github.com/paulmillr/noble-curves),
  [noble-hashes](https://github.com/paulmillr/noble-hashes),
  and [scure-base](https://github.com/paulmillr/scure-base)
- 🪶 18KB gzipped with all dependencies bundled

Check out [scure-bip39](https://github.com/paulmillr/scure-bip39) if you need mnemonic phrases.
See [key-producer](https://github.com/paulmillr/micro-key-producer) if you need SLIP-0010/BIP32 ed25519 hdkey implementation.
Notice [Warnings about BIP32](#warnings-about-bip32).

### This library belongs to _scure_

> **scure** — audited micro-libraries.

- Zero or minimal dependencies
- Highly readable TypeScript / JS code
- PGP-signed releases and transparent NPM builds
- Check out [homepage](https://paulmillr.com/noble/#scure) & all libraries:
  [base](https://github.com/paulmillr/scure-base),
  [bip32](https://github.com/paulmillr/scure-bip32),
  [bip39](https://github.com/paulmillr/scure-bip39),
  [btc-signer](https://github.com/paulmillr/scure-btc-signer),
  [sr25519](https://github.com/paulmillr/scure-sr25519),
  [starknet](https://github.com/paulmillr/scure-starknet)

## Usage

> `npm install @scure/bip32`

> `deno add jsr:@scure/bip32`

Two immutable key types, `HDPrivateKey` (xprv) and `HDPublicKey` (xpub):

```ts
import { HDPrivateKey, HDPublicKey, fromExtendedKey, parsePath } from '@scure/bip32';
import { randomBytes } from '@noble/hashes/utils.js';

const seed = randomBytes(32); // or mnemonicToSeedSync() from @scure/bip39
const root = HDPrivateKey.fromMasterSeed(seed);
const account = root.derive("m/84'/0'/0'");
const xprv = account.toExtended(); // 'xprv...'
const xpub = account.toPublic().toExtended(); // 'xpub...'

// Watch-only side: relative derivation, no secrets in scope
const watch = HDPublicKey.fromExtended(xpub);
const receive5 = watch.derive('0/5').publicKey; // 33-byte compressed key
const change = watch.derive([1, 0]); // array form == relative indexes

// Unknown string → narrow by type
const key = fromExtendedKey(xprv);
if (key instanceof HDPrivateKey) key.privateKey;

// PSBT-style metadata
const derivation = { fingerprint: root.fingerprint, path: parsePath("m/84'/0'/0'/0/5").indexes };
```

Rules that follow from the two types:

- `HDPublicKey` has no `privateKey`, cannot derive hardened children (`0'`, `0h`, index `>= HARDENED_OFFSET`)
  and `toExtended()` always yields an xpub. `HDPrivateKey.toPublic()` is BIP32's `N()`.
- Byte getters (`publicKey`, `chainCode`, `identifier`, `privateKey`) return fresh copies;
  keys are never mutated after construction. `chainCode` is part of the secret: guard it like the key.
- `derive(path)` accepts absolute paths (`m/...`) only on a depth-0 key and relative paths
  (`0/1'`) on any key. Hardened markers `'` and `h` are both accepted. `deriveChild(index)`
  is one step; hardened indexes are `index + HARDENED_OFFSET`.
- `JSON.stringify(publicKey)` yields the xpub string; `JSON.stringify(privateKey)` throws —
  private material only leaves via an explicit `toExtended()`.
- Version bytes are a serialization concern, not a key property: pass them to
  `toExtended(versions)` / `fromExtended(key, versions)`. Default is Bitcoin mainnet.

Signing is left to the caller so any signature shape can be used:

```ts
import { HDPrivateKey } from '@scure/bip32';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';

const key = HDPrivateKey.fromMasterSeed(randomBytes(32)).derive("m/86'/0'/0'/0/0");
const msgHash = sha256(new TextEncoder().encode('hello scure-bip32'));
const sig = secp256k1.sign(msgHash, key.privateKey, { prehash: false });
const ok = secp256k1.verify(sig, msgHash, key.publicKey, { prehash: false });
const taproot = schnorr.sign(msgHash, key.privateKey);
```

Other networks:

```ts
import { HDPrivateKey, HDPublicKey } from '@scure/bip32';
import { randomBytes } from '@noble/hashes/utils.js';

const TESTNET = { private: 0x04358394, public: 0x043587cf }; // tprv / tpub
const root = HDPrivateKey.fromMasterSeed(randomBytes(32));
const tpub = root.derive("m/84'/1'/0'").toPublic().toExtended(TESTNET);
const acct = HDPublicKey.fromExtended(tpub, TESTNET); // wrong network throws
const next = acct.derive('0/1').toExtended(TESTNET);
```

The full API is:

```ts
declare const HARDENED_OFFSET: number; // 0x80000000
declare const BITCOIN_VERSIONS: Versions; // xprv / xpub, the default everywhere
interface Versions {
  private: number;
  public: number;
}
interface NodeMeta {
  depth?: number;
  index?: number;
  parentFingerprint?: number;
}
/** "m/44'/0h/1" → { absolute: true, indexes: [0x8000002c, 0x80000000, 1] } */
declare function parsePath(path: string): { absolute: boolean; indexes: number[] };

/** What both key types share; use as a parameter type when either is fine. */
interface HDNode {
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  readonly publicKey: Uint8Array; // 33 bytes, copy
  readonly chainCode: Uint8Array; // 32 bytes, copy
  readonly identifier: Uint8Array; // hash160(publicKey), copy
  readonly fingerprint: number; // first 4 bytes of identifier
  deriveChild(index: number): HDNode;
  derive(path: string | number[]): HDNode;
  toExtended(versions?: Versions): string;
}
declare class HDPublicKey implements HDNode {
  constructor(publicKey: Uint8Array, chainCode: Uint8Array, meta?: NodeMeta);
  static fromExtended(xpub: string, versions?: Versions): HDPublicKey; // throws on xprv
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  readonly publicKey: Uint8Array;
  readonly chainCode: Uint8Array;
  readonly identifier: Uint8Array;
  readonly fingerprint: number;
  deriveChild(index: number): HDPublicKey; // hardened → throws
  derive(path: string | number[]): HDPublicKey;
  toExtended(versions?: Versions): string; // xpub
  toJSON(): string; // xpub
}
declare class HDPrivateKey implements HDNode {
  constructor(privateKey: Uint8Array, chainCode: Uint8Array, meta?: NodeMeta);
  static fromMasterSeed(seed: Uint8Array): HDPrivateKey; // 16..64 bytes
  static fromExtended(xprv: string, versions?: Versions): HDPrivateKey; // throws on xpub
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  readonly privateKey: Uint8Array; // 32 bytes, copy
  readonly publicKey: Uint8Array;
  readonly chainCode: Uint8Array;
  readonly identifier: Uint8Array;
  readonly fingerprint: number;
  toPublic(): HDPublicKey; // BIP32 N()
  deriveChild(index: number): HDPrivateKey;
  derive(path: string | number[]): HDPrivateKey;
  toExtended(versions?: Versions): string; // xprv
  toJSON(): never; // throws
}
/** Decodes either kind; narrow with `instanceof HDPrivateKey`. */
declare function fromExtendedKey(key: string, versions?: Versions): HDPrivateKey | HDPublicKey;
```

### Legacy `HDKey` (2.x API)

The 2.x class `HDKey` is still exported, unchanged in behaviour, but is now a thin adapter over
the two classes above and is deprecated; it will be removed in the next major.
`hdkey.node` returns the underlying `HDPrivateKey | HDPublicKey`, and `new HDKey(node, versions?)`
wraps one for code still typed on `HDKey`. Two deliberate differences from 2.x:
`wipePrivateData()` swaps in the public node instead of zeroing bytes (returned copies were never
zeroed anyway), and constructing without a `chainCode` now throws.

| 2.x                                                | 3.x                                                              |
| -------------------------------------------------- | ---------------------------------------------------------------- |
| `HDKey.fromMasterSeed(seed, versions)`             | `HDPrivateKey.fromMasterSeed(seed)`; versions move to `toExtended` |
| `HDKey.fromExtendedKey(s, versions)`               | `fromExtendedKey(s, versions)` or `HDPrivateKey.fromExtended` / `HDPublicKey.fromExtended` |
| `new HDKey({ privateKey, chainCode, depth, ... })` | `new HDPrivateKey(privateKey, chainCode, { depth, ... })`        |
| `new HDKey({ publicKey, chainCode })`              | `new HDPublicKey(publicKey, chainCode)`                          |
| `.privateExtendedKey` / `.publicExtendedKey`       | `.toExtended()` / `.toPublic().toExtended()`                     |
| `.wipePrivateData()`                               | `.toPublic()`, then drop the private reference                   |
| `.pubKeyHash`                                      | `.identifier`                                                    |
| `.sign(hash)` / `.verify(hash, sig)`               | `secp256k1.sign(hash, key.privateKey, { prehash: false })` / `secp256k1.verify(...)` |
| `.toJSON()`, `.toPrivateJSON()`, `HDKey.fromJSON()` | `.toExtended()` / `fromExtendedKey()`                            |
| `.derive("m/0/1")` — `m` means "this key"          | `.derive("m/0/1")` absolute from depth 0 only; `.derive("0/1")` relative anywhere |
| `.deriveChild(i)`, `HARDENED_OFFSET`, `.depth`, `.index`, `.parentFingerprint`, `.fingerprint`, `.identifier` | unchanged |
| `.versions`                                        | gone; pass to `toExtended` / `fromExtended`                      |

The module implements [bip32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) standard:
check it out for additional documentation.

The legacy `HDKey` API is loosely based on cryptocoinjs/hdkey, [which has MIT License](#LICENSE).

## Warnings about BIP32

BIP32 is a bad standard. It would be great if we've had something better.

- Network IDs (different currencies) are taken from a single GitHub document
  called SLIP-0044
- There were new projects, which did not yet have SLIP. Exchanges added support of
  those projects to their cold wallets. Then after the projects were added to SLIP,
  the exchanges were required to re-generate their cold wallets - a complicated task
- BIP32 is unusable for many different elliptic curves. For example, ETH2 uses bls12-381
  curve, and with bip32 54% of generated keys would be invalid. So, they’re using much better
  BLS-only EIP-2333 as a replacement.
- It’s easy to shoot yourself in foot with non-hardened keys, which
  could allow simple de-anonimization of all addresses

## Security

The library has been audited:

- at version 2.2.0, in Apr 2026, by ourselves (self-audited)
  - Scope: everything
  - [Changes since audit](https://github.com/paulmillr/scure-bip32/compare/2.2.0..main)
- at version 1.0.1, in Jan 2022, independently, by [cure53](https://cure53.de)
  - PDFs: [online](https://cure53.de/pentest-report_hashing-libs.pdf), [offline](./audit/2022-01-05-cure53-audit-nbl2.pdf)
  - [Changes since audit](https://github.com/paulmillr/scure-bip32/compare/1.0.0..main).
  - The audit has been funded by [Ethereum Foundation](https://ethereum.org/en/) with help of [Nomic Labs](https://nomiclabs.io)

The library was initially developed for [js-ethereum-cryptography](https://github.com/ethereum/js-ethereum-cryptography).
At commit [ae00e6d7](https://github.com/ethereum/js-ethereum-cryptography/commit/ae00e6d7d24fb3c76a1c7fe10039f6ecd120b77e),
it was extracted to a separate package called `micro-bip32`.
After the audit we've decided to use `@scure` NPM namespace for security.

### Supply chain security

- **Commits** are signed with PGP keys to prevent forgery. Be sure to verify the commit signatures
- **Releases** are made transparently through token-less GitHub CI and Trusted Publishing. Be sure to verify the [provenance logs](https://docs.npmjs.com/generating-provenance-statements) for authenticity.
- **Rare releasing** is practiced to minimize the need for re-audits by end-users.
- **Dependencies** are minimized and strictly pinned to reduce supply-chain risk.
  - We use as few dependencies as possible.
  - Version ranges are locked, and changes are checked with npm-diff.
- **Dev dependencies** are excluded from end-user installs; they’re only used for development and build steps.

For this package, there are 3 dependencies; and a few dev dependencies:

- [noble-hashes](https://github.com/paulmillr/noble-hashes) provides cryptographic hashing functionality
- [noble-curves](https://github.com/paulmillr/noble-curves) provides ECDSA
- [scure-base](https://github.com/paulmillr/scure-base) provides base58
- jsbt is used for benchmarking / testing / build tooling and developed by the same author
- prettier and typescript are used for code quality / ts compilation

## License

[MIT License](./LICENSE)

Copyright (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com)
