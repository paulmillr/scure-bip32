# micro-bip32

Create BIP32 hierarchical deterministic (HD) wallets with minimum dependencies.

Developed for, and then extracted from
[js-ethereum-cryptography](https://github.com/ethereum/js-ethereum-cryptography). The source code is the same,
the files have been copied for convenience.

Check out [micro-bip39](https://github.com/paulmillr/micro-bip39) if you need
mnemonic phrases.

## Usage

> npm install micro-bip32

Or, `yarn add micro-bip32`

## API

This module exports a single class `HDKey`, which should be used like this:

```ts
const { HDKey } = require("micro-bip32");
const hdkey1 = HDKey.fromMasterSeed(seed);
const hdkey2 = HDKey.fromExtendedKey(base58key);
const hdkey3 = HDKey.fromJSON({ xpriv: string });

// props
[hdkey1.depth, hdkey1.index, hdkey1.chainCode];
console.log(hdkey2.privateKey, hdkey2.publicKey);
console.log(hdkey3.derive("m/0/2147483647'/1"));
const sig = hdkey3.sign(hash);
hdkey3.verify(hash, sig);
```

Note: `chainCode` property is essentially a private part
of a secret "master" key, it should be guarded from unauthorized access.

The full API is:

```ts
class HDKey {
  public static HARDENED_OFFSET: number;
  public static fromMasterSeed(seed: Uint8Array, versions: Versions): HDKey;
  public static fromExtendedKey(base58key: string, versions: Versions): HDKey;
  public static fromJSON(json: { xpriv: string }): HDKey;

  readonly versions: Versions;
  readonly depth: number = 0;
  readonly index: number = 0;
  readonly chainCode: Uint8Array | null = null;
  readonly parentFingerprint: number = 0;

  get fingerprint(): number;
  get identifier(): Uint8Array | undefined;
  get pubKeyHash(): Uint8Array | undefined;
  get privateKey(): Uint8Array | null;
  get publicKey(): Uint8Array | null;
  get privateExtendedKey(): string;
  get publicExtendedKey(): string;

  derive(path: string): HDKey;
  deriveChild(index: number): HDKey;
  sign(hash: Uint8Array): Uint8Array;
  verify(hash: Uint8Array, signature: Uint8Array): boolean;
  wipePrivateData(): this;
}

interface Versions {
  private: number;
  public: number;
}
```

The `hdkey` submodule provides a library for keys derivation according to
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

It has almost the exact same API than the version `1.x` of
[`hdkey` from cryptocoinjs](https://github.com/cryptocoinjs/hdkey),
but it's backed by this package's primitives, and has built-in TypeScript types.
Its only difference is that it has to be be used with a named import.
The implementation is [loosely based on hdkey, which has MIT License](#LICENSE).

## License

[MIT License](./LICENSE)

Copyright (c) 2021 Patricio Palladino, Paul Miller, ethereum-cryptography contributors
