# Changelog for scure-bip32

## 2.4.0 (2026-08-28)

Hardening:

- The `privateKey`, `publicKey`, `chainCode`, `identifier`, `pubKeyHash` now return copies instead of live buffers
- `deriveChild` no longer blindly try-catches. Use proper filtered-by-kind error handling. Retries will stop at last
  valid index instead of overflowing with error
- `fromExtendedKey` now rejects checksum-valid payloads that are not exactly 78 bytes
- Stricter `HDKey` constructor validation: `depth` must be an integer in 0..255 (throws `RangeError`), `index` and `parentFingerprint` must be valid uint32 values, and `chainCode` must be exactly 32 bytes
- `derive(path)` now rejects paths up front that would exceed the maximum serializable depth of 255
- Added `toPrivateJSON()` for explicit private (`xpriv` + `xpub`) export; `toJSON()` currently still includes `xpriv` for backwards compatibility (planned to become public-only in v3, so migrate to `toPrivateJSON()` for private round-trips)
- `fromJSON` now also accepts `{ xpub }` to restore a public-only key
- Upgrade deps: noble-hashes, noble-curves and scure-base to 2.4.0.

## 2.3.0 (2026-08-08)

- Improve validation and error messages.
- Upgrade deps: noble-hashes, noble-curves and scure-base to 2.3.0.
- Reduce on-disk package size: 47.5kb → 35.7kb (-11.8kb), by disabling source maps (they became less relevant).
- Reduce npm package size:  13.3kb → 8.63kb (-4.68kb)

## 2.2.0 (2026-04-21)

* **April 2026 self-audit** (all files): no major issues found
  * Audited for spec compliance and security
* Fix all Byte Array types, to ensure proper work in both TypeScript 5.6 & TypeScript 5.9+
  * TS 5.6 has `Uint8Array`, while TS 5.9+ made it generic `Uint8Array<ArrayBuffer>`
  * This creates incompatibility of code between versions
  * Previously, it was hard to use and constantly emitted errors similar to `TS2345`
  * See [typescript#62240](https://github.com/microsoft/TypeScript/issues/62240) for more context
* Fix compilation issues on TypeScript v6
* Upgrade dependencies to self-audited 2.2.0

*(We're skipping v2.1, to align with other noble / scure packages)*

## 2.0.1 (2025-10-07)

- Upgrade noble-hashes to v2.0.1 and noble-curves to v2.0.1
- Upgrade noble-hashes to [2.0.1](https://github.com/paulmillr/noble-hashes/releases/tag/2.0.1)
- Upgrade noble-curves to [2.0.1](https://github.com/paulmillr/noble-curves/releases/tag/2.0.1)

## 2.0.0 (2025-08-25)

- The package is now ESM-only. ESM can finally be loaded from common.js on node v20.19+
    - Node v20.19 is now the minimum required version
    - Package imports now work correctly in bundler-less environments, such as browsers
    - Reduces npm package size (traffic consumed): 15KB => 11.7KB
    - Reduces unpacked npm size (on-disk space): 67KB => 43KB
- Make bundle sizes smaller, compared to v1.x
- Upgrade to noble-hashes, noble-curves & scure-base v2
- Prohibit HD key depths over 255 to match spec
- Upgrade typescript compilation env to ts5.9 and es2022

## 1.7.0 (2025-04-24)

- Bump hashes to [v1.8.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.8.0), curves to [v1.9.0](https://github.com/paulmillr/noble-curves/releases/tag/1.9.0), base to [v1.2.5](https://github.com/paulmillr/scure-base/releases/tag/1.2.5)
- Standalone build files are now attested, check out README for verification instructions

## 1.6.2 (2025-01-18)

- Use typescript verbatimModuleSyntax to support future node.js type stripping
- Improve docs

## 1.6.1 (2025-01-03)

* Bump noble-curves to [1.8.0](https://github.com/paulmillr/noble-curves/releases/tag/1.8.0) and noble-hashes to [1.7.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.0)
* Use typescript isolatedDeclarations to improve docs
* Publish to JSR

## 1.6.0 (2024-11-23)

- Bump hashes to [v1.6.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.6.0), curves to [v1.7.0](https://github.com/paulmillr/noble-curves/releases/tag/1.7.0), base to [1.2.0](https://github.com/paulmillr/scure-base/releases/tag/1.2.0)
- Improve type checks for bigints

## 1.5.0 (2024-09-03)

* Bump noble-curves to [v1.6.0](https://github.com/paulmillr/noble-curves/releases/tag/1.6.0)
* Bump noble-hashes to [v1.5.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.5.0)
* Improve typescript compatibility by emitting separate types for cjs / esm

## 1.4.0 (2024-03-20)

* Fix `HDKeyOpt` type by @arobsn in https://github.com/paulmillr/scure-bip32/pull/14
- Update deps
    - noble-curves to 1.4.0: https://github.com/paulmillr/noble-curves/releases/tag/1.4.0
    - noble-hashes to 1.4.0: https://github.com/paulmillr/noble-hashes/releases/tag/1.4.0
    - scure-base to 1.1.6: https://github.com/paulmillr/scure-base/releases/tag/1.1.6

## 1.3.3 (2023-12-12)

- Update deps
    - noble-curves to 1.3.0: https://github.com/paulmillr/noble-curves/releases/tag/1.3.0
    - noble-hashes to 1.3.3: https://github.com/paulmillr/noble-hashes/releases/tag/1.3.3
    - scure-base to 1.1.4: https://github.com/paulmillr/scure-base/releases/tag/1.1.4

## 1.3.2 (2023-08-25)

- Improve tree-shaking, decrease bundle size
- Update deps
    - noble-curves from 1.1.0 to 1.2.0: https://github.com/paulmillr/noble-curves/releases/tag/1.2.0
    - noble-hashes from 1.3.1 to 1.3.2: https://github.com/paulmillr/noble-hashes/releases/tag/1.3.2
    - scure-base from 1.1.0 to 1.1.2: https://github.com/paulmillr/scure-base/releases/tag/1.1.2

## 1.3.1 (2023-07-10)

- Update noble-curves from 1.0.0 to 1.1.0: https://github.com/paulmillr/noble-curves/releases/tag/1.1.0
- Update noble-hashes from 1.3.0 to 1.3.1: https://github.com/paulmillr/noble-hashes/releases/tag/1.3.1

## 1.3.0 (2023-04-12)

Use stable noble-curves.

## 1.2.0 (2023-03-16)

Switch from noble-secp256k1 to noble-curves.

## 1.1.5 (2023-02-03)

Added source maps

## 1.1.4 (2023-02-02)

Update dependencies

## 1.1.3 (2023-01-09)

* Improves compatibility with new version of noble/secp256k1

## 1.1.2 (2023-01-09)

* Improves compatibility with new version of noble/secp256k1
* This release was not built correctly, bump straight to 1.1.3

## 1.1.1 (2022-09-30)

* Improve type check in `fromMasterSeed()`
* Bump dependencies

## 1.1.0 (2022-06-12)

- Improve ESM support
- Update dependencies
- Remove viral `esModuleInterop` option from typescript compiling

## 1.0.1 (2022-02-17)

First post-audit stable release

## 0.1.0 (2021-12-31)

- Initial release
