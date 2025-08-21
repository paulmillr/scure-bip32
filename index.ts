/**
 * BIP32 hierarchical deterministic (HD) wallets over secp256k1.
 * @module
 * @example
 * ```js
 * import { HDKey } from "@scure/bip32";
 * const hdkey1 = HDKey.fromMasterSeed(seed);
 * const hdkey2 = HDKey.fromExtendedKey(base58key);
 * const hdkey3 = HDKey.fromJSON({ xpriv: string });
 *
 * // props
 * [hdkey1.depth, hdkey1.index, hdkey1.chainCode];
 * console.log(hdkey2.privateKey, hdkey2.publicKey);
 * console.log(hdkey3.derive("m/0/2147483647'/1"));
 * const sig = hdkey3.sign(hash);
 * hdkey3.verify(hash, sig);
 * ```
 */
/*! scure-bip32 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import { secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { abytes, concatBytes, createView } from '@noble/hashes/utils.js';
import { createBase58check } from '@scure/base';

const Point = secp.Point;
const { Fn } = Point;
const base58check = createBase58check(sha256);

const MASTER_SECRET = Uint8Array.from('Bitcoin seed'.split(''), (char) => char.charCodeAt(0));

/** Network-specific versioning. */
export interface Versions {
  private: number;
  public: number;
}

const BITCOIN_VERSIONS: Versions = { private: 0x0488ade4, public: 0x0488b21e };
/** Hardened offset from Bitcoin, default */
export const HARDENED_OFFSET: number = 0x80000000;

const hash160 = (data: Uint8Array) => ripemd160(sha256(data));
const fromU32 = (data: Uint8Array) => createView(data).getUint32(0, false);
const toU32 = (n: number): Uint8Array => {
  if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1) {
    throw new Error('invalid number, should be from 0 to 2**32-1, got ' + n);
  }
  const buf = new Uint8Array(4);
  createView(buf).setUint32(0, n, false);
  return buf;
};

interface HDKeyOpt {
  versions?: Versions;
  depth?: number;
  index?: number;
  parentFingerprint?: number;
  chainCode?: Uint8Array;
  publicKey?: Uint8Array;
  privateKey?: Uint8Array;
}

/**
 * HDKey from BIP32
 * @example
```js
const hdkey1 = HDKey.fromMasterSeed(seed);
const hdkey2 = HDKey.fromExtendedKey(base58key);
const hdkey3 = HDKey.fromJSON({ xpriv: string });
```
 */
export class HDKey {
  get fingerprint(): number {
    if (!this.pubHash) {
      throw new Error('No publicKey set!');
    }
    return fromU32(this.pubHash);
  }
  get identifier(): Uint8Array | undefined {
    return this.pubHash;
  }
  get pubKeyHash(): Uint8Array | undefined {
    return this.pubHash;
  }
  get privateKey(): Uint8Array | null {
    return this._privateKey || null;
  }
  get publicKey(): Uint8Array | null {
    return this._publicKey || null;
  }
  get privateExtendedKey(): string {
    const priv = this._privateKey;
    if (!priv) {
      throw new Error('No private key');
    }
    return base58check.encode(
      this.serialize(this.versions.private, concatBytes(Uint8Array.of(0), priv))
    );
  }
  get publicExtendedKey(): string {
    if (!this._publicKey) {
      throw new Error('No public key');
    }
    return base58check.encode(this.serialize(this.versions.public, this._publicKey));
  }

  static fromMasterSeed(seed: Uint8Array, versions: Versions = BITCOIN_VERSIONS): HDKey {
    abytes(seed);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new Error(
        'HDKey: seed length must be between 128 and 512 bits; 256 bits is advised, got ' +
          seed.length
      );
    }
    const I = hmac(sha512, MASTER_SECRET, seed);
    const privateKey = I.slice(0, 32);
    const chainCode = I.slice(32);
    return new HDKey({ versions, chainCode, privateKey });
  }

  static fromExtendedKey(base58key: string, versions: Versions = BITCOIN_VERSIONS): HDKey {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    const keyBuffer: Uint8Array = base58check.decode(base58key);
    const keyView = createView(keyBuffer);
    const version = keyView.getUint32(0, false);
    const opt = {
      versions,
      depth: keyBuffer[4],
      parentFingerprint: keyView.getUint32(5, false),
      index: keyView.getUint32(9, false),
      chainCode: keyBuffer.slice(13, 45),
    };
    const key = keyBuffer.slice(45);
    const isPriv = key[0] === 0;
    if (version !== versions[isPriv ? 'private' : 'public']) {
      throw new Error('Version mismatch');
    }
    if (isPriv) {
      return new HDKey({ ...opt, privateKey: key.slice(1) });
    } else {
      return new HDKey({ ...opt, publicKey: key });
    }
  }

  public static fromJSON(json: { xpriv: string }): HDKey {
    return HDKey.fromExtendedKey(json.xpriv);
  }
  readonly versions: Versions;
  readonly depth: number = 0;
  readonly index: number = 0;
  readonly chainCode: Uint8Array | null = null;
  readonly parentFingerprint: number = 0;
  private _privateKey?: Uint8Array;
  private _publicKey?: Uint8Array;
  private pubHash: Uint8Array | undefined;

  constructor(opt: HDKeyOpt) {
    if (!opt || typeof opt !== 'object') {
      throw new Error('HDKey.constructor must not be called directly');
    }
    this.versions = opt.versions || BITCOIN_VERSIONS;
    this.depth = opt.depth || 0;
    this.chainCode = opt.chainCode || null;
    this.index = opt.index || 0;
    this.parentFingerprint = opt.parentFingerprint || 0;
    if (!this.depth) {
      if (this.parentFingerprint || this.index) {
        throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
      }
    }
    if (this.depth > 255) {
      throw new Error('HDKey: depth exceeds the serializable value 255');
    }
    if (opt.publicKey && opt.privateKey) {
      throw new Error('HDKey: publicKey and privateKey at same time.');
    }
    if (opt.privateKey) {
      if (!secp.utils.isValidSecretKey(opt.privateKey)) throw new Error('Invalid private key');
      this._privateKey = opt.privateKey;
      this._publicKey = secp.getPublicKey(opt.privateKey, true);
    } else if (opt.publicKey) {
      this._publicKey = Point.fromBytes(opt.publicKey).toBytes(true); // force compressed point
    } else {
      throw new Error('HDKey: no public or private key provided');
    }
    this.pubHash = hash160(this._publicKey);
  }

  derive(path: string): HDKey {
    if (!/^[mM]'?/.test(path)) {
      throw new Error('Path must start with "m" or "M"');
    }
    if (/^[mM]'?$/.test(path)) {
      return this;
    }
    const parts = path.replace(/^[mM]'?\//, '').split('/');
    // tslint:disable-next-line
    let child: HDKey = this;
    for (const c of parts) {
      const m = /^(\d+)('?)$/.exec(c);
      const m1 = m && m[1];
      if (!m || m.length !== 3 || typeof m1 !== 'string')
        throw new Error('invalid child index: ' + c);
      let idx = +m1;
      if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) {
        throw new Error('Invalid index');
      }
      // hardened key
      if (m[2] === "'") {
        idx += HARDENED_OFFSET;
      }
      child = child.deriveChild(idx);
    }
    return child;
  }

  deriveChild(index: number): HDKey {
    if (!this._publicKey || !this.chainCode) {
      throw new Error('No publicKey or chainCode set');
    }
    let data = toU32(index);
    if (index >= HARDENED_OFFSET) {
      // Hardened
      const priv = this._privateKey;
      if (!priv) {
        throw new Error('Could not derive hardened child key');
      }
      // Hardened child: 0x00 || ser256(kpar) || ser32(index)
      data = concatBytes(Uint8Array.of(0), priv, data);
    } else {
      // Normal child: serP(point(kpar)) || ser32(index)
      data = concatBytes(this._publicKey, data);
    }
    const I = hmac(sha512, this.chainCode, data);
    const childTweak = I.slice(0, 32);
    const chainCode = I.slice(32);
    if (!secp.utils.isValidSecretKey(childTweak)) {
      throw new Error('Tweak bigger than curve order');
    }
    const opt: HDKeyOpt = {
      versions: this.versions,
      chainCode,
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      index,
    };
    const ctweak = Fn.fromBytes(childTweak);
    try {
      // Private parent key -> private child key
      if (this._privateKey) {
        const added = Fn.create(Fn.fromBytes(this._privateKey) + ctweak);
        if (!Fn.isValidNot0(added)) {
          throw new Error('The tweak was out of range or the resulted private key is invalid');
        }
        opt.privateKey = Fn.toBytes(added);
      } else {
        const added = Point.fromBytes(this._publicKey).add(Point.BASE.multiply(ctweak));
        // Cryptographically impossible: hmac-sha512 preimage would need to be found
        if (added.equals(Point.ZERO)) {
          throw new Error('The tweak was equal to negative P, which made the result key invalid');
        }
        opt.publicKey = added.toBytes(true);
      }
      return new HDKey(opt);
    } catch (err) {
      return this.deriveChild(index + 1);
    }
  }

  sign(hash: Uint8Array): Uint8Array {
    if (!this._privateKey) {
      throw new Error('No privateKey set!');
    }
    abytes(hash, 32);
    return secp.sign(hash, this._privateKey, { prehash: false });
  }

  verify(hash: Uint8Array, signature: Uint8Array): boolean {
    abytes(hash, 32);
    abytes(signature, 64);
    if (!this._publicKey) {
      throw new Error('No publicKey set!');
    }
    return secp.verify(signature, hash, this._publicKey, { prehash: false });
  }

  wipePrivateData(): this {
    if (this._privateKey) {
      this._privateKey.fill(0);
      this._privateKey = undefined;
    }
    return this;
  }
  toJSON(): { xpriv: string; xpub: string } {
    return {
      xpriv: this.privateExtendedKey,
      xpub: this.publicExtendedKey,
    };
  }

  private serialize(version: number, key: Uint8Array) {
    if (!this.chainCode) {
      throw new Error('No chainCode set');
    }
    abytes(key, 33);
    // version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    return concatBytes(
      toU32(version),
      new Uint8Array([this.depth]),
      toU32(this.parentFingerprint),
      toU32(this.index),
      this.chainCode,
      key
    );
  }
}
