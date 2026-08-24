/**
 * BIP32 hierarchical deterministic (HD) wallets over secp256k1.
 * @module
 * @example
 * ```js
 * import { HDKey } from "@scure/bip32";
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const seed = randomBytes(32);
 * const root = HDKey.fromMasterSeed(seed);
 * const base58key = root.privateExtendedKey;
 * const restored = HDKey.fromExtendedKey(base58key);
 * const fromJson = HDKey.fromJSON({ xpriv: base58key });
 * const child = fromJson.derive("m/0/2147483647'/1");
 * const msgHash = sha256(new TextEncoder().encode('hello scure-bip32'));
 *
 * // props
 * [root.depth, root.index, root.chainCode];
 * [restored.privateKey, restored.publicKey];
 * const sig = child.sign(msgHash);
 * child.verify(msgHash, sig);
 * ```
 */
/*! scure-bip32 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import { secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { abytes, concatBytes, createView, type TArg, type TRet } from '@noble/hashes/utils.js';
import { createBase58check } from '@scure/base';

const Point = /* @__PURE__ */ (() => secp.Point)();
const Fn = /* @__PURE__ */ (() => Point.Fn)();
const base58check = /* @__PURE__ */ createBase58check(sha256);
const MASTER_SECRET = /* @__PURE__ */ (() => {
  return Uint8Array.from('Bitcoin seed'.split(''), (char) => char.charCodeAt(0));
})();

/** Network-specific BIP32 version bytes. */
export interface Versions {
  /** 4-byte version used when serializing private extended keys. */
  private: number;
  /** 4-byte version used when serializing public extended keys. */
  public: number;
}

const BITCOIN_VERSIONS: Versions = { private: 0x0488ade4, public: 0x0488b21e };
/** Hardened child index offset from BIP32. */
export const HARDENED_OFFSET: number = 0x80000000;
const MAX_DEPTH = 0xff;

const hash160 = (data: TArg<Uint8Array>) => ripemd160(sha256(data));
const fromU32 = (data: TArg<Uint8Array>) => createView(data).getUint32(0, false);
const toU32 = (n: number, title: string = 'number'): TRet<Uint8Array> => {
  if (typeof n !== 'number')
    throw new TypeError(`"${title}" expected number, got type=${typeof n}`);
  if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1)
    throw new RangeError(`"${title}" expected integer in range 0..2**32-1, got ${n}`);
  const buf = new Uint8Array(4);
  createView(buf).setUint32(0, n, false);
  return buf;
};
const validateVersions = (versions: TArg<Versions>, title: string = 'versions'): Versions => {
  if (!(typeof versions === 'object' && versions !== null))
    throw new Error('versions must be an object');
  toU32((versions as Versions).private, `${title}.private`);
  toU32((versions as Versions).public, `${title}.public`);
  return versions as Versions;
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
 * @param opt - Node fields used to construct one HDKey instance.
 * @example
 * ```js
 * import { HDKey } from '@scure/bip32';
 * import { randomBytes } from '@noble/hashes/utils.js';
 *
 * const seed = randomBytes(32);
 * const root = HDKey.fromMasterSeed(seed);
 * const account0 = root.derive("m/0/1'");
 * account0.publicKey;
 * ```
 */
export class HDKey {
  get fingerprint(): number {
    if (!this._pubHash) {
      throw new Error('No publicKey set!');
    }
    return fromU32(this._pubHash);
  }
  get identifier(): Uint8Array | undefined {
    return this._pubHash ? Uint8Array.from(this._pubHash) : undefined;
  }
  get pubKeyHash(): Uint8Array | undefined {
    return this._pubHash ? Uint8Array.from(this._pubHash) : undefined;
  }
  get privateKey(): Uint8Array | null {
    return this._privateKey ? Uint8Array.from(this._privateKey) : null;
  }
  get publicKey(): Uint8Array | null {
    return this._publicKey ? Uint8Array.from(this._publicKey) : null;
  }
  get chainCode(): Uint8Array | null {
    return this._chainCode ? Uint8Array.from(this._chainCode) : null;
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
    versions = validateVersions(versions);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new RangeError(
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
    versions = validateVersions(versions);
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    const keyBuffer: Uint8Array = base58check.decode(base58key);
    if (keyBuffer.length !== 78) {
      throw new Error(
        `HDKey: invalid extended key length: expected 78 bytes, got ${keyBuffer.length}`
      );
    }
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

  public static fromJSON(json: { xpriv: string } | { xpub: string }): HDKey {
    return HDKey.fromExtendedKey('xpriv' in json ? json.xpriv : json.xpub);
  }
  readonly versions: Versions;
  readonly depth: number = 0;
  readonly index: number = 0;
  readonly parentFingerprint: number = 0;
  private _chainCode: Uint8Array | null = null;
  private _privateKey?: Uint8Array;
  private _publicKey?: Uint8Array;
  private _pubHash: Uint8Array | undefined;

  constructor(opt: HDKeyOpt) {
    if (!opt || typeof opt !== 'object') {
      throw new Error('HDKey.constructor must not be called directly');
    }
    const depth = opt.depth ?? 0;
    const index = opt.index ?? 0;
    const parentFingerprint = opt.parentFingerprint ?? 0;
    if (!Number.isSafeInteger(depth) || depth < 0 || depth > MAX_DEPTH) {
      throw new RangeError('HDKey: depth must be an integer in range 0..255');
    }
    toU32(index, 'index');
    toU32(parentFingerprint, 'parentFingerprint');
    if (depth === 0 && (index !== 0 || parentFingerprint !== 0)) {
      throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
    }
    this.versions = opt.versions ? validateVersions(opt.versions) : BITCOIN_VERSIONS;
    this.depth = depth;
    if (opt.chainCode) abytes(opt.chainCode, 32);
    this._chainCode = opt.chainCode ? Uint8Array.from(opt.chainCode) : null;
    this.index = index;
    this.parentFingerprint = parentFingerprint;
    if (opt.publicKey && opt.privateKey) {
      throw new Error('HDKey: publicKey and privateKey at same time.');
    }
    if (opt.privateKey) {
      if (!secp.utils.isValidSecretKey(opt.privateKey)) throw new Error('Invalid private key');
      // Don't alias caller-owned secret buffers.
      this._privateKey = Uint8Array.from(opt.privateKey);
      this._publicKey = secp.getPublicKey(this._privateKey, true);
    } else if (opt.publicKey) {
      this._publicKey = Point.fromBytes(opt.publicKey).toBytes(true); // force compressed point
    } else {
      throw new Error('HDKey: no public or private key provided');
    }
    this._pubHash = hash160(this._publicKey);
  }

  derive(path: string): HDKey {
    if (!/^[mM]'?/.test(path)) {
      throw new Error('Path must start with "m" or "M"');
    }
    if (/^[mM]'?$/.test(path)) {
      return this;
    }
    const parts = path.replace(/^[mM]'?\//, '').split('/');
    if (parts.length > MAX_DEPTH - this.depth) {
      throw new Error('HDKey: path exceeds the serializable depth 255');
    }
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
    return this._deriveChild(index);
  }

  /** Test-only implementation seam. Production callers must use deriveChild(). */
  private _deriveChild(index: number, _I?: Uint8Array): HDKey {
    if (!this._publicKey || !this._chainCode) {
      throw new Error('No publicKey or chainCode set');
    }
    let data = toU32(index, 'index');
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
    const out = _I || hmac(sha512, this._chainCode, data);
    abytes(out, 64);
    const childTweak = out.slice(0, 32);
    const chainCode = out.slice(32);
    const opt: HDKeyOpt = {
      versions: this.versions,
      chainCode,
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      index,
    };
    // Fail early instead of re-trying different index
    if (opt.depth! > MAX_DEPTH) {
      throw new Error('HDKey: depth exceeds the serializable value 255');
    }
    const retry = (): HDKey => {
      // Public derivation cannot cross into the hardened index range.
      const maxIndex = this._privateKey ? 2 ** 32 - 1 : HARDENED_OFFSET - 1;
      if (index >= maxIndex) {
        throw new Error(`HDKey: cannot retry child derivation at index ${index}`);
      }
      return this.deriveChild(index + 1);
    };
    // Decode without reducing: BIP-32 requires a retry when parse256(I_L) >= n.
    const ctweak = Fn.fromBytes(childTweak, true);
    if (!Fn.isValid(ctweak)) return retry();
    // I_L = 0 is valid unless it produces an invalid child below.
    if (this._privateKey) {
      const added = Fn.create(Fn.fromBytes(this._privateKey) + ctweak);
      if (!Fn.isValidNot0(added)) return retry();
      opt.privateKey = Fn.toBytes(added);
    } else {
      const point = Point.fromBytes(this._publicKey);
      const added = ctweak === 0n ? point : point.add(Point.BASE.multiply(ctweak));
      // Cryptographically impossible: HMAC-SHA512 would need to produce the scalar -P.
      if (added.equals(Point.ZERO)) return retry();
      opt.publicKey = added.toBytes(true);
    }
    return new HDKey(opt);
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
  // TODO(v3): Make automatic JSON serialization public-only so JSON.stringify cannot expose xpriv.
  toJSON(): { xpriv: string; xpub: string } {
    return this.toPrivateJSON();
  }
  /**
   * Explicitly exports private key material. Treat the returned value as a secret.
   */
  toPrivateJSON(): { xpriv: string; xpub: string } {
    return {
      xpriv: this.privateExtendedKey,
      xpub: this.publicExtendedKey,
    };
  }

  private serialize(version: number, key: Uint8Array) {
    if (!this._chainCode) {
      throw new Error('No chainCode set');
    }
    abytes(key, 33);
    // version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    return concatBytes(
      toU32(version, 'version'),
      new Uint8Array([this.depth]),
      toU32(this.parentFingerprint, 'parentFingerprint'),
      toU32(this.index, 'index'),
      this._chainCode,
      key
    );
  }
}
