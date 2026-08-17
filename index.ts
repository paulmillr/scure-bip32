/**
 * BIP32 hierarchical deterministic (HD) wallets over secp256k1.
 * @module
 * @example
 * ```js
 * import { HDPrivateKey, HDPublicKey, fromExtendedKey, parsePath } from '@scure/bip32';
 * import { randomBytes } from '@noble/hashes/utils.js';
 *
 * const seed = randomBytes(32);
 * const root = HDPrivateKey.fromMasterSeed(seed);
 * const account = root.derive("m/84'/0'/0'");
 * const xprv = account.toExtended();                 // 'xprv...'
 * const xpub = account.toPublic().toExtended();      // 'xpub...'
 *
 * // watch-only side: relative derivation, no secrets in scope
 * const watch = HDPublicKey.fromExtended(xpub);
 * const receive5 = watch.derive('0/5').publicKey;
 *
 * // unknown string → narrow by type
 * const any = fromExtendedKey(xprv);
 * if (any instanceof HDPrivateKey) any.privateKey;
 *
 * // PSBT-style metadata
 * ({ fingerprint: root.fingerprint, path: parsePath("m/84'/0'/0'/0/5").indexes });
 * ```
 */
/*! scure-bip32 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) */
import { secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import {
  abytes,
  concatBytes,
  createView,
  utf8ToBytes,
  type TArg,
  type TRet,
} from '@noble/hashes/utils.js';
import { createBase58check } from '@scure/base';

const Point = /* @__PURE__ */ (() => secp.Point)();
const Fn = /* @__PURE__ */ (() => Point.Fn)();
const base58check = /* @__PURE__ */ createBase58check(sha256);
const MASTER_SECRET = /* @__PURE__ */ utf8ToBytes('Bitcoin seed');
const _0n = /* @__PURE__ */ BigInt(0);

/** Hardened child index offset from BIP32. */
export const HARDENED_OFFSET: number = 0x80000000;
const MAX_DEPTH = 0xff;
const MAX_INDEX = 0xffffffff;

/** Network-specific BIP32 version bytes. */
export interface Versions {
  /** 4-byte version used when serializing private extended keys. */
  private: number;
  /** 4-byte version used when serializing public extended keys. */
  public: number;
}
/** Bitcoin mainnet version bytes (`xprv` / `xpub`). Default for all (de)serialization. */
export const BITCOIN_VERSIONS: Versions = /* @__PURE__ */ Object.freeze({
  private: 0x0488ade4,
  public: 0x0488b21e,
});

const hash160 = (data: TArg<Uint8Array>) => ripemd160(sha256(data));
const fromU32 = (data: TArg<Uint8Array>) => createView(data).getUint32(0, false);
const toU32 = (n: number, title: string = 'number'): TRet<Uint8Array> => {
  if (typeof n !== 'number')
    throw new TypeError(`"${title}" expected number, got type=${typeof n}`);
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_INDEX)
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

// Paths ------------------------------------------------------------------------------------------

/** Result of {@link parsePath}. */
export interface ParsedPath {
  /** `true` when the path started with `m/` (or was exactly `m`). */
  absolute: boolean;
  /** Child indexes; hardened ones already have {@link HARDENED_OFFSET} added. */
  indexes: number[];
}

/**
 * Parses a BIP32 derivation path. Pure; does no crypto.
 * Hardened segments may use `'` or `h`. An `m/` prefix marks an absolute path.
 * @param path - Derivation path such as `m/44'/0'/0'/0/1` or a relative `0/1`.
 * @returns Whether the path was absolute, plus the child indexes with hardened ones offset.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On malformed segments or out-of-range indexes. {@link Error}
 * @example
 * ```js
 * import { parsePath } from '@scure/bip32';
 * const abs = parsePath("m/44'/0h/1"); // { absolute: true, indexes: [0x8000002c, 0x80000000, 1] }
 * const rel = parsePath('0/5');        // { absolute: false, indexes: [0, 5] }
 * ```
 */
export function parsePath(path: string): ParsedPath {
  if (typeof path !== 'string') throw new TypeError('HDKey: path must be a string');
  if (path === 'm') return { absolute: true, indexes: [] };
  const absolute = path.startsWith('m/');
  return { absolute, indexes: parseSegments(absolute ? path.slice(2) : path) };
}

/** Parses `0/1'/2h` (no `m/` prefix). Throws on any malformed segment. */
function parseSegments(str: string): number[] {
  const indexes: number[] = [];
  for (const seg of str.split('/')) {
    const m = /^(\d+)(['h]?)$/.exec(seg);
    if (!m) throw new Error(`HDKey: invalid path segment "${seg}"`);
    const n = Number(m[1]);
    if (!Number.isSafeInteger(n) || n >= HARDENED_OFFSET)
      throw new Error(`HDKey: path index out of range: ${seg}`);
    indexes.push(m[2] ? n + HARDENED_OFFSET : n);
  }
  return indexes;
}

// Node metadata ----------------------------------------------------------------------------------

/** Position of a key in the tree. All fields default to 0. Depth 0 requires index and parentFingerprint 0. */
export interface NodeMeta {
  /** Levels below the master key, 0..255. */
  depth?: number;
  /** Child index this key was derived at; hardened indexes are `>= HARDENED_OFFSET`. */
  index?: number;
  /** First 4 bytes of the parent's identifier as a big-endian u32. */
  parentFingerprint?: number;
}
type Meta = Readonly<Required<NodeMeta>>;
const ZERO_META: Meta = /* @__PURE__ */ Object.freeze({ depth: 0, index: 0, parentFingerprint: 0 });

function validateMeta(meta: NodeMeta | undefined): Meta {
  if (meta === undefined) return ZERO_META;
  if (typeof meta !== 'object' || meta === null)
    throw new TypeError('HDKey: meta must be an object');
  const depth = meta.depth ?? 0;
  const index = meta.index ?? 0;
  const parentFingerprint = meta.parentFingerprint ?? 0;
  if (typeof depth !== 'number' || !Number.isSafeInteger(depth) || depth < 0 || depth > MAX_DEPTH)
    throw new RangeError('HDKey: depth must be an integer in range 0..255, got ' + depth);
  toU32(index, 'index');
  toU32(parentFingerprint, 'parentFingerprint');
  if (depth === 0 && (index !== 0 || parentFingerprint !== 0))
    throw new Error('HDKey: zero depth with non-zero index/parent fingerprint');
  return { depth, index, parentFingerprint };
}

// 78-byte serialization --------------------------------------------------------------------------

// version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
function ser78(
  version: number,
  meta: Meta,
  chainCode: TArg<Uint8Array>,
  key33: TArg<Uint8Array>
): string {
  return base58check.encode(
    concatBytes(
      toU32(version, 'version'),
      Uint8Array.of(meta.depth),
      toU32(meta.parentFingerprint, 'parentFingerprint'),
      toU32(meta.index, 'index'),
      chainCode,
      key33
    )
  );
}
interface Decoded {
  isPrivate: boolean;
  meta: NodeMeta;
  chainCode: Uint8Array;
  key: Uint8Array;
}
function de78(base58key: string, versions: Versions): TRet<Decoded> {
  versions = validateVersions(versions);
  const buf = base58check.decode(base58key);
  if (buf.length !== 78)
    throw new Error(`HDKey: invalid extended key length: expected 78 bytes, got ${buf.length}`);
  const view = createView(buf);
  const version = view.getUint32(0, false);
  const meta = {
    depth: buf[4],
    parentFingerprint: view.getUint32(5, false),
    index: view.getUint32(9, false),
  };
  const key = buf.slice(45);
  const isPrivate = key[0] === 0;
  if (version !== (isPrivate ? versions.private : versions.public))
    throw new Error('Version mismatch');
  return { isPrivate, meta, chainCode: buf.slice(13, 45), key } as TRet<Decoded>;
}

// CKD --------------------------------------------------------------------------------------------

type Ckd = { key: Uint8Array; chainCode: Uint8Array } | null;

/** CKDpriv given I = HMAC-SHA512 output. `null` means "invalid child, use next index" (BIP32). */
function ckdPriv(parentPriv: TArg<Uint8Array>, I: TArg<Uint8Array>): TRet<Ckd> {
  const priv = abytes(parentPriv, 32);
  const out = abytes(I, 64);
  // Decode without reducing: BIP32 requires a retry when parse256(I_L) >= n.
  const IL = Fn.fromBytes(out.subarray(0, 32), true);
  if (!Fn.isValid(IL)) return null;
  // I_L = 0 is valid unless the resulting child key is 0.
  const k = Fn.create(Fn.fromBytes(priv) + IL);
  if (!Fn.isValidNot0(k)) return null;
  return { key: Fn.toBytes(k), chainCode: out.slice(32) } as TRet<Ckd>;
}

/** CKDpub given I. `null` means "invalid child, use next index". */
function ckdPub(parentPub: TArg<Uint8Array>, I: TArg<Uint8Array>): TRet<Ckd> {
  const pub = abytes(parentPub, 33);
  const out = abytes(I, 64);
  const IL = Fn.fromBytes(out.subarray(0, 32), true);
  if (!Fn.isValid(IL)) return null;
  const P = Point.fromBytes(pub);
  const K = IL === _0n ? P : P.add(Point.BASE.multiply(IL));
  // Cryptographically impossible: HMAC-SHA512 would need to produce the scalar -k_par.
  if (K.equals(Point.ZERO)) return null;
  return { key: K.toBytes(true), chainCode: out.slice(32) } as TRet<Ckd>;
}

const noRetry = (i: number) => new Error(`HDKey: cannot retry child derivation at index ${i}`);
const tooDeep = () => new Error('HDKey: depth exceeds the serializable value 255');

/**
 * Private child derivation with the BIP32-mandated retry (invalid child → next index).
 * `I0`, when given, replaces the HMAC output for the first index only; test seam, see `__TESTS`.
 */
function derivePriv(
  k: TArg<HDPrivateKey>,
  index: number,
  I0?: TArg<Uint8Array>
): TRet<HDPrivateKey> {
  toU32(index, 'index');
  if (k.depth >= MAX_DEPTH) throw tooDeep();
  const priv = k.privateKey;
  const pub = k.publicKey;
  const cc = k.chainCode;
  const meta = { depth: k.depth + 1, parentFingerprint: k.fingerprint };
  for (let i = index; ; i++) {
    // Hardened: 0x00 || ser256(k_par) || ser32(i). Normal: serP(point(k_par)) || ser32(i).
    const data =
      i >= HARDENED_OFFSET
        ? concatBytes(Uint8Array.of(0), priv, toU32(i))
        : concatBytes(pub, toU32(i));
    const I = i === index && I0 ? I0 : hmac(sha512, cc, data);
    const c = ckdPriv(priv, I);
    if (c) return new HDPrivateKey(c.key, c.chainCode, { ...meta, index: i }) as TRet<HDPrivateKey>;
    if (i >= MAX_INDEX) throw noRetry(i);
  }
}

/** Public child derivation with the BIP32-mandated retry; cannot cross into hardened indexes. */
function derivePub(k: TArg<HDPublicKey>, index: number, I0?: TArg<Uint8Array>): TRet<HDPublicKey> {
  toU32(index, 'index');
  if (index >= HARDENED_OFFSET)
    throw new Error('HDKey: cannot derive hardened child from a public key');
  if (k.depth >= MAX_DEPTH) throw tooDeep();
  const pub = k.publicKey;
  const cc = k.chainCode;
  const meta = { depth: k.depth + 1, parentFingerprint: k.fingerprint };
  for (let i = index; ; i++) {
    const I = i === index && I0 ? I0 : hmac(sha512, cc, concatBytes(pub, toU32(i)));
    const c = ckdPub(pub, I);
    if (c) return new HDPublicKey(c.key, c.chainCode, { ...meta, index: i }) as TRet<HDPublicKey>;
    if (i >= HARDENED_OFFSET - 1) throw noRetry(i);
  }
}

/** Shared `derive()` body: absolute string paths only from depth 0; arrays are always relative. */
function derivePath<T extends { readonly depth: number; deriveChild(index: number): T }>(
  node: T,
  path: string | number[]
): T {
  let indexes: number[];
  if (typeof path === 'string') {
    const parsed = parsePath(path);
    if (parsed.absolute && node.depth !== 0)
      throw new Error(
        'HDKey: absolute path (m/...) can only be derived from a master key (depth 0)'
      );
    indexes = parsed.indexes;
  } else if (Array.isArray(path)) {
    for (const i of path) toU32(i, 'index'); // validate everything before deriving anything
    indexes = path;
  } else {
    throw new TypeError('HDKey: path must be a string or an array of indexes');
  }
  let child = node;
  for (const i of indexes) child = child.deriveChild(i);
  return child;
}

// Public API -------------------------------------------------------------------------------------

/**
 * What {@link HDPrivateKey} and {@link HDPublicKey} have in common.
 * Use as a parameter type when either kind of key is acceptable.
 */
export interface HDNode {
  /** Levels below the master key, 0..255. */
  readonly depth: number;
  /** Child index this key was derived at; hardened indexes are `>= HARDENED_OFFSET`. */
  readonly index: number;
  /** First 4 bytes of the parent's identifier as a big-endian u32. */
  readonly parentFingerprint: number;
  /** 33-byte compressed public key. Fresh copy on every access. */
  readonly publicKey: Uint8Array;
  /** 32-byte chain code. Fresh copy on every access. Secret-ish: guard it like the key. */
  readonly chainCode: Uint8Array;
  /** hash160(publicKey), 20 bytes. Fresh copy on every access. */
  readonly identifier: Uint8Array;
  /** First 4 bytes of {@link identifier} as a big-endian u32. */
  readonly fingerprint: number;
  /** One CKD step. Hardened indexes are `>= HARDENED_OFFSET`. */
  deriveChild(index: number): HDNode;
  /** String paths may be absolute (`m/...`, only from depth 0) or relative; arrays are always relative. */
  derive(path: string | number[]): HDNode;
  /**
   * Base58check extended key.
   * @param versions - 4-byte prefixes to use; defaults to Bitcoin mainnet (`xprv` / `xpub`).
   * @returns Base58check string.
   */
  toExtended(versions?: Versions): string;
}

/**
 * BIP32 public node (xpub). Immutable. Can derive non-hardened children only.
 * @param publicKey - SEC1 point, 33 (compressed) or 65 (uncompressed) bytes; stored compressed.
 * @param chainCode - 32 bytes.
 * @param meta - Tree position; defaults to a depth-0 root.
 * @example
 * ```js
 * import { HDPrivateKey, HDPublicKey } from '@scure/bip32';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const xpub = HDPrivateKey.fromMasterSeed(randomBytes(32)).toPublic().toExtended();
 * const watch = HDPublicKey.fromExtended(xpub);
 * const receive5 = watch.derive('0/5').publicKey;
 * ```
 */
export class HDPublicKey implements HDNode {
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  private readonly _pub: Uint8Array;
  private readonly _cc: Uint8Array;
  private _id: Uint8Array | undefined;

  constructor(publicKey: Uint8Array, chainCode: Uint8Array, meta?: NodeMeta) {
    const m = validateMeta(meta);
    abytes(publicKey);
    abytes(chainCode, 32);
    this._pub = Point.fromBytes(publicKey).toBytes(true); // validates on-curve, normalizes, copies
    this._cc = Uint8Array.from(chainCode);
    this.depth = m.depth;
    this.index = m.index;
    this.parentFingerprint = m.parentFingerprint;
  }

  /** Decodes an `xpub`-style key. Throws if the string is a private extended key. */
  static fromExtended(xpub: string, versions: Versions = BITCOIN_VERSIONS): HDPublicKey {
    const d = de78(xpub, versions);
    if (d.isPrivate) throw new Error('HDKey: expected public extended key, got private');
    return new HDPublicKey(d.key, d.chainCode, d.meta);
  }

  get publicKey(): Uint8Array {
    return Uint8Array.from(this._pub);
  }
  get chainCode(): Uint8Array {
    return Uint8Array.from(this._cc);
  }
  get identifier(): Uint8Array {
    return Uint8Array.from(this.id());
  }
  get fingerprint(): number {
    return fromU32(this.id());
  }
  private id(): Uint8Array {
    return (this._id ??= hash160(this._pub));
  }

  /** CKDpub. Throws for hardened indexes (`>= HARDENED_OFFSET`). */
  deriveChild(index: number): HDPublicKey {
    return derivePub(this, index);
  }
  derive(path: string | number[]): HDPublicKey {
    return derivePath<HDPublicKey>(this, path);
  }
  toExtended(versions: Versions = BITCOIN_VERSIONS): string {
    return ser78(validateVersions(versions).public, this, this._cc, this._pub);
  }
  /** `JSON.stringify` yields the xpub string. */
  toJSON(): string {
    return this.toExtended();
  }
}

/**
 * BIP32 private node (xprv). Immutable. Derives hardened and non-hardened children;
 * `toPublic()` gives the matching {@link HDPublicKey}.
 * @param privateKey - 32-byte scalar in `1..n-1`.
 * @param chainCode - 32 bytes.
 * @param meta - Tree position; defaults to a depth-0 root.
 * @example
 * ```js
 * import { HDPrivateKey } from '@scure/bip32';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const root = HDPrivateKey.fromMasterSeed(randomBytes(32));
 * const account = root.derive("m/84'/0'/0'");
 * const xprv = account.toExtended();
 * const xpub = account.toPublic().toExtended();
 * ```
 */
export class HDPrivateKey implements HDNode {
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  private readonly _priv: Uint8Array;
  private readonly _pub: HDPublicKey;

  constructor(privateKey: Uint8Array, chainCode: Uint8Array, meta?: NodeMeta) {
    const m = validateMeta(meta);
    abytes(privateKey, 32);
    abytes(chainCode, 32);
    if (!secp.utils.isValidSecretKey(privateKey)) throw new Error('HDKey: invalid private key');
    this._priv = Uint8Array.from(privateKey); // don't alias caller-owned secret buffers
    this._pub = new HDPublicKey(secp.getPublicKey(this._priv, true), chainCode, m);
    this.depth = m.depth;
    this.index = m.index;
    this.parentFingerprint = m.parentFingerprint;
  }

  /** Master key from a 128..512-bit seed (BIP39 output, or random bytes). */
  static fromMasterSeed(seed: Uint8Array): HDPrivateKey {
    abytes(seed);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new RangeError(
        'HDKey: seed length must be between 128 and 512 bits; 256 bits is advised, got ' +
          seed.length
      );
    }
    const I = hmac(sha512, MASTER_SECRET, seed);
    return new HDPrivateKey(I.slice(0, 32), I.slice(32));
  }

  /** Decodes an `xprv`-style key. Throws if the string is a public extended key. */
  static fromExtended(xprv: string, versions: Versions = BITCOIN_VERSIONS): HDPrivateKey {
    const d = de78(xprv, versions);
    if (!d.isPrivate) throw new Error('HDKey: expected private extended key, got public');
    return new HDPrivateKey(d.key.subarray(1), d.chainCode, d.meta);
  }

  /** 32-byte private key. Fresh copy on every access. */
  get privateKey(): Uint8Array {
    return Uint8Array.from(this._priv);
  }
  get publicKey(): Uint8Array {
    return this._pub.publicKey;
  }
  get chainCode(): Uint8Array {
    return this._pub.chainCode;
  }
  get identifier(): Uint8Array {
    return this._pub.identifier;
  }
  get fingerprint(): number {
    return this._pub.fingerprint;
  }

  /** BIP32 N(): the same node without its private key. */
  toPublic(): HDPublicKey {
    return this._pub;
  }
  /** CKDpriv. Hardened indexes are `>= HARDENED_OFFSET`. */
  deriveChild(index: number): HDPrivateKey {
    return derivePriv(this, index);
  }
  derive(path: string | number[]): HDPrivateKey {
    return derivePath<HDPrivateKey>(this, path);
  }
  toExtended(versions: Versions = BITCOIN_VERSIONS): string {
    const key = concatBytes(Uint8Array.of(0), this._priv);
    return ser78(validateVersions(versions).private, this, this._pub.chainCode, key);
  }
  /** Always throws: private keys never leave via `JSON.stringify`. Use `toExtended()` explicitly. */
  toJSON(): never {
    throw new Error('HDKey: refusing to JSON-serialize a private key; use toExtended() explicitly');
  }
}

/**
 * Decodes either kind of extended key. Narrow with `instanceof HDPrivateKey`.
 * @param key - Base58check `xprv…` / `xpub…` string (or another network's equivalent).
 * @param versions - Expected 4-byte prefixes; defaults to Bitcoin mainnet.
 * @returns {@link HDPrivateKey} for private keys, {@link HDPublicKey} for public ones.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws On bad checksum, length, version, key material or tree metadata. {@link Error}
 * @example
 * ```js
 * import { fromExtendedKey, HDPrivateKey } from '@scure/bip32';
 * const key = fromExtendedKey('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8');
 * const canSign = key instanceof HDPrivateKey;
 * ```
 */
export function fromExtendedKey(
  key: string,
  versions: Versions = BITCOIN_VERSIONS
): TRet<HDPrivateKey | HDPublicKey> {
  const d = de78(key, versions);
  const node = d.isPrivate
    ? new HDPrivateKey(d.key.subarray(1), d.chainCode, d.meta)
    : new HDPublicKey(d.key, d.chainCode, d.meta);
  return node as TRet<HDPrivateKey | HDPublicKey>;
}

// Legacy 2.x API ---------------------------------------------------------------------------------

/**
 * Options for the legacy {@link HDKey} constructor.
 * @deprecated Part of the 2.x API; use the {@link HDPrivateKey} / {@link HDPublicKey} constructors.
 */
export interface HDKeyOpt {
  /** Version bytes stored on the key; default Bitcoin mainnet. */
  versions?: Versions;
  /** Levels below the master key, 0..255. */
  depth?: number;
  /** Child index this key was derived at. */
  index?: number;
  /** First 4 bytes of the parent's identifier as a big-endian u32. */
  parentFingerprint?: number;
  /** 32-byte chain code. Required. */
  chainCode?: Uint8Array;
  /** SEC1 public key; mutually exclusive with `privateKey`. */
  publicKey?: Uint8Array;
  /** 32-byte private key; mutually exclusive with `publicKey`. */
  privateKey?: Uint8Array;
}

/**
 * Legacy 2.x API: one mutable class for both private and public keys.
 * Now a thin adapter over {@link HDPrivateKey} / {@link HDPublicKey}; use `.node` to unwrap.
 * @deprecated Use {@link HDPrivateKey} and {@link HDPublicKey}. Will be removed in the next major.
 * @param opt - Legacy options, see {@link HDKeyOpt}.
 * @param node - Alternatively, a new-API node to wrap.
 * @param versions - Version bytes for the wrapped node; default Bitcoin mainnet.
 * @example
 * ```js
 * import { HDKey } from '@scure/bip32';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const root = HDKey.fromMasterSeed(randomBytes(32));
 * const account0 = root.derive("m/0/1'");
 * const pub = account0.publicKey;
 * ```
 */
export class HDKey {
  static fromMasterSeed(seed: Uint8Array, versions: Versions = BITCOIN_VERSIONS): HDKey {
    return new HDKey(HDPrivateKey.fromMasterSeed(seed), versions);
  }
  static fromExtendedKey(base58key: string, versions: Versions = BITCOIN_VERSIONS): HDKey {
    return new HDKey(fromExtendedKey(base58key, versions), versions);
  }
  static fromJSON(json: { xpriv: string } | { xpub: string }): HDKey {
    return HDKey.fromExtendedKey('xpriv' in json ? json.xpriv : json.xpub);
  }

  readonly versions: Versions;
  readonly depth: number;
  readonly index: number;
  readonly parentFingerprint: number;
  private _node: HDPrivateKey | HDPublicKey;

  /** Legacy form: `new HDKey({ privateKey | publicKey, chainCode, depth?, index?, parentFingerprint?, versions? })`. */
  constructor(opt: HDKeyOpt);
  /** Wraps a new-API node so it can be handed to code still typed on `HDKey`. */
  constructor(node: HDPrivateKey | HDPublicKey, versions?: Versions);
  constructor(a: HDKeyOpt | HDPrivateKey | HDPublicKey, versions: Versions = BITCOIN_VERSIONS) {
    let node: HDPrivateKey | HDPublicKey;
    if (a instanceof HDPrivateKey || a instanceof HDPublicKey) {
      node = a;
    } else {
      if (!a || typeof a !== 'object') {
        throw new Error('HDKey.constructor must not be called directly');
      }
      if (a.publicKey && a.privateKey) {
        throw new Error('HDKey: publicKey and privateKey at same time.');
      }
      if (!a.chainCode) throw new Error('HDKey: chainCode is required');
      versions = a.versions || BITCOIN_VERSIONS;
      const meta = { depth: a.depth, index: a.index, parentFingerprint: a.parentFingerprint };
      if (a.privateKey) node = new HDPrivateKey(a.privateKey, a.chainCode, meta);
      else if (a.publicKey) node = new HDPublicKey(a.publicKey, a.chainCode, meta);
      else throw new Error('HDKey: no public or private key provided');
    }
    this.versions = validateVersions(versions);
    this._node = node;
    this.depth = node.depth;
    this.index = node.index;
    this.parentFingerprint = node.parentFingerprint;
  }

  /** The underlying new-API node. `HDPublicKey` after `wipePrivateData()`. */
  get node(): HDPrivateKey | HDPublicKey {
    return this._node;
  }
  private pub(): HDPublicKey {
    return this._node instanceof HDPrivateKey ? this._node.toPublic() : this._node;
  }
  private wrap(node: HDPrivateKey | HDPublicKey): HDKey {
    return new HDKey(node, this.versions);
  }

  get fingerprint(): number {
    return this._node.fingerprint;
  }
  get identifier(): Uint8Array {
    return this._node.identifier;
  }
  get pubKeyHash(): Uint8Array {
    return this._node.identifier;
  }
  get privateKey(): Uint8Array | null {
    return this._node instanceof HDPrivateKey ? this._node.privateKey : null;
  }
  get publicKey(): Uint8Array {
    return this._node.publicKey;
  }
  get chainCode(): Uint8Array {
    return this._node.chainCode;
  }
  get privateExtendedKey(): string {
    if (!(this._node instanceof HDPrivateKey)) throw new Error('No private key');
    return this._node.toExtended(this.versions);
  }
  get publicExtendedKey(): string {
    return this.pub().toExtended(this.versions);
  }

  /** 2.x semantics: `m`/`M` means "this node", so the path is relative to the receiver. */
  derive(path: string): HDKey {
    if (!/^[mM]'?/.test(path)) throw new Error('Path must start with "m" or "M"');
    if (/^[mM]'?$/.test(path)) return this;
    return this.wrap(this._node.derive(parseSegments(path.replace(/^[mM]'?\//, ''))));
  }
  deriveChild(index: number): HDKey {
    return this.wrap(this._node.deriveChild(index));
  }

  sign(hash: Uint8Array): Uint8Array {
    if (!(this._node instanceof HDPrivateKey)) throw new Error('No privateKey set!');
    abytes(hash, 32);
    return secp.sign(hash, this._node.privateKey, { prehash: false });
  }
  verify(hash: Uint8Array, signature: Uint8Array): boolean {
    abytes(hash, 32);
    abytes(signature, 64);
    return secp.verify(signature, hash, this._node.publicKey, { prehash: false });
  }

  /** Drops the private half. Nodes are immutable, so this swaps in the public node; no buffers are zeroed. */
  wipePrivateData(): this {
    this._node = this.pub();
    return this;
  }
  // TODO(v3): public-only; kept private for 2.x compatibility. HDPrivateKey.toJSON() already throws.
  toJSON(): { xpriv: string; xpub: string } {
    return this.toPrivateJSON();
  }
  /** Explicitly exports private key material. Treat the returned value as a secret. */
  toPrivateJSON(): { xpriv: string; xpub: string } {
    return { xpriv: this.privateExtendedKey, xpub: this.publicExtendedKey };
  }
}

// Test seam --------------------------------------------------------------------------------------

/** Runs child derivation with a caller-supplied `I` for the first index (retries use real HMAC). */
function deriveChildWithI<T extends HDPrivateKey | HDPublicKey | HDKey>(
  key: T,
  index: number,
  I: TArg<Uint8Array>
): TRet<T> {
  abytes(I, 64);
  // Bytes wrappers widen the seam; the loop needs concrete inputs.
  if (key instanceof HDKey)
    return new HDKey(deriveChildWithI(key.node, index, I), key.versions) as TRet<T>;
  if (key instanceof HDPrivateKey) return derivePriv(key, index, I) as TRet<T>;
  return derivePub(key as HDPublicKey, index, I) as TRet<T>;
}

type Tests = Readonly<{
  deriveChildWithI: typeof deriveChildWithI;
}>;

/** Internal test hooks. Not part of the public API. */
export const __TESTS: Tests = /* @__PURE__ */ Object.freeze({ deriveChildWithI });
