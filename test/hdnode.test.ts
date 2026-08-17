import { secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { hexToBytes, bytesToHex as toHex } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import {
  __TESTS,
  BITCOIN_VERSIONS,
  fromExtendedKey,
  HARDENED_OFFSET,
  HDKey,
  HDPrivateKey,
  HDPublicKey,
  parsePath,
  type HDNode,
} from '../index.ts';
import { deepStrictEqual, throws } from './assert.ts';
import VECTORS from './vectors/bip32.json' with { type: 'json' };

const TESTNET = { private: 0x04358394, public: 0x043587cf };
const H = HARDENED_OFFSET;
const seed1 = hexToBytes(VECTORS.valid[0].seed);
const eq = deepStrictEqual;
const isHardened = (i: number) => i >= H;

describe('hdnode (v3 API)', () => {
  describe('BIP-32 spec vectors', () => {
    for (const v of VECTORS.valid) {
      it(`TV${v.vector} ${v.path}`, () => {
        const root = HDPrivateKey.fromMasterSeed(hexToBytes(v.seed));
        const key = root.derive(v.path);
        eq(key.toExtended(), v.xprv);
        eq(key.toPublic().toExtended(), v.xpub);
        eq(JSON.stringify(key.toPublic()), JSON.stringify(v.xpub));

        // typed decoders round-trip and reject the other kind
        const priv = HDPrivateKey.fromExtended(v.xprv);
        eq(priv.toExtended(), v.xprv);
        eq(priv.toPublic().toExtended(), v.xpub);
        eq(priv.depth, key.depth);
        eq(priv.index, key.index);
        eq(priv.parentFingerprint, key.parentFingerprint);
        eq(priv.fingerprint, key.fingerprint);
        eq(HDPublicKey.fromExtended(v.xpub).toExtended(), v.xpub);
        throws(() => HDPrivateKey.fromExtended(v.xpub));
        throws(() => HDPublicKey.fromExtended(v.xprv));

        // untyped decoder narrows by kind
        const a = fromExtendedKey(v.xprv);
        const b = fromExtendedKey(v.xpub);
        eq(a instanceof HDPrivateKey, true);
        eq(b instanceof HDPublicKey, true);
        eq(a.toExtended(), v.xprv);
        eq(b.toExtended(), v.xpub);

        // array form == string form; relative derivation from every prefix matches
        const { indexes } = parsePath(v.path);
        eq(root.derive(indexes).toExtended(), v.xprv);
        for (let cut = 0; cut <= indexes.length; cut++) {
          const head = root.derive(indexes.slice(0, cut));
          const tail = indexes.slice(cut);
          eq(head.derive(tail).toExtended(), v.xprv);
          if (!tail.some(isHardened)) {
            eq(head.toPublic().derive(tail).toExtended(), v.xpub);
          } else {
            throws(() => head.toPublic().derive(tail));
          }
        }
      });
    }
    it('TV5: invalid extended keys are rejected by every decoder', () => {
      for (const { key, reason } of VECTORS.invalid) {
        throws(() => fromExtendedKey(key), reason);
        throws(() => HDPrivateKey.fromExtended(key), reason);
        throws(() => HDPublicKey.fromExtended(key), reason);
      }
    });
  });

  describe('parsePath', () => {
    it('parses absolute and relative paths, both hardened markers', () => {
      eq(parsePath('m'), { absolute: true, indexes: [] });
      eq(parsePath("m/44'/0h/1"), { absolute: true, indexes: [44 + H, H, 1] });
      eq(parsePath('0/5'), { absolute: false, indexes: [0, 5] });
      eq(parsePath("2147483647'"), { absolute: false, indexes: [2147483647 + H] });
      eq(parsePath('007'), { absolute: false, indexes: [7] });
    });
    it('rejects malformed paths', () => {
      const bad = [
        '',
        'm/',
        'M',
        'M/0',
        "m'",
        'm/m/0',
        'm/0/ 1 /2',
        'm/0/1.5/2',
        'm/0/331e100/2',
        'm/0/3e/2',
        "m/0/'/2",
        'm/2147483648',
        "m/0''",
        'm/0hh',
        'm//0',
        '/0',
        'x/0',
        'm/-1',
      ];
      for (const p of bad) throws(() => parsePath(p), p);
      throws(() => parsePath(0 as any));
      throws(() => parsePath(['0'] as any));
    });
  });

  describe('derive()', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('absolute paths only from depth 0; relative from anywhere', () => {
      const acct = root.derive("m/0'/1");
      throws(() => acct.derive('m/2'));
      throws(() => acct.derive('m'));
      eq(acct.derive("2'/2").toExtended(), root.derive("m/0'/1/2'/2").toExtended());
      eq(acct.derive([2 + H, 2]).toExtended(), root.derive("m/0'/1/2'/2").toExtended());
      eq(
        acct.toPublic().derive('2/3').toExtended(),
        root.derive("m/0'/1/2/3").toPublic().toExtended()
      );
    });
    it('empty derivation returns the same immutable instance', () => {
      eq(root.derive('m') === root, true);
      eq(root.derive([]) === root, true);
      const pub = root.toPublic();
      eq(pub.derive([]) === pub, true);
    });
    it('validates every index before deriving anything', () => {
      throws(() => root.derive([0, -1]));
      throws(() => root.derive([0, 1.5]));
      throws(() => root.derive([0, 2 ** 32]));
      throws(() => root.derive(['0'] as any));
      throws(() => root.derive(0 as any));
    });
    it('public keys cannot derive hardened children', () => {
      const pub = root.toPublic();
      throws(() => pub.derive("0'"));
      throws(() => pub.derive([H]));
      throws(() => pub.deriveChild(H));
      throws(() => pub.deriveChild(2 ** 32 - 1));
      eq(pub.deriveChild(H - 1).index, H - 1);
    });
    it('deriveChild validates its index', () => {
      let err: unknown;
      try {
        root.deriveChild(1.5);
      } catch (e) {
        err = e;
      }
      eq(err instanceof RangeError, true);
      try {
        root.deriveChild('1' as any);
      } catch (e) {
        err = e;
      }
      eq(err instanceof TypeError, true);
      throws(() => root.deriveChild(-1));
      throws(() => root.deriveChild(2 ** 32));
    });
    it('children carry parent fingerprint, depth+1 and index', () => {
      const child = root.deriveChild(7 + H);
      eq(child.depth, 1);
      eq(child.index, 7 + H);
      eq(child.parentFingerprint, root.fingerprint);
      const grandchild = child.toPublic().deriveChild(3);
      eq(grandchild.depth, 2);
      eq(grandchild.index, 3);
      eq(grandchild.parentFingerprint, child.fingerprint);
    });
  });

  describe('versions', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('are only a serialization concern', () => {
      const tprv = root.toExtended(TESTNET);
      const tpub = root.toPublic().toExtended(TESTNET);
      eq(tprv.startsWith('tprv'), true);
      eq(tpub.startsWith('tpub'), true);
      eq(HDPrivateKey.fromExtended(tprv, TESTNET).toExtended(TESTNET), tprv);
      eq(HDPublicKey.fromExtended(tpub, TESTNET).toExtended(TESTNET), tpub);
      eq(HDPrivateKey.fromExtended(tprv, TESTNET).toExtended(), root.toExtended());
      // wrong network throws instead of silently decoding
      throws(() => HDPrivateKey.fromExtended(tprv));
      throws(() => fromExtendedKey(tpub));
      throws(() => fromExtendedKey(root.toExtended(), TESTNET));
    });
    it('are validated', () => {
      for (const bad of [
        null,
        1,
        {},
        { private: 1 },
        { private: -1, public: 1 },
        { private: 1, public: 2 ** 32 },
      ]) {
        throws(() => root.toExtended(bad as any), String(bad));
        throws(() => HDPrivateKey.fromExtended(root.toExtended(), bad as any));
      }
      eq(Object.isFrozen(BITCOIN_VERSIONS), true);
    });
  });

  describe('JSON', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('public keys stringify to their xpub; private keys refuse', () => {
      eq(JSON.stringify(root.toPublic()), JSON.stringify(root.toPublic().toExtended()));
      eq(JSON.stringify({ k: root.toPublic() }), `{"k":"${root.toPublic().toExtended()}"}`);
      throws(() => JSON.stringify(root));
      throws(() => JSON.stringify({ wallet: root }));
      throws(() => JSON.stringify([root]));
      throws(() => root.toJSON());
    });
  });

  describe('constructors', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    const priv = root.privateKey;
    const pub = root.publicKey;
    const cc = root.chainCode;
    it('accept raw material and default to a depth-0 root', () => {
      const k = new HDPrivateKey(priv, cc);
      eq(k.toExtended(), root.toExtended());
      eq([k.depth, k.index, k.parentFingerprint], [0, 0, 0]);
      const p = new HDPublicKey(pub, cc);
      eq(p.toExtended(), root.toPublic().toExtended());
      const child = root.derive("m/1'/2");
      const rebuilt = new HDPublicKey(child.publicKey, child.chainCode, {
        depth: child.depth,
        index: child.index,
        parentFingerprint: child.parentFingerprint,
      });
      eq(rebuilt.toExtended(), child.toPublic().toExtended());
    });
    it('normalize uncompressed public keys', () => {
      const uncompressed = secp.getPublicKey(priv, false);
      eq(uncompressed.length, 65);
      const p = new HDPublicKey(uncompressed, cc);
      eq(p.publicKey.length, 33);
      eq(toHex(p.publicKey), toHex(pub));
    });
    it('reject invalid key material', () => {
      throws(() => new HDPrivateKey(new Uint8Array(32), cc)); // 0
      throws(() => new HDPrivateKey(secp.Point.Fn.toBytes(secp.Point.CURVE().n), cc)); // n
      throws(() => new HDPrivateKey(priv.slice(1), cc));
      throws(() => new HDPrivateKey(toHex(priv) as any, cc));
      throws(() => new HDPublicKey(new Uint8Array(33), cc));
      throws(() => new HDPublicKey(pub.slice(1), cc));
      throws(() => new HDPublicKey(pub, cc.slice(1)));
      throws(() => new HDPublicKey(pub, new Uint8Array(33)));
      throws(() => new HDPrivateKey(priv, new Uint8Array(31)));
      throws(() => new HDPublicKey(('02' + toHex(pub)) as any, cc));
    });
    it('reject invalid meta', () => {
      const ok = { depth: 3, index: 5, parentFingerprint: 0xdeadbeef };
      new HDPrivateKey(priv, cc, ok);
      new HDPublicKey(pub, cc, { depth: 255, index: 2 ** 32 - 1, parentFingerprint: 2 ** 32 - 1 });
      for (const bad of [
        { depth: 256 },
        { depth: -1 },
        { depth: 1.5 },
        { depth: '1' },
        { depth: NaN },
        { index: 1 },
        { parentFingerprint: 1 }, // depth 0 must have zero index/fingerprint
        { depth: 1, index: -1 },
        { depth: 1, index: 2 ** 32 },
        { depth: 1, index: 1.5 },
        { depth: 1, parentFingerprint: -1 },
        { depth: 1, parentFingerprint: '0' },
        null,
        1,
        'x',
      ]) {
        throws(() => new HDPrivateKey(priv, cc, bad as any), JSON.stringify(bad));
        throws(() => new HDPublicKey(pub, cc, bad as any), JSON.stringify(bad));
      }
    });
    it('fromMasterSeed validates seed length', () => {
      let err: unknown;
      try {
        HDPrivateKey.fromMasterSeed(new Uint8Array(15));
      } catch (e) {
        err = e;
      }
      eq(err instanceof RangeError, true);
      throws(() => HDPrivateKey.fromMasterSeed(new Uint8Array(65)));
      throws(() => HDPrivateKey.fromMasterSeed('00'.repeat(32) as any));
      HDPrivateKey.fromMasterSeed(new Uint8Array(16));
      HDPrivateKey.fromMasterSeed(new Uint8Array(64));
    });
    it('do not alias caller buffers', () => {
      const p = Uint8Array.from(priv);
      const c = Uint8Array.from(cc);
      const k = new HDPrivateKey(p, c);
      p.fill(0);
      c.fill(0);
      eq(k.toExtended(), root.toExtended());
    });
  });

  describe('immutability', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('byte getters return fresh copies', () => {
      const before = root.toExtended();
      for (const k of [root, root.toPublic()] as HDNode[]) {
        for (const name of ['publicKey', 'chainCode', 'identifier'] as const) {
          const a = k[name];
          const b = k[name];
          eq(a === b, false);
          eq(a, b);
          a.fill(0);
          eq(k[name], b);
        }
      }
      root.privateKey.fill(0);
      eq(root.toExtended(), before);
      eq(root.derive("m/0'").toExtended(), VECTORS.valid[1].xprv);
    });
    it('toPublic() is the same instance every time and shares nothing mutable', () => {
      const p1 = root.toPublic();
      const p2 = root.toPublic();
      eq(p1 === p2, true);
      eq(p1 instanceof HDPublicKey, true);
      eq('privateKey' in p1, false);
      eq(p1.fingerprint, root.fingerprint);
      eq(p1.identifier, root.identifier);
      eq(p1.chainCode, root.chainCode);
      eq(p1.publicKey, root.publicKey);
    });
    it('identifier / fingerprint are consistent with BIP-32', () => {
      // m/0/2147483647'/1/2147483646'/2 from TV2
      const key = HDPrivateKey.fromExtended(VECTORS.valid[11].xprv);
      eq(key.depth, 5);
      eq(key.parentFingerprint, 0x31a507b8);
      eq(key.index, 2);
      eq(toHex(key.chainCode), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
      eq(
        toHex(key.publicKey),
        '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'
      );
      eq(toHex(key.identifier), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220');
      eq(key.fingerprint, 0x26132fdb);
      eq(key.toPublic().fingerprint, 0x26132fdb);
    });
  });

  describe('child derivation retry (BIP-32 invalid child → next index)', () => {
    const invalidTweak = hexToBytes(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    ); // == n
    const withTweak = (tweak: Uint8Array): Uint8Array => {
      const I = new Uint8Array(64);
      I.set(tweak);
      return I;
    };
    const parent = HDPrivateKey.fromMasterSeed(seed1);
    const publicParent = parent.toPublic();
    const negativeParent = secp.Point.Fn.toBytes(
      secp.Point.Fn.neg(secp.Point.Fn.fromBytes(parent.privateKey))
    );

    it('I_L = 0 yields a valid child equal to the parent key', () => {
      const child = __TESTS.deriveChildWithI(parent, 0, new Uint8Array(64));
      const publicChild = __TESTS.deriveChildWithI(publicParent, 0, new Uint8Array(64));
      eq(child instanceof HDPrivateKey, true);
      eq(publicChild instanceof HDPublicKey, true);
      eq(child.privateKey, parent.privateKey);
      eq(child.chainCode, new Uint8Array(32));
      eq(child.index, 0);
      eq(child.depth, 1);
      eq(publicChild.publicKey, publicParent.publicKey);
      eq(publicChild.chainCode, new Uint8Array(32));
    });
    it('I_L >= n and k_i = 0 / K_i = ∞ retry at index + 1 with real HMAC', () => {
      for (const key of [parent, publicParent]) {
        const expected = key.deriveChild(1);
        for (const I of [withTweak(invalidTweak), withTweak(negativeParent)]) {
          const got = __TESTS.deriveChildWithI(key, 0, I);
          eq(got.index, 1);
          eq(got.toExtended(), expected.toExtended());
        }
      }
    });
    it('retry stops at the last valid private / public index', () => {
      throws(() => __TESTS.deriveChildWithI(parent, 2 ** 32 - 1, withTweak(invalidTweak)));
      throws(() => __TESTS.deriveChildWithI(publicParent, H - 1, withTweak(invalidTweak)));
      // private retry may cross into the hardened range
      const crossed = __TESTS.deriveChildWithI(parent, H - 1, withTweak(invalidTweak));
      eq(crossed.index, H);
      eq(crossed.toExtended(), parent.deriveChild(H).toExtended());
    });
    it('rejects malformed I', () => {
      throws(() => __TESTS.deriveChildWithI(parent, 0, new Uint8Array(63)));
    });
  });

  describe('depth limits', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('255 levels below the master are serializable, 256 are not', () => {
      let k: HDPrivateKey = root;
      for (let i = 0; i < 255; i++) k = k.deriveChild(0);
      eq(k.depth, 255);
      throws(() => k.deriveChild(0));
      throws(() => k.toPublic().deriveChild(0));
      eq(HDPrivateKey.fromExtended(k.toExtended()).depth, 255);
      throws(() => root.derive('0/'.repeat(255) + '0'));
      eq(root.derive('0/'.repeat(254) + '0').depth, 255);
    });
    it('cannot construct beyond depth 255', () => {
      const meta = { depth: 255, index: 0, parentFingerprint: root.fingerprint };
      const k = new HDPrivateKey(root.privateKey, root.chainCode, meta);
      throws(() => k.deriveChild(0));
      throws(() => new HDPrivateKey(root.privateKey, root.chainCode, { ...meta, depth: 256 }));
      const k254 = new HDPublicKey(root.publicKey, root.chainCode, { ...meta, depth: 254 });
      eq(k254.deriveChild(0).depth, 255);
      throws(() => k254.deriveChild(0).deriveChild(0));
    });
  });

  describe('HDNode', () => {
    it('is satisfied by both kinds', () => {
      const root = HDPrivateKey.fromMasterSeed(seed1);
      const address = (k: HDNode) => toHex(k.derive('0/1').publicKey);
      eq(address(root), address(root.toPublic()));
      const nodes: HDNode[] = [root, root.toPublic(), fromExtendedKey(root.toExtended())];
      eq(
        nodes.map((n) => n.toExtended().slice(0, 4)),
        ['xprv', 'xpub', 'xprv']
      );
    });
    it('privateKey / publicKey bytes work with noble directly', () => {
      const key = HDPrivateKey.fromMasterSeed(seed1).derive("m/0'/1");
      const msg = new Uint8Array(32).fill(8);
      const sig = secp.sign(msg, key.privateKey, { prehash: false });
      eq(secp.verify(sig, msg, key.publicKey, { prehash: false }), true);
      eq(secp.verify(sig, msg, key.toPublic().publicKey, { prehash: false }), true);
    });
  });

  describe('legacy HDKey adapter', () => {
    const root = HDPrivateKey.fromMasterSeed(seed1);
    it('wraps and unwraps nodes', () => {
      const legacy = HDKey.fromMasterSeed(seed1);
      eq(legacy.node instanceof HDPrivateKey, true);
      eq(legacy.node.toExtended(), root.toExtended());
      eq(legacy.privateExtendedKey, root.toExtended());
      const wrapped = new HDKey(root.derive("m/0'"), TESTNET);
      eq(wrapped.versions, TESTNET);
      eq(wrapped.depth, 1);
      eq(wrapped.index, H);
      eq(wrapped.privateExtendedKey, root.derive("m/0'").toExtended(TESTNET));
      eq(wrapped.publicExtendedKey, root.derive("m/0'").toPublic().toExtended(TESTNET));
      const pubWrapped = new HDKey(root.toPublic());
      eq(pubWrapped.privateKey, null);
      eq(pubWrapped.publicExtendedKey, root.toPublic().toExtended());
      throws(() => pubWrapped.privateExtendedKey);
    });
    it('keeps 2.x path semantics: m is the receiver, so paths are relative', () => {
      const legacy = HDKey.fromMasterSeed(seed1);
      const acct = legacy.derive("m/0'");
      eq(acct.derive('m/1').publicExtendedKey, root.derive("m/0'/1").toPublic().toExtended());
      eq(acct.derive("M/1/2'").privateExtendedKey, root.derive("m/0'/1/2'").toExtended());
      eq(acct.derive('m') === acct, true);
      throws(() => acct.derive('0/1'));
      // shares the v3 parser, so the `h` marker now works here too (2.x accepted only `'`)
      eq(acct.derive('m/0h').privateExtendedKey, root.derive("m/0'/0'").toExtended());
    });
    it('wipePrivateData swaps in the public node', () => {
      const legacy = HDKey.fromMasterSeed(seed1);
      const child = legacy.derive("m/0'");
      legacy.wipePrivateData();
      eq(legacy.node instanceof HDPublicKey, true);
      eq(
        legacy.node === root.toPublic() ||
          legacy.node.toExtended() === root.toPublic().toExtended(),
        true
      );
      eq(child.privateKey !== null, true); // children were derived before the wipe and are independent
      throws(() => legacy.derive("m/1'"));
    });
    it('requires a chain code (2.x accepted key-only nodes)', () => {
      throws(() => new HDKey({ privateKey: root.privateKey }));
      throws(() => new HDKey({ publicKey: root.publicKey }));
    });
  });
});

it.runWhen(import.meta.url);
