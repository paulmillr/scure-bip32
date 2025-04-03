import { secp256k1 as secp } from '@noble/curves/secp256k1';
import { HARDENED_OFFSET, HDKey } from '../lib/esm/index.js';
import { hexToBytes, bytesToHex as toHex } from '@noble/hashes/utils';
import { deepStrictEqual, throws } from './assert.js';
import { it, describe } from 'micro-should';
// https://github.com/cryptocoinjs/hdkey/blob/42637e381bdef0c8f785b14f5b66a80dad969514/test/fixtures/hdkey.json
const fixtures = [
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: 'm',
        public: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
        private: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    },
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: "m/0'",
        public: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
        private: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
    },
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: "m/0'/1",
        public: 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
        private: 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
    },
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: "m/0'/1/2'",
        public: 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
        private: 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
    },
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: "m/0'/1/2'/2",
        public: 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
        private: 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
    },
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: "m/0'/1/2'/2/1000000000",
        public: 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
        private: 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: 'm',
        public: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
        private: 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: 'm/0',
        public: 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
        private: 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: "m/0/2147483647'",
        public: 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
        private: 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: "m/0/2147483647'/1",
        public: 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
        private: 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: "m/0/2147483647'/1/2147483646'",
        public: 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
        private: 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
    },
    {
        seed: 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
        path: "m/0/2147483647'/1/2147483646'/2",
        public: 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
        private: 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
    },
];
describe('hdkey', () => {
    it('Should throw an error when constructing a key of excesive depth', () => {
      const seed = '000102030405060708090a0b0c0d0e0f';
      var hdkey = HDKey.fromMasterSeed(hexToBytes(seed));

      const optMaxDepth = {
        versions: hdkey.versions,
        chainCode: hdkey.chainCode,
        // The depth is the maximum 255
        depth: 255,
        parentFingerprint: hdkey.fingerprint,
        index: 0,
        privateKey: hdkey.privateKey,
      };
      // no errors
      new HDKey(optMaxDepth);

      // Craft whatever key, but with excesive depth
      const optTooDeep = {
        versions: hdkey.versions,
        chainCode: hdkey.chainCode,
        // The depth is exceeding 255
        depth: 256,
        parentFingerprint: hdkey.fingerprint,
        index: 0,
        privateKey: hdkey.privateKey,
      };
      throws(() => new HDKey(optTooDeep));
    });
    it('Should throw an error when deriving keys of 256 depth', () => {
      const seed = '000102030405060708090a0b0c0d0e0f';
      var hdkey = HDKey.fromMasterSeed(hexToBytes(seed));

      // deriving 255 children should work
      for (let i = 0; i < 255; i++) {
          hdkey = hdkey.deriveChild(0);
      }
      // deriving one more shall throw an error
      throws(() => hdkey.deriveChild(0));
    });
    it('Should throw an error when deriving from path of length 256', () => {
      const seed = '000102030405060708090a0b0c0d0e0f';
      var hdkey = HDKey.fromMasterSeed(hexToBytes(seed));

      // master key "lives" at 0th level, together with 255
      // more level its 256, which is still serializable
      hdkey.derive('m' + '/0'.repeat(255));
      // but deriving one level deeper fails.
      throws(() => hdkey.derive('m' + '/0'.repeat(256)));
    });

    it('Should derive private key correctly', () => {
        const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
        const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
        const childkey = hdkey.derive("m/0/2147483647'/1");
        deepStrictEqual(childkey.privateExtendedKey, 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef');
        // Should throw on 2**32 childs
        throws(() => hdkey.deriveChild(2 ** 32));
    });
    it('Should derive public key correctly', () => {
        const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
        const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
        const expected = hdkey.derive("m/0/2147483647'/1");
        const parentkey = hdkey.derive("m/0/2147483647'");
        parentkey.wipePrivateData();
        const childkey = parentkey.derive('m/1');
        deepStrictEqual(childkey.publicExtendedKey, expected.publicExtendedKey);
    });
    // Ported from https://github.com/cryptocoinjs/hdkey/blob/42637e381bdef0c8f785b14f5b66a80dad969514/test/hdkey.test.js
    describe('+ fromMasterSeed', () => {
        for (const f of fixtures) {
            it('should properly derive the chain path: ' + f.path, () => {
                const hdkey = HDKey.fromMasterSeed(hexToBytes(f.seed));
                const childkey = hdkey.derive(f.path);
                deepStrictEqual(childkey.privateExtendedKey, f.private);
                deepStrictEqual(childkey.publicExtendedKey, f.public);
            });
            describe('> ' + f.path + ' toJSON() / fromJSON()', () => {
                it('should return an object read for JSON serialization', () => {
                    const hdkey = HDKey.fromMasterSeed(hexToBytes(f.seed));
                    const childkey = hdkey.derive(f.path);
                    const obj = {
                        xpriv: f.private,
                        xpub: f.public,
                    };
                    deepStrictEqual(childkey.toJSON(), obj);
                    const newKey = HDKey.fromJSON(obj);
                    deepStrictEqual(newKey.privateExtendedKey, f.private);
                    deepStrictEqual(newKey.publicExtendedKey, f.public);
                });
            });
        }
    });
    describe('- privateKey', () => {
        it('should throw an error if incorrect key size', () => {
            const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
            const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
            // const hdkey = new HDKey.HDKey();
            throws(() => {
                // @ts-ignore
                hdkey.privateKey = new Uint8Array([1, 2, 3, 4]);
            });
        });
    });
    describe('- publicKey', () => {
        it('should throw an error if incorrect key size', () => {
            throws(() => {
                const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
                const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
                // @ts-ignore
                hdkey.publicKey = new Uint8Array([1, 2, 3, 4]);
            });
        });
        it('should not throw if key is 33 bytes (compressed)', () => {
            const pub = secp.getPublicKey(secp.utils.randomPrivateKey(), true);
            deepStrictEqual(pub.length, 33);
            const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
            const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
            throws(() => {
                // @ts-ignore
                hdkey.publicKey = pub;
            });
        });
        it('should not throw if key is 65 bytes (not compressed)', () => {
            const pub = secp.getPublicKey(secp.utils.randomPrivateKey(), false);
            deepStrictEqual(pub.length, 65);
            const seed = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
            const hdkey = HDKey.fromMasterSeed(hexToBytes(seed));
            throws(() => {
                // @ts-ignore
                hdkey.publicKey = pub;
            });
        });
    });
    describe('+ fromExtendedKey()', () => {
        describe('> when private', () => {
            it('should parse it', () => {
                // m/0/2147483647'/1/2147483646'/2
                const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
                const hdkey = HDKey.fromExtendedKey(key);
                deepStrictEqual(hdkey.versions.private, 0x0488ade4);
                deepStrictEqual(hdkey.versions.public, 0x0488b21e);
                deepStrictEqual(hdkey.depth, 5);
                deepStrictEqual(hdkey.parentFingerprint, 0x31a507b8);
                deepStrictEqual(hdkey.index, 2);
                deepStrictEqual(toHex(hdkey.chainCode), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
                deepStrictEqual(toHex(hdkey.privateKey), 'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23');
                deepStrictEqual(toHex(hdkey.publicKey), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c');
                deepStrictEqual(toHex(hdkey.identifier), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220');
            });
        });
        describe('> when public', () => {
            it('should parse it', () => {
                // m/0/2147483647'/1/2147483646'/2
                const key = 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt';
                const hdkey = HDKey.fromExtendedKey(key);
                deepStrictEqual(hdkey.versions.private, 0x0488ade4);
                deepStrictEqual(hdkey.versions.public, 0x0488b21e);
                deepStrictEqual(hdkey.depth, 5);
                deepStrictEqual(hdkey.parentFingerprint, 0x31a507b8);
                deepStrictEqual(hdkey.index, 2);
                deepStrictEqual(toHex(hdkey.chainCode), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
                deepStrictEqual(hdkey.privateKey, null);
                deepStrictEqual(toHex(hdkey.publicKey), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c');
                deepStrictEqual(toHex(hdkey.identifier), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220');
            });
        });
    });
    describe('> when signing', () => {
        it('should work', () => {
            const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
            const hdkey = HDKey.fromExtendedKey(key);
            const ma = new Uint8Array(32);
            const mb = new Uint8Array(32).fill(8);
            const a = hdkey.sign(ma);
            const b = hdkey.sign(mb);
            deepStrictEqual(toHex(a), '6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06');
            deepStrictEqual(toHex(b), 'dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381');
            // TODO: noble-secp256k1 incompat
            // assert.equal(hdkey.verify(ma, a), true);
            deepStrictEqual(hdkey.verify(mb, b), true);
            deepStrictEqual(hdkey.verify(new Uint8Array(32), new Uint8Array(64)), false);
            deepStrictEqual(hdkey.verify(ma, b), false);
            deepStrictEqual(hdkey.verify(mb, a), false);
            throws(() => hdkey.verify(new Uint8Array(99), a));
            throws(() => hdkey.verify(ma, new Uint8Array(99)));
        });
    });
    describe('> when deriving public key', () => {
        it('should work', () => {
            const key = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
            const hdkey = HDKey.fromExtendedKey(key);
            const path = 'm/3353535/2223/0/99424/4/33';
            const derivedHDKey = hdkey.derive(path);
            const expected = 'xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1';
            deepStrictEqual(derivedHDKey.publicExtendedKey, expected);
        });
    });
    describe('> when private key integer is less than 32 bytes', () => {
        it('should work', () => {
            const seed = '000102030405060708090a0b0c0d0e0f';
            const masterKey = HDKey.fromMasterSeed(hexToBytes(seed));
            const newKey = masterKey.derive("m/44'/6'/4'");
            const expected = 'xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx';
            deepStrictEqual(newKey.privateExtendedKey, expected);
        });
    });
    describe('HARDENED_OFFSET', () => {
        it('should be set', () => {
            deepStrictEqual(!!HARDENED_OFFSET, true);
        });
    });
    describe('> when private key has leading zeros', () => {
        it('will include leading zeros when hashing to derive child', () => {
            const key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr';
            const hdkey = HDKey.fromExtendedKey(key);
            deepStrictEqual(toHex(hdkey.privateKey), '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd');
            const derived = hdkey.derive("m/44'/0'/0'/0/0'");
            deepStrictEqual(toHex(derived.privateKey), '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb');
        });
    });
    describe('> when private key is null', () => {
        it('privateExtendedKey should return null and not throw', () => {
            const seed = '000102030405060708090a0b0c0d0e0f';
            const masterKey = HDKey.fromMasterSeed(hexToBytes(seed));
            deepStrictEqual(!!masterKey.privateExtendedKey, true, 'xpriv is truthy');
            throws(() => {
                masterKey.privateKey = undefined;
            });
            // throws(() => masterKey.privateExtendedKey);
        });
    });
    describe(' - when the path given to derive contains only the master extended key', () => {
        const hdKeyInstance = HDKey.fromMasterSeed(hexToBytes(fixtures[0].seed));
        it('should return the same hdkey instance', () => {
            deepStrictEqual(hdKeyInstance.derive('m'), hdKeyInstance);
            deepStrictEqual(hdKeyInstance.derive('M'), hdKeyInstance);
            deepStrictEqual(hdKeyInstance.derive("m'"), hdKeyInstance);
            deepStrictEqual(hdKeyInstance.derive("M'"), hdKeyInstance);
        });
    });
    describe(' - when the path given to derive does not begin with master extended key', () => {
        it('should throw an error', () => {
            throws(() => HDKey.prototype.derive('123'));
        });
    });
    describe('- after wipePrivateData()', () => {
        it('should not have private data', () => {
            const hdkey = HDKey.fromMasterSeed(hexToBytes(fixtures[6].seed)).wipePrivateData();
            deepStrictEqual(hdkey.privateKey, null);
            throws(() => hdkey.privateExtendedKey);
            throws(() => hdkey.sign(new Uint8Array(32)));
            const childKey = hdkey.derive('m/0');
            deepStrictEqual(childKey.publicExtendedKey, fixtures[7].public);
            deepStrictEqual(childKey.privateKey, null);
            throws(() => childKey.privateExtendedKey);
        });
        it('should have correct data', () => {
            // m/0/2147483647'/1/2147483646'/2
            const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
            const hdkey = HDKey.fromExtendedKey(key).wipePrivateData();
            deepStrictEqual(hdkey.versions.private, 0x0488ade4);
            deepStrictEqual(hdkey.versions.public, 0x0488b21e);
            deepStrictEqual(hdkey.depth, 5);
            deepStrictEqual(hdkey.parentFingerprint, 0x31a507b8);
            deepStrictEqual(hdkey.index, 2);
            deepStrictEqual(toHex(hdkey.chainCode), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271');
            deepStrictEqual(toHex(hdkey.publicKey), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c');
            deepStrictEqual(toHex(hdkey.identifier), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220');
        });
        it('should be able to verify signatures', () => {
            const fullKey = HDKey.fromMasterSeed(hexToBytes(fixtures[0].seed));
            // using JSON methods to clone before mutating
            const wipedKey = HDKey.fromJSON(fullKey.toJSON()).wipePrivateData();
            const hash = new Uint8Array(32).fill(8);
            deepStrictEqual(!!wipedKey.verify(hash, fullKey.sign(hash)), true);
        });
        it('should not throw if called on hdkey without private data', () => {
            const hdkey = HDKey.fromExtendedKey(fixtures[0].public);
            hdkey.wipePrivateData();
            deepStrictEqual(hdkey.publicExtendedKey, fixtures[0].public);
        });
    });
    it('should throw on derive of wrong indexes', () => {
        const hdkey = HDKey.fromExtendedKey(fixtures[0].public);
        const invalid = ['m/0/ 1 /2', 'm/0/1.5/2', 'm/0/331e100/2', 'm/0/3e/2', "m/0/'/2"];
        for (const t of invalid) {
            throws(() => hdkey.derive(t));
        }
    });
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    describe('Spec test vectors', () => {
        it('Test Vector 1', () => {
            const master = HDKey.fromMasterSeed(hexToBytes('000102030405060708090a0b0c0d0e0f'));
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
                xpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv: 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
                xpub: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
            });
            deepStrictEqual(master.derive("m/0'/1").toJSON(), {
                xpriv: 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
                xpub: 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
            });
            deepStrictEqual(master.derive("m/0'/1/2'").toJSON(), {
                xpriv: 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
                xpub: 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
            });
            deepStrictEqual(master.derive("m/0'/1/2'/2").toJSON(), {
                xpriv: 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
                xpub: 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
            });
            deepStrictEqual(master.derive("m/0'/1/2'/2/1000000000").toJSON(), {
                xpriv: 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
                xpub: 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
            });
        });
        it('Test Vector 2', () => {
            const master = HDKey.fromMasterSeed(hexToBytes('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'));
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv: 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
                xpub: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
            });
            deepStrictEqual(master.derive('m/0').toJSON(), {
                xpriv: 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
                xpub: 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
            });
            deepStrictEqual(master.derive("m/0/2147483647'").toJSON(), {
                xpriv: 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
                xpub: 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1").toJSON(), {
                xpriv: 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
                xpub: 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1/2147483646'").toJSON(), {
                xpriv: 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
                xpub: 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1/2147483646'/2").toJSON(), {
                xpriv: 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
                xpub: 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
            });
        });
        it('Test Vector 3', () => {
            const master = HDKey.fromMasterSeed(hexToBytes('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'));
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv: 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                xpub: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv: 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
                xpub: 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
            });
        });
        it('Test Vector 4', () => {
            const master = HDKey.fromMasterSeed(hexToBytes('3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678'));
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv: 'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
                xpub: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv: 'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
                xpub: 'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
            });
            deepStrictEqual(master.derive("m/0'/1'").toJSON(), {
                xpriv: 'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
                xpub: 'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
            });
        });
        it('Test Vector 5', () => {
            const keys = [
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm', // (pubkey version / prvkey mismatch)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH', // (prvkey version / pubkey mismatch)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn', // (invalid pubkey prefix 04)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ', // (invalid prvkey prefix 04)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4', // (invalid pubkey prefix 01)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J', // (invalid prvkey prefix 01)
                'xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv', // (zero depth with non-zero parent fingerprint)
                'xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ', // (zero depth with non-zero parent fingerprint)
                'xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN', // (zero depth with non-zero index)
                'xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8', // (zero depth with non-zero index)
                'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4', // (unknown extended key version)
                'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9', // (unknown extended key version)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx', // (private key 0 not in 1..n-1)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G', // (private key n not in 1..n-1)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY', // (invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007)
                'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL', // (invalid checksum)
            ];
            for (const c of keys) {
                throws(() => HDKey.fromExtendedKey(c));
            }
        });
    });
});
it.runWhen(import.meta.url);
