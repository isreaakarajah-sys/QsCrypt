//! Known-answer tests for the production backend, plus cross-checks
//! against the independent reference implementation in qscrypt-core.

use qscrypt_core::crypto::{Backend, CipherKind, Prf};
use qscrypt_core::disk::{Disk, MemDisk};
use qscrypt_core::qsc;
use qscrypt_core::reference::RefBackend;
use qscrypt_core::vc::{self, selftest, CipherChain, Ea, OpenOptions};
use qscrypt_core::xts::Xts;
use qscrypt_crypto::RustCrypto;
use std::sync::atomic::AtomicBool;

include!("../../../testdata/vectors.rs");

const NO: AtomicBool = AtomicBool::new(false);

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn pbkdf2_matches_python() {
    let b = RustCrypto::new();
    for (prf, cases) in [
        (Prf::Sha512, [(1, v::PBKDF2_SHA512_1), (2, v::PBKDF2_SHA512_2), (1000, v::PBKDF2_SHA512_1000)]),
        (Prf::Sha256, [(1, v::PBKDF2_SHA256_1), (2, v::PBKDF2_SHA256_2), (1000, v::PBKDF2_SHA256_1000)]),
        (Prf::Ripemd160, [(1, v::PBKDF2_RIPEMD160_1), (2, v::PBKDF2_RIPEMD160_2), (1000, v::PBKDF2_RIPEMD160_1000)]),
    ] {
        for (iters, expect) in cases {
            let mut out = vec![0u8; 192];
            qscrypt_core::kdf::pbkdf2(&b, prf, v::PBKDF2_PW, v::PBKDF2_SALT, iters, &mut out, &NO).unwrap();
            assert_eq!(out, expect, "{prf:?} x{iters}");
        }
    }
}

#[test]
fn whirlpool_digest() {
    use whirlpool::{Digest, Whirlpool};
    // ISO/IEC 10118-3 / NESSIE: Whirlpool("").
    let d = Whirlpool::digest(b"");
    assert_eq!(
        d.to_vec(),
        hex("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3")
    );
}

#[test]
fn hmac_and_hkdf_match_python() {
    let b = RustCrypto::new();
    assert_eq!(b.hmac_sha512(v::HMAC_KEY_SHORT, &[v::HMAC_MSG]).to_vec(), v::HMAC_SHA512_SHORT);
    assert_eq!(b.hmac_sha512(v::HMAC_KEY_LONG, &[v::HMAC_MSG]).to_vec(), v::HMAC_SHA512_LONG);
    let mut out = vec![0u8; 160];
    qscrypt_core::kdf::hkdf_sha512(&b, v::HKDF_SALT, v::HKDF_IKM, v::HKDF_INFO, &mut out).unwrap();
    assert_eq!(out, v::HKDF_OUT);
    assert_eq!(b.sha256(&[v::HASH_MSGS[1]]).to_vec(), v::SHA256[1]);
}

#[test]
fn aes_xts_matches_python() {
    let b = RustCrypto::new();
    let x = Xts::new(b.cipher(CipherKind::Aes, v::XTS_K1.try_into().unwrap()).unwrap(), b.cipher(CipherKind::Aes, v::XTS_K2.try_into().unwrap()).unwrap());
    let mut buf = v::XTS_PT.to_vec();
    x.encrypt(&mut buf, 512, 256);
    assert_eq!(buf, v::XTS_CT_UNIT_256);
    x.decrypt(&mut buf, 512, 256);
    assert_eq!(buf, v::XTS_PT);
    let mut big = v::XTS_PT[..512].to_vec();
    x.encrypt(&mut big, 512, v::XTS_BIG_UNIT);
    assert_eq!(big, v::XTS_CT_BIG_UNIT);
}

#[test]
fn twofish_kat() {
    // Twofish paper, ECB_TBL.TXT, 256-bit key, I=1: zero key, zero block.
    let b = RustCrypto::new();
    let c = b.cipher(CipherKind::Twofish, &[0u8; 32]).unwrap();
    let mut blk = [0u8; 16];
    c.encrypt_blocks(&mut blk);
    assert_eq!(blk.to_vec(), hex("57ff739d4dc92c1bd7fc01700cc8216f"));
    c.decrypt_blocks(&mut blk);
    assert_eq!(blk, [0u8; 16]);
}

#[test]
fn argon2id_matches_python() {
    let b = RustCrypto::new();
    let mut out = [0u8; 32];
    b.argon2id(v::ARGON2_PW, v::ARGON2_SALT, 1024, 2, 2, &mut out).unwrap();
    assert_eq!(out.to_vec(), v::ARGON2ID_M1024_T2_P2);
}

#[test]
fn xchacha_matches_python() {
    let b = RustCrypto::new();
    let key: [u8; 32] = v::XC_KEY.try_into().unwrap();
    let nonce: [u8; 24] = v::XC_NONCE.try_into().unwrap();
    let mut buf = v::XC_PT.to_vec();
    let tag = b.xchacha_seal(&key, &nonce, v::XC_AAD, &mut buf).unwrap();
    assert_eq!(buf, v::XC_CT);
    assert_eq!(tag.to_vec(), v::XC_TAG);
    b.xchacha_open(&key, &nonce, v::XC_AAD, &mut buf, &tag).unwrap();
    assert_eq!(buf, v::XC_PT);
    buf[0] ^= 1;
    assert!(b.xchacha_open(&key, &nonce, v::XC_AAD, &mut buf, &tag).is_err());
}

#[test]
fn random_is_random() {
    let b = RustCrypto::new();
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    b.fill_random(&mut x).unwrap();
    b.fill_random(&mut y).unwrap();
    assert_ne!(x, y);
    assert_ne!(x, [0u8; 32]);
}

#[test]
fn matches_reference_backend() {
    let (prod, refb) = (RustCrypto::new(), RefBackend::new());
    for prf in [Prf::Sha512, Prf::Sha256] {
        let (mut a, mut b) = (vec![0u8; 100], vec![0u8; 100]);
        qscrypt_core::kdf::pbkdf2(&prod, prf, b"pw", b"salt", 77, &mut a, &NO).unwrap();
        qscrypt_core::kdf::pbkdf2(&refb, prf, b"pw", b"salt", 77, &mut b, &NO).unwrap();
        assert_eq!(a, b);
    }
    let key = [0x42u8; 32];
    let (pa, ra) = (prod.cipher(CipherKind::Aes, &key).unwrap(), refb.cipher(CipherKind::Aes, &key).unwrap());
    let mut x: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    let mut y = x.clone();
    pa.encrypt_blocks(&mut x);
    ra.encrypt_blocks(&mut y);
    assert_eq!(x, y);
}

/// VeraCrypt's startup self-test. Single ciphers need only key row 0; for
/// cascades the test's remaining key rows are searched so a failure says
/// whether the cipher code or only the assumed rows are off.
#[test]
fn veracrypt_sector_selftest() {
    let b = RustCrypto::new();
    let singles = selftest::run(&b, false);
    assert!(singles.iter().all(|(_, ok)| *ok), "single ciphers: {singles:?}");

    let rows: Vec<(&str, [u8; 32])> = vec![
        ("e", selftest::KEY_E),
        ("pi", selftest::KEY_PI),
        ("0..31", std::array::from_fn(|i| i as u8)),
        ("32..63", std::array::from_fn(|i| 32 + i as u8)),
        ("64..95", std::array::from_fn(|i| 64 + i as u8)),
        ("tc", selftest::KEY_ROW3),
        ("e+", hex("7240766303535475945713821785251664274274663919320030599218174135").try_into().unwrap()),
        ("pi+", hex("3078164062862089986280348253421170679821480865132823066470938446").try_into().unwrap()),
    ];
    let mut report = Vec::new();
    let mut all_default = true;
    let mut all_found = true;
    for (ea, crcs) in selftest::SECTOR_CRCS.iter().filter(|(ea, _)| ea.ciphers().len() > 1) {
        let default_ok = (0..4).all(|c| selftest::sector_crc(&b, *ea, &selftest::default_key1(), c).unwrap() == crcs[c as usize]);
        all_default &= default_ok;
        let mut matches = Vec::new();
        for (n1, r1) in &rows {
            for (n2, r2) in &rows {
                let mut k = [0u8; 96];
                k[..32].copy_from_slice(&selftest::KEY_E);
                k[32..64].copy_from_slice(r1);
                k[64..].copy_from_slice(r2);
                if (0..4).all(|c| selftest::sector_crc(&b, *ea, &k, c).unwrap() == crcs[c as usize]) {
                    matches.push(format!("rows[e,{n1},{n2}]"));
                }
            }
        }
        // Two-cipher cascades need only rows e and pi, which are certain; the
        // third row of VeraCrypt's test data is only reconstructed.
        if ea.ciphers().len() == 2 {
            all_found &= !matches.is_empty();
        }
        report.push(format!("{}: default={default_ok} matches={matches:?}", ea.name()));
    }
    // Some key-row assignment must reproduce VeraCrypt's CRCs: otherwise the
    // cascade code itself is wrong. The default rows only matter for the
    // in-app self-test, so a mismatch there is reported, not fatal.
    eprintln!("VeraCrypt cascade self-test: {report:#?}");
    assert!(all_found, "cascades: {report:#?}");
    // Confirmed in CI (build 6): rows e, pi and KEY_ROW3 reproduce all of
    // VeraCrypt's cascade CRCs, so the in-app self-test must pass too.
    assert!(all_default, "default rows no longer match VeraCrypt: {report:#?}");
}

#[test]
fn opens_test_volumes_with_all_algorithms_enabled() {
    let b = RustCrypto::new();
    for (file, pw, pim, fmt) in [
        ("vc_aes_sha512", "correct horse", 1, None),
        ("vc_aes_sha256", "SHA-256 volume", 1, None),
        ("vc_hidden", "hidden password", 1, None),
        ("tc_aes_sha512", "truecrypt", 0, Some(vc::Format::TrueCrypt)),
    ] {
        let data = std::fs::read(format!("{}/../../testdata/{file}.vol", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let mut disk = MemDisk { data };
        let mut o = OpenOptions::new(pw.as_bytes());
        o.pim = pim;
        o.format = fmt;
        let h = vc::detect(&b, &mut disk, &o, &NO).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(h.ea, Ea::Aes, "{file}");
        let chain = CipherChain::new(&b, h.ea, &h.header.master_keys).unwrap();
        let mut vol = vc::EncVolume::new(Box::new(disk), chain, h.header.data_offset, h.header.data_size, true).unwrap();
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
    }
}

#[test]
fn create_and_open_every_algorithm() {
    let b = RustCrypto::new();
    for ea in Ea::ALL {
        let size = vc::DATA_OFFSET * 2 + (1 << 20);
        let mut disk = MemDisk::new(size as usize);
        let mut opts = vc::CreateOptions::new(vc::Format::VeraCrypt, b"pw", ea, Prf::Whirlpool, size);
        opts.pim = 1;
        vc::create_container(&b, &mut disk, &opts, &mut |_, _| true, &NO).unwrap();
        let mut o = OpenOptions::new(b"pw");
        o.pim = 1;
        let h = vc::detect(&b, &mut disk, &o, &NO).unwrap();
        assert_eq!((h.ea, h.prf), (ea, Prf::Whirlpool));
        let chain = CipherChain::new(&b, h.ea, &h.header.master_keys).unwrap();
        let vol = vc::EncVolume::new(Box::new(disk), chain, h.header.data_offset, h.header.data_size, false).unwrap();
        let mut fs = qscrypt_core::fs::mount(Box::new(vol), false, 0).unwrap();
        fs.write_file("/x.txt", &mut &b"ok"[..], 2, false, &mut |_| true).unwrap();
        let mut out = Vec::new();
        fs.read_file("/x.txt", &mut out, &mut |_| true).unwrap();
        assert_eq!(out, b"ok");
    }
}

#[test]
fn qscrypt_round_trip_with_real_primitives() {
    let b = RustCrypto::new();
    let content: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    let meta = qsc::Meta { name: "عقد.pdf".into(), modified: 1_700_000_000, size: content.len() as u64 };
    let params = qsc::Params { memory_kib: 8 * 1024, iterations: 1, lanes: 1, chunk_size: 1 << 20 };
    let mut enc = Vec::new();
    qsc::encrypt(&b, "كلمة سر".as_bytes(), &meta, &mut content.as_slice(), &mut enc, params, &mut |_, _| true).unwrap();
    let mut dec = Vec::new();
    let m = qsc::decrypt(&b, "كلمة سر".as_bytes(), &mut enc.as_slice(), Some(&mut dec), &mut |_, _| true).unwrap();
    assert_eq!(m, meta);
    assert_eq!(dec, content);
    let mut sink = Vec::new();
    assert!(qsc::decrypt(&b, b"nope", &mut enc.as_slice(), Some(&mut sink), &mut |_, _| true).is_err());
}

// ------------------------------------------------------------ diagnostics

/// If Serpent ever disagrees with VeraCrypt, this names the byte-order
/// transformation that would reconcile them, so the fix is one CI run away.
mod serpent_order {
    use super::*;
    use qscrypt_core::crypto::BlockCipher;

    #[derive(Clone, Copy, Debug)]
    pub enum Tf {
        Id,
        Reverse,
        ReverseWords,
        SwapInWords,
    }

    pub fn apply(tf: Tf, b: &mut [u8]) {
        match tf {
            Tf::Id => {}
            Tf::Reverse => b.reverse(),
            Tf::ReverseWords => {
                let words: Vec<[u8; 4]> = b.chunks_exact(4).map(|w| w.try_into().unwrap()).rev().collect();
                for (dst, w) in b.chunks_exact_mut(4).zip(words) {
                    dst.copy_from_slice(&w);
                }
            }
            Tf::SwapInWords => b.chunks_exact_mut(4).for_each(|w| w.reverse()),
        }
    }

    struct Wrapped(Box<dyn BlockCipher>, Tf);

    impl BlockCipher for Wrapped {
        fn encrypt_blocks(&self, data: &mut [u8]) {
            data.chunks_exact_mut(16).for_each(|b| apply(self.1, b));
            self.0.encrypt_blocks(data);
            data.chunks_exact_mut(16).for_each(|b| apply(self.1, b));
        }
        fn decrypt_blocks(&self, data: &mut [u8]) {
            data.chunks_exact_mut(16).for_each(|b| apply(self.1, b));
            self.0.decrypt_blocks(data);
            data.chunks_exact_mut(16).for_each(|b| apply(self.1, b));
        }
    }

    pub struct Variant {
        pub key: Tf,
        pub block: Tf,
    }

    impl Backend for Variant {
        fn name(&self) -> &'static str {
            "variant"
        }
        fn has_prf(&self, p: Prf) -> bool {
            RustCrypto.has_prf(p)
        }
        fn has_cipher(&self, c: CipherKind) -> bool {
            RustCrypto.has_cipher(c)
        }
        fn pbkdf2_block(&self, prf: Prf, pw: &[u8], salt: &[u8], it: u32, i: u32, out: &mut [u8], c: &AtomicBool) -> qscrypt_core::Result<()> {
            RustCrypto.pbkdf2_block(prf, pw, salt, it, i, out, c)
        }
        fn hmac_sha512(&self, k: &[u8], p: &[&[u8]]) -> [u8; 64] {
            RustCrypto.hmac_sha512(k, p)
        }
        fn sha256(&self, p: &[&[u8]]) -> [u8; 32] {
            RustCrypto.sha256(p)
        }
        fn sha512(&self, p: &[&[u8]]) -> [u8; 64] {
            RustCrypto.sha512(p)
        }
        fn cipher(&self, kind: CipherKind, key: &[u8; 32]) -> qscrypt_core::Result<Box<dyn BlockCipher>> {
            if kind != CipherKind::Serpent {
                return RustCrypto.cipher(kind, key);
            }
            let mut k = *key;
            apply(self.key, &mut k);
            Ok(Box::new(Wrapped(RustCrypto.cipher(kind, &k)?, self.block)))
        }
        fn fill_random(&self, o: &mut [u8]) -> qscrypt_core::Result<()> {
            RustCrypto.fill_random(o)
        }
        fn argon2id(&self, p: &[u8], s: &[u8], m: u32, t: u32, l: u32, o: &mut [u8]) -> qscrypt_core::Result<()> {
            RustCrypto.argon2id(p, s, m, t, l, o)
        }
        fn xchacha_seal(&self, k: &[u8; 32], n: &[u8; 24], a: &[u8], b: &mut [u8]) -> qscrypt_core::Result<[u8; 16]> {
            RustCrypto.xchacha_seal(k, n, a, b)
        }
        fn xchacha_open(&self, k: &[u8; 32], n: &[u8; 24], a: &[u8], b: &mut [u8], t: &[u8; 16]) -> qscrypt_core::Result<()> {
            RustCrypto.xchacha_open(k, n, a, b, t)
        }
    }
}

#[test]
fn serpent_byte_order_matches_veracrypt() {
    use serpent_order::{Tf, Variant};
    let expect = selftest::SECTOR_CRCS.iter().find(|(ea, _)| *ea == Ea::Serpent).unwrap().1;
    let key1 = selftest::default_key1();
    let mut matches = Vec::new();
    for key in [Tf::Id, Tf::Reverse, Tf::ReverseWords, Tf::SwapInWords] {
        for block in [Tf::Id, Tf::Reverse, Tf::ReverseWords, Tf::SwapInWords] {
            let v = Variant { key, block };
            if (0..4).all(|c| selftest::sector_crc(&v, Ea::Serpent, &key1, c).unwrap() == expect[c as usize]) {
                matches.push(format!("key={key:?} block={block:?}"));
            }
        }
    }
    assert!(matches.iter().any(|m| m == "key=Id block=Id"), "Serpent differs from VeraCrypt; matching transformations: {matches:?}");
}

#[test]
fn opens_asset_sealed_by_python() {
    let b = RustCrypto::new();
    assert_eq!(qsc::open_asset(&b, v::ASSET_PW, v::ASSET_SEALED).unwrap(), v::ASSET_PLAIN);
    assert!(matches!(qsc::open_asset(&b, b"WRONG", v::ASSET_SEALED), Err(qscrypt_core::Error::WrongPassword)));
    let mut bad = v::ASSET_SEALED.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(qsc::open_asset(&b, v::ASSET_PW, &bad).is_err());
}

// ---------------------------------------------------------------- asymmetric (QsCrypt v2)

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn x25519_rfc7748() {
    let b = RustCrypto;
    let mut base = [0u8; 32];
    base[0] = 9;
    let a: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap();
    let bb: [u8; 32] = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").try_into().unwrap();
    let pa = b.x25519(&a, &base).unwrap();
    let pb = b.x25519(&bb, &base).unwrap();
    assert_eq!(pa.to_vec(), unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    assert_eq!(pb.to_vec(), unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    let k = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(b.x25519(&a, &pb).unwrap().to_vec(), k);
    assert_eq!(b.x25519(&bb, &pa).unwrap().to_vec(), k);
    assert!(b.x25519(&a, &[0u8; 32]).is_err(), "low-order point rejected");
}

#[test]
fn ed25519_rfc8032_test1() {
    let b = RustCrypto;
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").try_into().unwrap();
    let pk = b.ed25519_public(&seed).unwrap();
    assert_eq!(pk.to_vec(), unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    let sig = b.ed25519_sign(&seed, b"").unwrap();
    assert_eq!(sig.to_vec(), unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
    assert!(b.ed25519_verify(&pk, b"", &sig));
    assert!(!b.ed25519_verify(&pk, b"x", &sig));
}

#[test]
fn mlkem768_round_trip() {
    let b = RustCrypto;
    let (dk, ek) = b.mlkem768_keygen().unwrap();
    assert_eq!((dk.len(), ek.len()), (2400, 1184));
    let (ct, ss) = b.mlkem768_encapsulate(&ek).unwrap();
    assert_eq!(ct.len(), 1088);
    assert_eq!(b.mlkem768_decapsulate(&dk, &ct).unwrap(), ss);
    // A different key gives a different (implicitly rejected) secret.
    let (dk2, _) = b.mlkem768_keygen().unwrap();
    assert_ne!(b.mlkem768_decapsulate(&dk2, &ct).unwrap(), ss);
    let mut bad = ct.clone();
    bad[5] ^= 1;
    assert_ne!(b.mlkem768_decapsulate(&dk, &bad).unwrap(), ss);
}

#[test]
fn sha512_and_aes128() {
    let b = RustCrypto;
    assert_eq!(b.sha512(&[b"abc"]).to_vec(), unhex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    let c = b.aes128(&unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap()).unwrap();
    let mut blk = unhex("00112233445566778899aabbccddeeff");
    c.encrypt_blocks(&mut blk);
    assert_eq!(blk, unhex("69c4e0d86a7b0430d8cdb78070b4c55a"));
}
