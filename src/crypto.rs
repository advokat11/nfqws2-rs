//! Port of crypto/: AES block, AES-CTR, AES-GCM (non-verifying, like the C gcm_crypt_and_tag),
//! SHA-224/256 and HKDF. Backed by RustCrypto primitives.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use sha2::{Digest, Sha224, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShaVer {
    Sha224,
    Sha256,
}

impl ShaVer {
    pub fn from_name(s: &str) -> Option<ShaVer> {
        match s {
            "sha256" => Some(ShaVer::Sha256),
            "sha224" => Some(ShaVer::Sha224),
            _ => None,
        }
    }
}

pub fn hash(v: ShaVer, data: &[u8]) -> Vec<u8> {
    match v {
        ShaVer::Sha256 => Sha256::digest(data).to_vec(),
        ShaVer::Sha224 => Sha224::digest(data).to_vec(),
    }
}

pub fn hkdf(
    v: ShaVer,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Option<Vec<u8>> {
    let mut okm = vec![0u8; okm_len];
    let ok = match v {
        ShaVer::Sha256 => hkdf::Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut okm)
            .is_ok(),
        ShaVer::Sha224 => hkdf::Hkdf::<Sha224>::new(salt, ikm)
            .expand(info, &mut okm)
            .is_ok(),
    };
    ok.then_some(okm)
}

/// HKDF-Expand-Label style helpers need raw expand from a PRK.
pub fn hkdf_expand(v: ShaVer, prk: &[u8], info: &[u8], okm_len: usize) -> Option<Vec<u8>> {
    let mut okm = vec![0u8; okm_len];
    let ok = match v {
        ShaVer::Sha256 => hkdf::Hkdf::<Sha256>::from_prk(prk)
            .ok()?
            .expand(info, &mut okm)
            .is_ok(),
        ShaVer::Sha224 => hkdf::Hkdf::<Sha224>::from_prk(prk)
            .ok()?
            .expand(info, &mut okm)
            .is_ok(),
    };
    ok.then_some(okm)
}

pub fn hkdf_extract(v: ShaVer, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match v {
        ShaVer::Sha256 => hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        ShaVer::Sha224 => hkdf::Hkdf::<Sha224>::extract(Some(salt), ikm).0.to_vec(),
    }
}

enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Option<Aes> {
        Some(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).ok()?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).ok()?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        })
    }
    fn enc(&self, b: &mut [u8; 16]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            Aes::A128(c) => c.encrypt_block(g),
            Aes::A192(c) => c.encrypt_block(g),
            Aes::A256(c) => c.encrypt_block(g),
        }
    }
    fn dec(&self, b: &mut [u8; 16]) {
        let g = GenericArray::from_mut_slice(b);
        match self {
            Aes::A128(c) => c.decrypt_block(g),
            Aes::A192(c) => c.decrypt_block(g),
            Aes::A256(c) => c.decrypt_block(g),
        }
    }
}

/// Single block AES. None on bad key length.
pub fn aes_block(encrypt: bool, key: &[u8], input: &[u8; 16]) -> Option<[u8; 16]> {
    let c = Aes::new(key)?;
    let mut b = *input;
    if encrypt {
        c.enc(&mut b)
    } else {
        c.dec(&mut b)
    }
    Some(b)
}

fn ctr_increment(c: &mut [u8; 16]) {
    for b in c.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// AES-CTR with a full 128-bit big-endian counter, as aes_ctr_xcrypt_buffer.
pub fn aes_ctr(key: &[u8], iv: &[u8; 16], input: &[u8]) -> Option<Vec<u8>> {
    let c = Aes::new(key)?;
    let mut ivc = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let mut ks = ivc;
        c.enc(&mut ks);
        ctr_increment(&mut ivc);
        out.extend(chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
    }
    Some(out)
}

/// GCM like the C gcm_crypt_and_tag: decrypt mode does not verify, it returns the tag
/// computed over the ciphertext input.
pub fn aes_gcm(
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    aad: &[u8],
) -> Option<(Vec<u8>, [u8; 16])> {
    let c = Aes::new(key)?;
    let mut h = [0u8; 16];
    c.enc(&mut h);
    // J0
    let mut j0 = [0u8; 16];
    if iv.len() == 12 {
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
    } else {
        let mut g = GHash::new(GenericArray::from_slice(&h));
        g.update_padded(iv);
        let mut lenblk = [0u8; 16];
        lenblk[8..].copy_from_slice(&((iv.len() as u64) * 8).to_be_bytes());
        g.update(&[GenericArray::clone_from_slice(&lenblk)]);
        j0.copy_from_slice(&g.finalize());
    }
    let mut ctr = j0;
    inc32(&mut ctr);
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let mut ks = ctr;
        c.enc(&mut ks);
        inc32(&mut ctr);
        out.extend(chunk.iter().zip(ks.iter()).map(|(a, b)| a ^ b));
    }
    let ct: &[u8] = if encrypt { &out } else { input };
    let mut g = GHash::new(GenericArray::from_slice(&h));
    g.update_padded(aad);
    g.update_padded(ct);
    let mut lenblk = [0u8; 16];
    lenblk[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lenblk[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    g.update(&[GenericArray::clone_from_slice(&lenblk)]);
    let s = g.finalize();
    let mut ek = j0;
    c.enc(&mut ek);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ ek[i];
    }
    Some((out, tag))
}

fn inc32(c: &mut [u8; 16]) {
    let v = u32::from_be_bytes([c[12], c[13], c[14], c[15]]).wrapping_add(1);
    c[12..].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gcm_nist_tc3() {
        // NIST GCM test case 3
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let pt = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        let (ct, tag) = aes_gcm(true, &key, &iv, &pt, &[]).unwrap();
        assert_eq!(tag.to_vec(), hex("4d5c2af327cd64a62cf35abd2ba6fab4"));
        let (pt2, tag2) = aes_gcm(false, &key, &iv, &ct, &[]).unwrap();
        assert_eq!(pt2, pt);
        assert_eq!(tag2, tag);
    }
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
