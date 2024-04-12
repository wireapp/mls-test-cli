use core::time::Duration;
use std::str::FromStr;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use ecdsa::signature;

use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    certificate::Certificate,
    ext::pkix::SubjectAltName,
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity,
};

use crate::{backend::TestBackend, client::ClientId};

#[derive(Debug)]
pub enum CredentialType {
    Basic,
    X509,
}

impl core::str::FromStr for CredentialType {
    type Err = String;

    fn from_str(x: &str) -> Result<Self, String> {
        match x {
            "basic" => Ok(Self::Basic),
            "x509" => Ok(Self::X509),
            _ => Err(format!("Invalid credential type {}", x)),
        }
    }
}

#[derive(Debug)]
pub struct CredentialBundle {
    credential: Credential,
    keys: SignatureKeyPair,
}

impl CredentialBundle {
    pub fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.credential.clone(),
            signature_key: self.keys.public().into(),
        }
    }

    pub fn keys(&self) -> &SignatureKeyPair {
        &self.keys
    }

    pub fn new(
        backend: &impl OpenMlsCryptoProvider,
        credential_type: CredentialType,
        client_id: ClientId,
        ciphersuite: Ciphersuite,
        handle: Option<String>,
    ) -> Self {
        let ss = ciphersuite.signature_algorithm();
        let keys = SignatureKeyPair::new(ss, &mut *backend.rand().borrow_rand().unwrap()).unwrap();
        let credential = match credential_type {
            CredentialType::Basic => Credential::new_basic(client_id.to_vec()),
            CredentialType::X509 => {
                // generate a self-signed certificate
                use pkcs8::der::Encode;
                let cert = generate_certificate_for_scheme(ss, &keys, client_id, handle)
                    .to_der()
                    .unwrap();
                {
                    use std::io::Write;
                    let mut file = std::fs::File::create("/tmp/cert.crt").unwrap();
                    file.write_all(&cert).unwrap();
                }

                Credential::new_x509(vec![cert.clone(), cert]).unwrap()
            }
        };
        Self { credential, keys }
    }

    pub fn store(&self, backend: &TestBackend) {
        backend
            .key_store()
            .store_value(b"self", &(&self.keys, &self.credential))
            .unwrap();
    }

    pub fn read(backend: &TestBackend) -> Self {
        let ks = backend.key_store();
        let (keys, credential) = ks
            .read_value(b"self")
            .ok()
            .flatten()
            .expect("Credential not initialised. Please run `init` first.");
        Self { credential, keys }
    }
}

/// Wrapper around ed25519 SigningKey that implements the traits needed by the x509
/// `CertificateBuilder`.
struct Ed25519Signer(ed25519_dalek::SigningKey);

pub struct Ed25519Signature(ed25519_dalek::Signature);
impl pkcs8::spki::SignatureBitStringEncoding for Ed25519Signature {
    fn to_bitstring(&self) -> pkcs8::der::Result<pkcs8::der::asn1::BitString> {
        pkcs8::der::asn1::BitString::new(0, self.0.to_vec())
    }
}

impl signature::Keypair for Ed25519Signer {
    type VerifyingKey = ed25519_dalek::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl pkcs8::spki::SignatureAlgorithmIdentifier for Ed25519Signer {
    type Params = der::AnyRef<'static>;
    const SIGNATURE_ALGORITHM_IDENTIFIER: pkcs8::spki::AlgorithmIdentifier<Self::Params> =
        ed25519_dalek::pkcs8::ALGORITHM_ID;
}

impl signature::Signer<Ed25519Signature> for Ed25519Signer {
    fn try_sign(&self, message: &[u8]) -> Result<Ed25519Signature, ed25519_dalek::SignatureError> {
        self.0.try_sign(message).map(Ed25519Signature)
    }
}

/// A lightweight abstraction to make it possible to uniformly generate certificates for all the
/// supported signature schemes.
trait Signer:
    signature::Signer<Self::Signature> + signature::Keypair + pkcs8::spki::SignatureAlgorithmIdentifier
{
    type Signature: pkcs8::spki::SignatureBitStringEncoding;
    fn from_bytes(key: &[u8]) -> Self;
    fn public_key(&self) -> SubjectPublicKeyInfoOwned;
}

impl Signer for Ed25519Signer {
    type Signature = Ed25519Signature;

    fn from_bytes(key: &[u8]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(
            key.try_into().unwrap(),
        ))
    }

    fn public_key(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_key(self.0.verifying_key()).unwrap()
    }
}

impl Signer for p256::ecdsa::SigningKey {
    type Signature = p256::ecdsa::DerSignature;

    fn from_bytes(key: &[u8]) -> Self {
        p256::ecdsa::SigningKey::from_bytes(key.into()).unwrap()
    }

    fn public_key(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_key(*self.verifying_key()).unwrap()
    }
}

impl Signer for p384::ecdsa::SigningKey {
    type Signature = p384::ecdsa::DerSignature;

    fn from_bytes(key: &[u8]) -> Self {
        p384::ecdsa::SigningKey::from_bytes(key.into()).unwrap()
    }

    fn public_key(&self) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned::from_key(*self.verifying_key()).unwrap()
    }
}

fn generate_certificate_for_scheme(
    ss: SignatureScheme,
    key: &SignatureKeyPair,
    client_id: ClientId,
    handle: Option<String>,
) -> Certificate {
    match ss {
        SignatureScheme::ED25519 => generate_certificate::<Ed25519Signer>(key, client_id, handle),
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            generate_certificate::<p256::ecdsa::SigningKey>(key, client_id, handle)
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            generate_certificate::<p384::ecdsa::SigningKey>(key, client_id, handle)
        }
        _ => panic!("Unsupported signature scheme"),
    }
}

fn generate_certificate<S: Signer>(
    key: &SignatureKeyPair,
    client_id: ClientId,
    handle: Option<String>,
) -> Certificate
where
    <S as signature::Keypair>::VerifyingKey: pkcs8::EncodePublicKey,
{
    let serial_number = SerialNumber::from(1u32);
    let validity = Validity::from_now(Duration::new(3600 * 24 * 365, 0)).unwrap();
    let profile = Profile::Root;
    let handle = handle.unwrap_or(client_id.user.clone());
    let subject = Name::from_str(&format!("O={},CN={}", client_id.domain, handle)).unwrap();

    let signer = S::from_bytes(key.private());
    let pub_key = signer.public_key();
    let mut builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)
            .expect("Create certificate");
    let san = client_id.to_x509(&handle).collect();
    builder.add_extension(&SubjectAltName(san)).unwrap();
    builder.build::<S::Signature>().unwrap()
}
