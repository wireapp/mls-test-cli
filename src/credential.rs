use std::io::Write;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

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
        let keys = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let credential = match credential_type {
            CredentialType::Basic => Credential::new_basic(client_id.to_vec()),
            CredentialType::X509 => {
                // generate a self-signed certificate
                let handle = handle.unwrap_or(client_id.user.clone());
                let subject = format!("/O={}/CN={}", client_id.domain, handle);
                let san = client_id.to_x509(&handle);
                let openssl = std::process::Command::new("openssl")
                    .args([
                        "req",
                        "-new",
                        "-x509",
                        "-nodes",
                        "-days",
                        "3650",
                        "-key",
                        "/dev/stdin",
                        "-keyform",
                        "DER",
                        "-out",
                        "/dev/stdout",
                        "-keyout",
                        "/dev/null",
                        "-outform",
                        "DER",
                        "-subj",
                        &subject,
                        "-addext",
                        &san,
                    ])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdin = openssl.stdin.as_ref().unwrap();
                // add hardcoded pkcs8 envelope
                stdin
                    .write_all(b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20")
                    .unwrap();
                stdin.write_all(keys.private()).unwrap();
                let out = openssl.wait_with_output().unwrap();
                if !out.status.success() {
                    panic!(
                        "openssl failed: {}",
                        core::str::from_utf8(&out.stderr).unwrap()
                    );
                }
                let cert = out.stdout;
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
