use std::fs::File;
use std::io::ErrorKind;
use std::path::PathBuf;

use openmls::prelude::OpenMlsCryptoProvider;
use openmls_rust_crypto::{DummyAuthenticationService, RustCrypto};

use crate::keystore::{DummyKeyStore, TestKeyStore};

// used for show and key-package commands
#[derive(Default)]
pub struct DummyBackend(RustCrypto);

impl OpenMlsCryptoProvider for DummyBackend {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = DummyKeyStore;
    type AuthenticationServiceProvider = DummyAuthenticationService;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.0
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.0
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &DummyKeyStore
    }

    fn authentication_service(&self) -> &Self::AuthenticationServiceProvider {
        &DummyAuthenticationService
    }
}

pub struct TestBackend {
    crypto: RustCrypto,
    path: PathBuf,
    key_store: TestKeyStore,
}

impl TestBackend {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let crypto = Self::create_crypto();

        let key_store = match File::open(&path) {
            Ok(mut f) => TestKeyStore::read(&mut f),
            Err(e) if e.kind() == ErrorKind::NotFound => TestKeyStore::new(),
            Err(e) => panic!("Could not open key store file: {:?}", e),
        };

        Ok(TestBackend {
            crypto,
            path: path,
            key_store,
        })
    }

    pub fn create_crypto() -> RustCrypto {
        RustCrypto::default()
    }
}

impl Drop for TestBackend {
    fn drop(&mut self) {
        self.key_store.write(&mut File::create(&self.path).unwrap());
    }
}

impl OpenMlsCryptoProvider for TestBackend {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = TestKeyStore;
    type AuthenticationServiceProvider = DummyAuthenticationService;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }

    fn authentication_service(&self) -> &Self::AuthenticationServiceProvider {
        &DummyAuthenticationService
    }
}
