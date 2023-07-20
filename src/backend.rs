use crate::keystore::TestKeyStore;
use openmls::prelude::OpenMlsCryptoProvider;
use openmls_rust_crypto::RustCrypto;

use std::fs::File;
use std::path::PathBuf;

pub struct TestBackend {
    crypto: RustCrypto,
    path: PathBuf,
    key_store: TestKeyStore,
}

impl TestBackend {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        let crypto = RustCrypto::default();
        let key_store = TestKeyStore::read(&mut File::open(&path).unwrap());
        Ok(TestBackend {
            crypto,
            path: path,
            key_store,
        })
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

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
