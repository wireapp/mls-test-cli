use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};

use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct TestKeyStore {
    path: PathBuf,
}

impl std::error::Error for TestKeyStoreError {}

impl TestKeyStore {
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(&path)?;
        Ok(TestKeyStore {
            path: path.as_ref().to_path_buf(),
        })
    }

    fn key_path(&self, k: &[u8]) -> PathBuf {
        let mut path = self.path.clone();
        path.push(base64::encode_config(k, base64::URL_SAFE));
        path
    }

    pub fn store_bytes(
        &self,
        k: &[u8],
    ) -> Result<std::fs::File, TestKeyStoreError> {
        let file = std::fs::File::create(self.key_path(k))?;
        Ok(file)
    }

    pub fn read_bytes(
        &self,
        k: &[u8],
    ) -> Result<std::fs::File, TestKeyStoreError> {
        let file = std::fs::File::open(self.key_path(k))?;
        Ok(file)
    }

    pub fn delete_entry(&self, k: &[u8]) -> Result<(), TestKeyStoreError> {
        std::fs::remove_file(self.key_path(k)).ok();
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TestKeyStoreError(String);

impl Display for TestKeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for TestKeyStoreError {
    fn from(e: String) -> Self {
        Self(e)
    }
}

impl From<std::io::Error> for TestKeyStoreError {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}

#[async_trait::async_trait(?Send)]
impl OpenMlsKeyStore for TestKeyStore {
    type Error = TestKeyStoreError;

    async fn store<V: MlsEntity>(
        &self,
        k: &[u8],
        v: &V,
    ) -> Result<(), Self::Error> {
        let mut out = self.store_bytes(k)?;
        // TODO: serialise directly
        let value = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        out.write_all(&value)?;
        Ok(())
    }

    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        let mut reader = self.read_bytes(k).ok()?;
        serde_json::from_reader(&mut reader).ok()
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        self.delete_entry(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempdir::TempDir;

    #[test]
    fn test_store_and_read() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        let value = b"hello";
        ks.store_bytes(b"foo").unwrap().write_all(value).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        ks.read_bytes(b"foo")
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(value, &buf[..]);
    }

    #[test]
    fn test_delete() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        ks.store_bytes(b"foo").unwrap().write_all(b"hello").unwrap();
        ks.delete_entry(b"foo").unwrap();
        match ks.read_bytes(b"foo") {
            Err(_) => (),
            Ok(_) => panic!("Unexpected success"),
        }
    }
}
