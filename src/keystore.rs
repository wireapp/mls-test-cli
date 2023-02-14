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

impl OpenMlsKeyStore for TestKeyStore {
    type Error = TestKeyStoreError;

    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let mut out = self.store_bytes(k)?;
        let value = v.tls_serialize_detached().map_err(|e| e.to_string())?;
        out.write_all(&value)?;
        Ok(())
    }

    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        let mut out = self.read_bytes(k).ok()?;
        V::tls_deserialize(&mut out).ok()
    }

    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        std::fs::remove_file(self.key_path(k))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::key_store::MlsEntityId;
    use tempdir::TempDir;

    #[derive(Debug, PartialEq)]
    struct Value(Vec<u8>);

    impl Value {
        fn from_slice(v: &[u8]) -> Self {
            Value(v.to_vec())
        }
    }

    impl MlsEntity for Value {
        const ID: MlsEntityId = MlsEntityId::KeyPackage;
    }

    #[test]
    fn test_store_and_read() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        let value = Value::from_slice(b"hello");
        ks.store(b"foo", &value).unwrap();
        assert_eq!(Some(value), ks.read(b"foo"));
    }

    #[test]
    fn test_delete() {
        let p = TempDir::new("store").unwrap();
        let ks = TestKeyStore::create(&p).unwrap();

        let value = Value::from_slice(b"hello");
        ks.store(b"foo", &value).unwrap();
        assert_eq!(Some(value), ks.read(b"foo"));
        ks.delete(b"foo").unwrap();
        assert_eq!(None, ks.read::<Value>(b"foo"));
    }
}
