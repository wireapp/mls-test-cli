use async_trait::async_trait;
use openmls::prelude::*;
use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

use std::fmt::Display;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct TestKeyStore {
    path: PathBuf,
}

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
}

impl std::error::Error for TestKeyStoreError {}

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

#[async_trait]
impl OpenMlsKeyStore for TestKeyStore {
    type Error = TestKeyStoreError;

    async fn store<V: ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let mut file = std::fs::File::create(self.key_path(k))?;
        let value = v.to_key_store_value().map_err(|e| e.to_string())?;
        file.write_all(&value)?;
        Ok(())
    }

    async fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V> {
        let buf = std::fs::read(self.key_path(k)).ok()?;
        V::from_key_store_value(&buf).ok()
    }

    async fn delete<V: ToKeyStoreValue>(&self, k: &[u8]) -> Result<(), Self::Error> {
        std::fs::remove_file(self.key_path(k))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[derive(Debug, PartialEq)]
    struct Value(Vec<u8>);

    impl Value {
        fn from_slice(v: &[u8]) -> Self {
            Value(v.to_vec())
        }
    }

    impl FromKeyStoreValue for Value {
        type Error = String;

        fn from_key_store_value(v: &[u8]) -> Result<Self, String> {
            Ok(Self(v.to_vec()))
        }
    }

    impl ToKeyStoreValue for Value {
        type Error = String;

        fn to_key_store_value(&self) -> Result<Vec<u8>, String> {
            Ok(self.0.clone())
        }
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
