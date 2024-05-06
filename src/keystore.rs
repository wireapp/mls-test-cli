use openmls_traits::key_store::{MlsEntity, OpenMlsKeyStore};

use std::collections::HashMap;
use std::fmt::Display;
use std::io::{Read, Write};
use std::ops::Deref;
use std::sync::Mutex;

use serde_json::Value;

#[derive(PartialEq, Eq, Debug, Hash)]
struct Key(Vec<u8>);

impl core::borrow::Borrow<[u8]> for Key {
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}

impl serde::Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::encode(&self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = base64::decode(String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("Invalid base64 key"))?;
        Ok(Key(value))
    }
}

pub struct TestKeyStore(Mutex<HashMap<Key, Value>>);

impl std::error::Error for TestKeyStoreError {}

impl TestKeyStore {
    pub fn new() -> Self {
        TestKeyStore(Mutex::new(HashMap::new()))
    }

    pub fn read<R: Read>(r: &mut R) -> Self {
        Self(Mutex::new(serde_json::from_reader(r).unwrap()))
    }

    pub fn write<W: Write>(&self, w: &mut W) -> () {
        serde_json::to_writer(w, self.0.lock().unwrap().deref()).unwrap();
    }

    pub fn store_value<T: serde::Serialize>(
        &self,
        k: &[u8],
        x: &T,
    ) -> Result<(), serde_json::Error> {
        let value = serde_json::to_value(x)?;
        self.0.lock().unwrap().insert(Key(k.to_vec()), value);
        Ok(())
    }

    pub fn read_value<T: serde::de::DeserializeOwned>(
        &self,
        k: &[u8],
    ) -> Result<Option<T>, serde_json::Error> {
        match self.0.lock().unwrap().get(k) {
            Some(value) => serde_json::from_value(value.clone()),
            None => Ok(None),
        }
    }

    fn delete_entry(&self, k: &[u8]) {
        self.0.lock().unwrap().remove(k);
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

#[async_trait::async_trait]
impl OpenMlsKeyStore for TestKeyStore {
    type Error = TestKeyStoreError;

    async fn store<V: MlsEntity + Sync>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        self.store_value(k, v).map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        self.read_value(k).unwrap()
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        self.delete_entry(k);
        Ok(())
    }
}

pub struct DummyKeyStore;

#[async_trait::async_trait]
impl OpenMlsKeyStore for DummyKeyStore {
    type Error = TestKeyStoreError;

    async fn store<V: MlsEntity + Sync>(&self, _k: &[u8], _v: &V) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn read<V: MlsEntity>(&self, _k: &[u8]) -> Option<V> {
        None
    }

    async fn delete<V: MlsEntity>(&self, _k: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_read() {
        let ks = TestKeyStore::new();

        let value = "hello".to_string();
        ks.store_value(b"foo", &value).unwrap();
        let value2 = ks.read_value(b"foo").unwrap();
        assert_eq!(Some(value), value2);
    }

    #[test]
    fn test_delete() {
        let ks = TestKeyStore::new();

        ks.store_value(b"foo", &"hello".to_string()).unwrap();
        ks.delete_entry(b"foo");
        match ks.read_value::<String>(b"foo").unwrap() {
            None => (),
            Some(_) => panic!("Unexpected success"),
        }
    }

    #[test]
    fn test_reload() {
        let ks = TestKeyStore::new();
        ks.store_value(b"foo", &"hello".to_string()).unwrap();
        ks.store_value(b"bar", &vec!["hello".to_string(), "world".to_string()])
            .unwrap();

        let mut json: Vec<u8> = Vec::new();
        ks.write(&mut json);

        eprintln!("{}", std::str::from_utf8(&json).unwrap());

        let ks2 = TestKeyStore::read(&mut &json[..]);
        {
            let ks = ks.0.lock().unwrap();
            let ks2 = ks2.0.lock().unwrap();
            assert_eq!(ks.deref(), ks2.deref());
        }
    }
}
