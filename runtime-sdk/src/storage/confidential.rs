use anyhow::{anyhow, Error};
use thiserror::Error as _;

use crate::{
    core::{
        common::crypto::mrae::deoxysii,
        storage::mkvs,
    },
    context::Context,
    error,
    keymanager::{KeyPair, KeyPairId},
    modules,
    storage::Store,
};

/// A key-value store that encrypts all content with DeoxysII.
pub struct ConfidentialStore<S: Store> {
    inner: S,
    keypair: KeyPair,
    key: Vec<u8>,
}

impl<S: Store> ConfidentialStore<S> {
    /// Create a new confidential store with the given keymanager key id.
    pub fn new_with_id<C: Context>(ctx: &C, inner: S, kid: KeyPairId) -> Result<Self, Error> {
        let kmgr = ctx.key_manager().ok_or_else(|| { anyhow!("confidential transactions not available") })?;
        let keypair = kmgr.get_or_create_keys(kid)?;
        let key: Vec<u8> = keypair.input_keypair.sk.0.to_vec();
        Ok(ConfidentialStore {
            inner: inner,
            keypair: keypair,
            key: key,
        })
    }

    fn encode_key(&self, key: &[u8]) -> Result<([u8; deoxysii::NONCE_SIZE], Vec<u8>), Error> {
        let mut nonce: [u8; deoxysii::NONCE_SIZE] = [0; deoxysii::NONCE_SIZE];
        let result = deoxysii::box_seal(
            &nonce,
            key.to_vec(),
            Vec::new(),
            &self.keypair.input_keypair.pk.0,
            &self.keypair.input_keypair.sk.0,
        )?;
        Ok((nonce, result))
    }

    fn encode_value(&self, nonce: &[u8; deoxysii::NONCE_SIZE], value: &[u8]) -> Result<Vec<u8>, Error> {
        deoxysii::box_seal(
            nonce,
            value.to_vec(),
            Vec::new(),
            &self.keypair.input_keypair.pk.0,
            &self.keypair.input_keypair.sk.0,
        )
    }

    fn decode_value(&self, nonce: &[u8; deoxysii::NONCE_SIZE], value: &[u8]) -> Result<Vec<u8>, Error> {
        deoxysii::box_open(
            nonce,
            value.to_vec(),
            Vec::new(),
            &self.keypair.input_keypair.pk.0,
            &self.keypair.input_keypair.sk.0,
        )
    }
}

impl<S: Store> Store for ConfidentialStore<S> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let (nonce, ekey) = self.encode_key(key).expect("error encrypting key");
        match self.inner.get(&ekey) {
            None => None,
            Some(evalue) => {
                let value = self.decode_value(&nonce, &evalue).expect("error decrypting value");
                Some(value)
            }
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        let (nonce, ekey) = self.encode_key(key).expect("error encrypting key");
        let evalue = self.encode_value(&nonce, value).expect("error encrypting value");
        self.inner.insert(&ekey, &evalue)
    }

    fn remove(&mut self, key: &[u8]) {
        let (_, ekey) = self.encode_key(key).expect("error encrypting key");
        self.inner.remove(&ekey)
    }

    fn iter(&self) -> Box<dyn mkvs::Iterator + '_> {
        Box::new(ConfidentialStoreIterator::new(self))
    }
}

struct ConfidentialStoreIterator<'store, S: Store> {
    inner: Box<dyn mkvs::Iterator + 'store>,
    store: &'store ConfidentialStore<S>,

    key: Option<mkvs::Key>,
    value: Option<Vec<u8>>,
}

impl<'store, S: Store> ConfidentialStoreIterator<'store, S> {
    fn new(store: &'store ConfidentialStore<S>) -> ConfidentialStoreIterator<'_, S> {
        ConfidentialStoreIterator {
            inner: store.inner.iter(),
            store: store,
        }
    }

    fn reset(&mut self) {
        if self.inner.is_valid() {
            match self.inner.get_key() {
                None => {
                    ()
                }
                _ => (),
            }
        } else {
            self.key = None;
            self.value = None;
        }
    }
}

impl<'store, S: Store> Iterator for ConfidentialStoreIterator<'store, S> {
}

impl<'store, S: Store> mkvs::Iterator for ConfidentialStoreIterator<'store, S> {
    fn set_prefetch(&mut self, prefetch: usize) {
        self.inner.set_prefetch(prefetch)
    }

    fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }

    fn error(&self) -> Option<Error> {
        self.inner.error()
    }

    fn rewind(&mut self) {
        self.inner.rewind();
        self.reset();
    }

    fn seek(&mut self, key: &[u8]) {
        let (_, ekey) = self.store.encode_key(key).expect("error encrypting key");
        self.inner.seek(&ekey)
    }

    fn get_key(&self) -> &Option<mkvs::Key> {
        &self.key
    }

    fn get_value(&self) -> &Option<Vec<u8>> {
        &self.value
    }
}

/*
impl<S: Store, P: AsRef<[u8]>> Store for PrefixStore<S, P> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.parent.get(&[self.prefix.as_ref(), key].concat())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.parent
            .insert(&[self.prefix.as_ref(), key].concat(), value);
    }

    fn remove(&mut self, key: &[u8]) {
        self.parent.remove(&[self.prefix.as_ref(), key].concat());
    }

    fn iter(&self) -> Box<dyn mkvs::Iterator + '_> {
        Box::new(PrefixStoreIterator::new(
            self.parent.iter(),
            self.prefix.as_ref(),
        ))
    }
}

/// An iterator over the `PrefixStore`.
pub(crate) struct PrefixStoreIterator<'store> {
    inner: Box<dyn mkvs::Iterator + 'store>,
    prefix: &'store [u8],
}

impl<'store> PrefixStoreIterator<'store> {
    fn new(mut inner: Box<dyn mkvs::Iterator + 'store>, prefix: &'store [u8]) -> Self {
        inner.seek(prefix);
        Self { inner, prefix }
    }
}

impl<'store> Iterator for PrefixStoreIterator<'store> {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        Iterator::next(&mut self.inner).and_then(|(mut k, v)| {
            if k.starts_with(self.prefix) {
                Some((k.split_off(self.prefix.len()), v))
            } else {
                None
            }
        })
    }
}

impl<'store> mkvs::Iterator for PrefixStoreIterator<'store> {
    fn set_prefetch(&mut self, prefetch: usize) {
        self.inner.set_prefetch(prefetch)
    }

    fn is_valid(&self) -> bool {
        if !self
            .inner
            .get_key()
            .as_ref()
            .unwrap_or(&vec![])
            .starts_with(self.prefix)
        {
            return false;
        }
        self.inner.is_valid()
    }

    fn error(&self) -> &Option<anyhow::Error> {
        self.inner.error()
    }

    fn rewind(&mut self) {
        self.inner.seek(self.prefix);
    }

    fn seek(&mut self, key: &[u8]) {
        self.inner.seek(&[self.prefix, key].concat());
    }

    fn get_key(&self) -> &Option<mkvs::Key> {
        self.inner.get_key()
    }

    fn get_value(&self) -> &Option<Vec<u8>> {
        self.inner.get_value()
    }

    fn next(&mut self) {
        if !self.is_valid() {
            // Could be invalid due to prefix mismatch.
            return;
        }
        mkvs::Iterator::next(&mut *self.inner)
    }
}
*/
