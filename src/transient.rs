use openmls::{
    group::{group_context::GroupContext, MlsGroup},
    prelude::{LeafNodeIndex, OpenMlsCrypto as _, Signable},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize as _, TlsSerialize, TlsSize, VLBytes};

use crate::credential::CredentialBundle;

const PROTOCOL_VERSION: u16 = 1;
const TRANSIENT_MESSAGE_WIRE_FORMAT: u16 = 0xF000;
const PADDING_SIZE: usize = 128;
const SECRET_KEY_LABEL: &str = "Tnt TransientMessage Secret Key v1";
const NONCE_SECRET_LABEL: &str = "Tnt TransientMessage Nonce Secret v1";
const SIGN_LABEL: &str = "TntMessageTBS-Transient v1";

#[derive(Clone, Copy, TlsSize, TlsSerialize)]
#[repr(transparent)]
struct TntProtocolVersion(u16);

#[derive(TlsSize, TlsSerialize)]
#[repr(u16)]
enum TntMessageBody {
    #[tls_codec(discriminant = 0xF000)]
    Transient(TransientMessage),
}

#[derive(TlsSize, TlsSerialize)]
struct TntMessageTbs {
    protocol_version: TntProtocolVersion,
    body: TntMessageBody,
}

impl Signable for TntMessageTbs {
    type SignedOutput = TntMessage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGN_LABEL
    }
}

#[derive(TlsSize, TlsSerialize)]
struct TntMessage {
    content: TntMessageTbs,
    signature: openmls::prelude::Signature,
}

impl openmls::prelude::SignedStruct<TntMessageTbs> for TntMessage {
    fn from_payload(payload: TntMessageTbs, signature: openmls::prelude::Signature) -> Self {
        Self {
            content: payload,
            signature,
        }
    }
}

#[derive(TlsSize, TlsSerialize)]
struct TransientMessageAad {
    protocol_version: TntProtocolVersion,
    wire_format: u16,
    group_context: GroupContext,
    sender: LeafNodeIndex,
    counter: u32,
}

#[derive(TlsSize, TlsSerialize)]
struct TransientMessage {
    group_context: GroupContext,
    sender: LeafNodeIndex,
    counter: u32,
    payload: Vec<u8>,
}

pub(crate) fn create_transient_message(
    backend: &impl OpenMlsCryptoProvider,
    credentials: &CredentialBundle,
    group: &MlsGroup,
    counter: u32,
    text: &[u8],
) -> Vec<u8> {
    let sender = group.own_leaf_index();
    let group_context = group.export_group_context().clone();
    let aad = TransientMessageAad {
        protocol_version: TntProtocolVersion(PROTOCOL_VERSION),
        wire_format: TRANSIENT_MESSAGE_WIRE_FORMAT,
        sender,
        counter,
        group_context: group_context.clone(),
    };
    let aad_bytes = aad.tls_serialize_detached().unwrap();
    let sender_bytes = sender.tls_serialize_detached().unwrap();
    let counter_bytes = counter.tls_serialize_detached().unwrap();
    let ciphersuite = group.ciphersuite();

    let nonce_secret = group
        .export_secret(
            backend,
            NONCE_SECRET_LABEL,
            &sender_bytes,
            ciphersuite.hash_length(),
        )
        .unwrap();
    let nonce = backend
        .crypto()
        .hkdf_expand(
            ciphersuite.hash_algorithm(),
            &nonce_secret,
            &counter_bytes,
            ciphersuite.aead_nonce_length(),
        )
        .unwrap();
    let secret_key = group
        .export_secret(
            backend,
            SECRET_KEY_LABEL,
            &sender_bytes,
            ciphersuite.aead_key_length(),
        )
        .unwrap();

    let mut plaintext = VLBytes::from(text).tls_serialize_detached().unwrap();
    plaintext.resize(plaintext.len().next_multiple_of(PADDING_SIZE), 0);
    let payload = backend
        .crypto()
        .aead_encrypt(
            ciphersuite.aead_algorithm(),
            &secret_key,
            &plaintext,
            nonce.as_slice(),
            &aad_bytes,
        )
        .unwrap();

    let tbs = TntMessageTbs {
        protocol_version: TntProtocolVersion(PROTOCOL_VERSION),
        body: TntMessageBody::Transient(TransientMessage {
            sender,
            counter,
            group_context,
            payload,
        }),
    };
    tbs.sign(credentials.keys())
        .unwrap()
        .tls_serialize_detached()
        .unwrap()
}
