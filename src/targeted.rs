use openmls::{
    group::{group_context::GroupContext, GroupEpoch, GroupId, MlsGroup},
    prelude::{HpkeCiphertext, LeafNodeIndex, Signable},
};
use openmls_traits::{
    random::OpenMlsRand,
    types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
    OpenMlsCryptoProvider,
};
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};

use crate::credential::CredentialBundle;

const PROTOCOL_VERSION: u16 = 1;
const PADDING_SIZE: usize = 128;
const PSK_LABEL: &str = "Tnt TargetedMessage Psk v1";
const SIGN_LABEL_PERSISTED: &str = "TntMessageTBS-Persisted-Targeted v1";
const SIGN_LABEL_TRANSIENT: &str = "TntMessageTBS-Transient-Targeted v1";

#[derive(Clone, Copy, TlsSize, TlsSerialize)]
#[repr(transparent)]
struct TntProtocolVersion(u16);

#[derive(TlsSize, TlsSerialize)]
#[repr(u16)]
enum TntMessageBody {
    #[tls_codec(discriminant = 0xF001)]
    Targeted(TargetedMessage),
    #[tls_codec(discriminant = 0xF002)]
    TransientTargeted(TargetedMessage),
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
        match &self.body {
            TntMessageBody::Targeted(_) => SIGN_LABEL_PERSISTED,
            TntMessageBody::TransientTargeted(_) => SIGN_LABEL_TRANSIENT,
        }
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
struct TargetedMessageContext {
    protocol_version: TntProtocolVersion,
    policy: TargetedMessagePolicy,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    group_context: GroupContext,
}

#[derive(Clone, Copy, TlsSize, TlsSerialize)]
#[repr(u8)]
pub(crate) enum TargetedMessagePolicy {
    Transient,
    Persisted,
}

#[derive(TlsSize, TlsSerialize)]
struct PskId {
    group_id: GroupId,
    epoch: GroupEpoch,
}

#[derive(TlsSize, TlsSerialize)]
struct TargetedMessage {
    counter: u32,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    recipient_id: VLBytes,
    epoch: GroupEpoch,
    group_id: GroupId,
    payload: HpkeCiphertext,
}

pub(crate) fn create_targeted_message(
    backend: &impl OpenMlsCryptoProvider,
    credentials: &CredentialBundle,
    group: &MlsGroup,
    counter: u32,
    recipient: u32,
    policy: TargetedMessagePolicy,
    text: &[u8],
) -> Vec<u8> {
    let recipient_index = LeafNodeIndex::new(recipient);
    let recipient_member = group
        .members()
        .find(|member| member.index == recipient_index)
        .unwrap_or_else(|| panic!("No group member with leaf index {recipient}"));
    let sender = group.own_leaf_index();
    let context = TargetedMessageContext {
        protocol_version: TntProtocolVersion(PROTOCOL_VERSION),
        policy,
        sender,
        recipient: recipient_index,
        group_context: group.export_group_context().clone(),
    };
    let info = context.tls_serialize_detached().unwrap();
    let psk = group
        .export_secret(backend, PSK_LABEL, &[], group.ciphersuite().hash_length())
        .unwrap();
    let psk_id = PskId {
        group_id: group.group_id().clone(),
        epoch: group.epoch(),
    }
    .tls_serialize_detached()
    .unwrap();
    let aad = counter.tls_serialize_detached().unwrap();

    let mut plaintext = VLBytes::from(text).tls_serialize_detached().unwrap();
    let padded_len = ((plaintext.len() + PADDING_SIZE - 1) / PADDING_SIZE) * PADDING_SIZE;
    plaintext.resize(padded_len, 0);

    let payload = hpke_seal_psk(
        backend,
        group.ciphersuite().hpke_config(),
        &recipient_member.encryption_key,
        &info,
        &aad,
        &psk,
        &psk_id,
        &plaintext,
    )
    .unwrap();
    let targeted = TargetedMessage {
        counter,
        sender,
        recipient: recipient_index,
        recipient_id: VLBytes::from(recipient_member.credential.identity()),
        epoch: group.epoch(),
        group_id: group.group_id().clone(),
        payload,
    };
    let tbs = TntMessageTbs {
        protocol_version: TntProtocolVersion(PROTOCOL_VERSION),
        body: match policy {
            TargetedMessagePolicy::Transient => TntMessageBody::TransientTargeted(targeted),
            TargetedMessagePolicy::Persisted => TntMessageBody::Targeted(targeted),
        },
    };
    let signed = tbs.sign(credentials.keys()).unwrap();
    signed.tls_serialize_detached().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn hpke_seal_psk(
    backend: &impl OpenMlsCryptoProvider,
    config: HpkeConfig,
    public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, String> {
    use hpke::{Deserializable as _, PskBundle, Serializable as _};

    let mut rng = backend
        .rand()
        .borrow_rand()
        .map_err(|error| format!("obtaining HPKE randomness: {error:?}"))?;

    macro_rules! seal {
        ($aead:ty, $kdf:ty, $kem:ty) => {{
            let key = <$kem as hpke::Kem>::PublicKey::from_bytes(public_key)
                .map_err(|error| format!("decoding HPKE public key: {error:?}"))?;
            let psk = PskBundle { psk, psk_id };
            let (encapped, ciphertext) = hpke::single_shot_seal::<$aead, $kdf, $kem, _>(
                &hpke::OpModeS::Psk(psk),
                &key,
                info,
                plaintext,
                aad,
                &mut *rng,
            )
            .map_err(|error| format!("HPKE encryption: {error:?}"))?;
            Ok(HpkeCiphertext {
                kem_output: encapped.to_bytes().to_vec().into(),
                ciphertext: ciphertext.into(),
            })
        }};
    }

    match config {
        HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
            seal!(
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256
            )
        }
        HpkeConfig(
            HpkeKemType::DhKem25519,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::ChaCha20Poly1305,
        ) => {
            seal!(
                hpke::aead::ChaCha20Poly1305,
                hpke::kdf::HkdfSha256,
                hpke::kem::X25519HkdfSha256
            )
        }
        HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
            seal!(
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
                hpke::kem::DhP256HkdfSha256
            )
        }
        HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
            seal!(
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
                hpke::kem::DhP384HkdfSha384
            )
        }
        HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
            seal!(
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
                hpke::kem::DhP521HkdfSha512
            )
        }
        _ => Err(format!("unsupported HPKE configuration: {config:?}")),
    }
}
