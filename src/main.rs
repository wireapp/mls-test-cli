mod backend;
mod keystore;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use backend::TestBackend;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;

#[derive(Debug)]
struct ClientId(Vec<u8>);

impl core::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(ClientId(s.as_bytes().to_vec()))
    }
}

#[derive(Debug)]
struct CredentialBundle {
    credential: Credential,
    keys: SignatureKeyPair,
}

impl CredentialBundle {
    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.credential.clone(),
            signature_key: self.keys.public().into(),
        }
    }

    fn new(client_id: ClientId) -> Self {
        let credential =
            Credential::new(client_id.0, CredentialType::Basic).unwrap();
        let keys = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        Self { credential, keys }
    }

    fn store(&self, backend: &TestBackend) {
        let ks = backend.key_store();
        let mut out = ks.store_bytes(b"self").unwrap();
        self.credential.tls_serialize(&mut out).unwrap();
        self.keys.tls_serialize(&mut out).unwrap();
    }

    fn read(backend: &TestBackend) -> Self {
        let ks = backend.key_store();
        let mut input = ks
            .read_bytes(b"self")
            .expect("Credential not initialised. Please run `init` first.");
        let credential = Credential::tls_deserialize(&mut input).unwrap();
        let keys = SignatureKeyPair::tls_deserialize(&mut input).unwrap();
        Self { credential, keys }
    }
}

// impl TlsDeserializeTrait for CredentialBundle {
//     fn tls_deserialize<R: Read>(
//         bytes: &mut R,
//     ) -> Result<Self, tls_codec::Error> {
//         let credential = Credential::tls_deserialize(bytes)?;
//         let keys = SignatureKeyPair::tls_deserialize(bytes)?;
//         Self { credential, keys }
//     }
// }

// impl TlsSerializeTrait for CredentialBundle {
//     fn tls_serialize<W: Write>(
//         &self,
//         writer: &mut W,
//     ) -> Result<usize, tls_codec::Error> {
//         let mut written = self.credential.tls_serialize(writer)?;
//         written += self.keys.tls_serialize(writer)?;
//         Ok(written)
//     }
// }

#[derive(Parser, Debug)]
#[clap(name = "mls-test-cli", version = env!("FULL_VERSION"))]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init {
        client_id: ClientId,
    },
    Show {
        #[clap(subcommand)]
        command: ShowCommand,
    },
    KeyPackage {
        #[clap(subcommand)]
        command: KeyPackageCommand,
    },
    PublicKey,
    Group {
        #[clap(subcommand)]
        command: GroupCommand,
    },
    Member {
        #[clap(subcommand)]
        command: MemberCommand,
    },
    Message {
        #[clap(short, long)]
        group: String,
        text: String,
    },
    Proposal {
        #[clap(short, long)]
        group_in: String,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
        #[clap(subcommand)]
        command: ProposalCommand,
    },
    ExternalProposal {
        #[clap(short, long)]
        group_id: String,
        #[clap(short, long)]
        epoch: u64,
        #[clap(subcommand)]
        command: ExternalProposalCommand,
    },
    /// Create a commit that references all pending proposals
    Commit {
        #[clap(short, long)]
        group: String,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(long)]
        group_state_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
        #[clap(short, long)]
        welcome_out: Option<String>,
    },
    /// Create an external commit
    ExternalCommit {
        #[clap(long)]
        group_state_in: String,
        #[clap(long)]
        group_state_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
    },
    /// Receive and store an incoming message.
    Consume {
        #[clap(short, long)]
        group: String,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
        /// The public key used to sign the message. This is only used for external senders.
        /// Signatures of messages originating from members are not verified at the moment, so this
        /// option is ignored in those cases.
        #[clap(short, long)]
        signer_key: Option<String>,
        message: String,
    },
}

#[derive(Subcommand, Debug)]
enum ShowCommand {
    Message { file: String },
    KeyPackage { file: String },
}

#[derive(Subcommand, Debug)]
enum KeyPackageCommand {
    /// Create a new key package and save it in the store.
    Create {
        /// How long in seconds will the key package be valid
        #[clap(short, long)]
        lifetime: Option<u64>,
    },
    /// Compute the hash of a key package.
    Ref { key_package: String },
}

#[derive(Subcommand, Debug)]
enum GroupCommand {
    Create {
        group_id: String,
    },
    FromWelcome {
        welcome: String,
        #[clap(long)]
        group_out: String,
    },
}

#[derive(Subcommand, Debug)]
enum MemberCommand {
    Add {
        #[clap(short, long)]
        group: String,
        key_packages: Vec<String>,
        #[clap(short, long)]
        welcome_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(long)]
        group_state_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
    Remove {
        #[clap(short, long)]
        group: String,
        indices: Vec<u32>,
        #[clap(short, long)]
        welcome_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(long)]
        group_state_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ProposalCommand {
    /// Create an add proposal
    Add { key_package: String },
    /// Create a remove proposal
    Remove { index: u32 },
}

#[derive(Subcommand, Debug)]
enum ExternalProposalCommand {
    /// Create an add proposal
    Add {},
}

fn path_reader(path: &str) -> io::Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(fs::File::open(path)?))
    }
}

fn default_configuration() -> MlsGroupConfig {
    MlsGroupConfig::builder()
        .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .padding_size(16)
        .number_of_resumption_psks(1)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 5))
        .use_ratchet_tree_extension(true)
        .build()
}

fn new_key_package(
    backend: &TestBackend,
    _lifetime: Option<u64>,
) -> KeyPackage {
    let cred_bundle = CredentialBundle::read(backend);
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &cred_bundle.keys,
            cred_bundle.credential_with_key(),
        )
        .unwrap()
}

fn main() {
    let cli = Cli::parse();
    let backend = TestBackend::new(&cli.store).unwrap();
    match cli.command {
        Command::Init { client_id } => {
            let ks = backend.key_store();
            match ks.read::<SignatureKeyPair>(b"self") {
                Some(_) => {
                    panic!("Credential already initialised");
                }
                None => {
                    CredentialBundle::new(client_id).store(&backend);
                }
            }
        }
        Command::KeyPackage {
            command: KeyPackageCommand::Create { lifetime },
        } => {
            let key_package_bundle = new_key_package(&backend, lifetime);

            // output key package to standard output
            key_package_bundle.tls_serialize(&mut io::stdout()).unwrap();
        }

        Command::Show {
            command: ShowCommand::Message { file },
        } => {
            let message = {
                let mut data = path_reader(&file).unwrap();
                MlsMessageIn::tls_deserialize(&mut data).unwrap()
            };
            println!("{:#?}", message);
        }
        Command::Show {
            command: ShowCommand::KeyPackage { file },
        } => {
            let kp = {
                let mut data = path_reader(&file).unwrap();
                KeyPackage::tls_deserialize(&mut data).unwrap()
            };
            println!("{:#?}", kp);
        }
        Command::KeyPackage {
            command: KeyPackageCommand::Ref { key_package },
        } => {
            let mut kp_data = path_reader(&key_package).unwrap();
            let kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
            io::stdout()
                .write_all(kp.hash_ref(backend.crypto()).unwrap().as_slice())
                .unwrap();
        }
        Command::PublicKey => {
            let cred_bundle = CredentialBundle::read(&backend);
            let bytes = cred_bundle.keys.public();
            io::stdout().write_all(bytes).unwrap();
        }
        Command::Group {
            command: GroupCommand::Create { group_id },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let group_id = base64::decode(group_id)
                .expect("Failed to decode group_id as base64");
            let group_id = GroupId::from_slice(&group_id);
            let group_config = default_configuration();

            let mut group = MlsGroup::new_with_group_id(
                &backend,
                &cred_bundle.keys,
                &group_config,
                group_id,
                cred_bundle.credential_with_key(),
            )
            .unwrap();
            group.save(&mut io::stdout()).unwrap();
        }
        Command::Group {
            command: GroupCommand::FromWelcome { welcome, group_out },
        } => {
            let group_config = default_configuration();
            let welcome =
                Welcome::tls_deserialize(&mut path_reader(&welcome).unwrap())
                    .unwrap();
            let mut group = MlsGroup::new_from_welcome(
                &backend,
                &group_config,
                welcome,
                None,
            )
            .unwrap();
            let mut group_out = fs::File::create(group_out).unwrap();
            group.save(&mut group_out).unwrap();
        }
        Command::Member {
            command:
                MemberCommand::Add {
                    group: group_in,
                    key_packages,
                    welcome_out,
                    group_out,
                    group_state_out,
                    in_place,
                },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };
            let kps = key_packages
                .into_iter()
                .map(|kp| {
                    let mut data = path_reader(&kp).expect(&format!(
                        "Could not open key package file: {}",
                        kp
                    ));
                    KeyPackage::tls_deserialize(&mut data).unwrap()
                })
                .collect::<Vec<_>>();

            let (handshake, welcome, group_state) = if kps.is_empty() {
                group
                    .commit_to_pending_proposals(&backend, &cred_bundle.keys)
                    .unwrap()
            } else {
                let (commit, welcome, group_state) = group
                    .add_members(&backend, &cred_bundle.keys, &kps)
                    .unwrap();
                (commit, Some(welcome), group_state)
            };

            match (welcome_out, welcome) {
                (Some(welcome_out), Some(welcome)) => {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }
                _ => {}
            }
            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit(&backend).unwrap();
                group.save(&mut writer).unwrap();
            }

            if let Some(group_state_out) = group_state_out {
                let mut writer = fs::File::create(group_state_out).unwrap();
                group_state.tls_serialize(&mut writer).unwrap();
            }

            handshake.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Member {
            command:
                MemberCommand::Remove {
                    group: group_in,
                    indices,
                    welcome_out,
                    group_out,
                    group_state_out,
                    in_place,
                },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };

            let indices = indices
                .into_iter()
                .map(LeafNodeIndex::new)
                .collect::<Vec<_>>();

            let (commit, welcome, group_state) = group
                .remove_members(&backend, &cred_bundle.keys, &indices[..])
                .unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit(&backend).unwrap();
                group.save(&mut writer).unwrap();
            }

            if let Some(welcome_out) = welcome_out {
                if let Some(welcome) = welcome {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }
            }

            if let Some(group_state_out) = group_state_out {
                let mut writer = fs::File::create(group_state_out).unwrap();
                group_state.tls_serialize(&mut writer).unwrap();
            }

            commit.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Message { group, text } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group).unwrap();
                MlsGroup::load(data).unwrap()
            };
            let message = group
                .create_message(&backend, &cred_bundle.keys, text.as_bytes())
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Proposal {
            group_in,
            group_out,
            in_place,
            command: ProposalCommand::Add { key_package },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let key_package = {
                let mut data = path_reader(&key_package).unwrap();
                KeyPackage::tls_deserialize(&mut data).unwrap()
            };
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };
            let message = group
                .propose_add_member(&backend, &cred_bundle.keys, &key_package)
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.save(&mut writer).unwrap();
            }
        }
        Command::Proposal {
            group_in,
            group_out,
            in_place,
            command: ProposalCommand::Remove { index },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let index = LeafNodeIndex::new(index);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };
            let message = group
                .propose_remove_member(&backend, &cred_bundle.keys, index)
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.save(&mut writer).unwrap();
            }
        }
        Command::ExternalProposal {
            group_id: _,
            epoch: _,
            command: ExternalProposalCommand::Add {},
        } => {
            // TODO
        }
        Command::Commit {
            group: group_in,
            group_out,
            group_state_out,
            in_place,
            welcome_out,
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };

            let (message, welcome, group_state) = group
                .commit_to_pending_proposals(&backend, &cred_bundle.keys)
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            if let Some(welcome_out) = welcome_out {
                if let Some(welcome) = welcome {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }
            }

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit(&backend).unwrap();
                group.save(&mut writer).unwrap();
            }

            if let Some(group_state_out) = group_state_out {
                let mut writer = fs::File::create(group_state_out).unwrap();
                group_state.tls_serialize(&mut writer).unwrap();
            }
        }
        Command::ExternalCommit {
            group_state_in: _,
            group_state_out: _,
            group_out: _,
        } => {
            // TODO
        }
        Command::Consume {
            group: group_in,
            group_out,
            in_place,
            message,
            signer_key: _,
        } => {
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                MlsGroup::load(data).unwrap()
            };

            // parse and verify message
            let msg_in = {
                let mut data = path_reader(&message).unwrap();
                MlsMessageIn::tls_deserialize(&mut data).unwrap()
            };

            // TODO: read signer key if necessary

            let pmsg: ProtocolMessage = match msg_in.extract() {
                MlsMessageInBody::PrivateMessage(m) => m.into(),
                MlsMessageInBody::PublicMessage(m) => m.into(),
                _ => panic!("Unexpected message type"),
            };
            let message = group.process_message(&backend, pmsg).unwrap();

            // store proposal or apply commit
            match message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => {}
                ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                    group.store_pending_proposal(*staged_proposal);
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    group
                        .merge_staged_commit(&backend, *staged_commit)
                        .expect("Could not merge commit");
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(
                    staged_proposal,
                ) => {
                    group.store_pending_proposal(*staged_proposal);
                }
            }

            // save new group state
            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.save(&mut writer).unwrap();
            }
        }
    }
}
