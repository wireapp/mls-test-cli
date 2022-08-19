mod backend;
mod keystore;

use openmls::prelude::*;

use backend::TestBackend;

use clap::{Parser, Subcommand};
use futures_lite::future;
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
        group_in: String,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
        #[clap(subcommand)]
        command: ExternalProposalCommand,
    },
    /// Create a commit that references all propsals that are pending
    Commit {
        #[clap(short, long)]
        group: String,
        #[clap(short, long)]
        welcome_out: Option<String>,
    },
    CheckSignature {
        #[clap(short, long)]
        group: String,
        #[clap(short, long)]
        message: String,
        #[clap(short, long)]
        signer_key: String,
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
        #[clap(long)]
        key_package_out: Option<String>,
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
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
    Remove {
        #[clap(short, long)]
        group: String,
        key_packages: Vec<String>,
        #[clap(short, long)]
        welcome_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ProposalCommand {
    /// Create an add proposal
    Add { key_package: String },
    /// Create a remove proposal
    Remove { key_package_ref: String },
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
        .number_of_resumtion_secrets(1)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 5))
        .use_ratchet_tree_extension(true)
        .build()
}

async fn get_credential_bundle(
    backend: &impl OpenMlsCryptoProvider,
) -> CredentialBundle {
    let ks = backend.key_store();
    match ks.read(b"self").await {
        Some(bundle) => bundle,
        None => {
            panic!("Credential not initialised. Please run `init` first.");
        }
    }
}

async fn new_key_package(
    backend: &impl OpenMlsCryptoProvider,
    lifetime: Option<u64>,
) -> KeyPackageBundle {
    let cred_bundle = get_credential_bundle(backend).await;
    let extensions = match lifetime {
        Some(t) => vec![Extension::LifeTime(LifetimeExtension::new(t))],
        None => vec![],
    };
    let ciphersuites =
        [Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519];
    let kp_bundle =
        KeyPackageBundle::new(&ciphersuites, &cred_bundle, backend, extensions)
            .unwrap();

    // store the key package bundle in the key store
    let key_package = kp_bundle.key_package();
    backend
        .key_store()
        .store(
            key_package.hash_ref(backend.crypto()).unwrap().value(),
            &kp_bundle,
        )
        .await
        .unwrap();

    kp_bundle
}

fn main() {
    let cli = Cli::parse();
    let backend = TestBackend::new(&cli.store).unwrap();
    future::block_on(async move {
        match cli.command {
            Command::Init { client_id } => {
                let ks = backend.key_store();
                match ks.read::<CredentialBundle>(b"self").await {
                    Some(_) => {
                        panic!("Credential already initialised");
                    }
                    None => {
                        let bundle = CredentialBundle::new_basic(
                            client_id.0,
                            SignatureScheme::ED25519,
                            &backend,
                        )
                        .unwrap();
                        ks.store(b"self", &bundle).await.unwrap();
                        // also save credential under its signature key, as openmls assumes it is
                        // located there
                        ks.store(
                            &bundle
                                .credential()
                                .signature_key()
                                .tls_serialize_detached()
                                .unwrap(),
                            &bundle,
                        )
                        .await
                        .unwrap();
                    }
                }
            }
            Command::KeyPackage {
                command: KeyPackageCommand::Create { lifetime },
            } => {
                let key_package_bundle =
                    new_key_package(&backend, lifetime).await;

                // output key package to standard output
                key_package_bundle
                    .key_package()
                    .tls_serialize(&mut io::stdout())
                    .unwrap();
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
                    .write_all(kp.hash_ref(backend.crypto()).unwrap().value())
                    .unwrap();
            }
            Command::PublicKey => {
                let cred_bundle = get_credential_bundle(&backend).await;
                let credential = cred_bundle.credential();
                let bytes = credential.signature_key().as_slice();
                io::stdout().write_all(bytes).unwrap();
            }
            Command::Group {
                command:
                    GroupCommand::Create {
                        group_id,
                        key_package_out,
                    },
            } => {
                let group_id = base64::decode(group_id)
                    .expect("Failed to decode group_id as base64");
                let group_id = GroupId::from_slice(&group_id);
                let group_config = default_configuration();

                let kp_bundle = new_key_package(&backend, None).await;
                let kp = kp_bundle.key_package();

                if let Some(key_package_out) = key_package_out {
                    let mut writer = fs::File::create(key_package_out).unwrap();
                    kp.tls_serialize(&mut writer).unwrap();
                }

                let kp_ref = kp.hash_ref(backend.crypto()).unwrap();
                let kp_hash = kp_ref.value();

                let mut group = MlsGroup::new(
                    &backend,
                    &group_config,
                    group_id,
                    kp_hash.as_slice(),
                )
                .await
                .unwrap();
                group.save(&mut io::stdout()).unwrap();
            }
            Command::Group {
                command: GroupCommand::FromWelcome { welcome, group_out },
            } => {
                let group_config = default_configuration();
                let welcome = Welcome::tls_deserialize(
                    &mut fs::File::open(welcome).unwrap(),
                )
                .unwrap();
                let mut group = MlsGroup::new_from_welcome(
                    &backend,
                    &group_config,
                    welcome,
                    None,
                )
                .await
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
                        in_place,
                    },
            } => {
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
                let (handshake, welcome, _) =
                    group.add_members(&backend, &kps).await.unwrap();

                if let Some(welcome_out) = welcome_out {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }
                let group_out =
                    if in_place { Some(group_in) } else { group_out };
                if let Some(group_out) = group_out {
                    let mut writer = fs::File::create(group_out).unwrap();
                    group.merge_pending_commit().unwrap();
                    group.save(&mut writer).unwrap();
                }
                handshake.tls_serialize(&mut io::stdout()).unwrap();
            }
            Command::Member {
                command:
                    MemberCommand::Remove {
                        group: group_in,
                        key_packages,
                        welcome_out,
                        group_out,
                        in_place,
                    },
            } => {
                let mut group = {
                    let data = path_reader(&group_in).unwrap();
                    MlsGroup::load(data).unwrap()
                };

                let kprefs = key_packages
                    .into_iter()
                    .map(|filename| {
                        let mut data = path_reader(&filename).expect(&format!(
                            "Could not open key package file: {}",
                            filename
                        ));
                        let kp =
                            KeyPackage::tls_deserialize(&mut data).unwrap();
                        kp.hash_ref(backend.crypto()).unwrap()
                    })
                    .collect::<Vec<_>>();

                let (commit, welcome, _) = group
                    .remove_members(&backend, kprefs.as_slice())
                    .await
                    .unwrap();

                let group_out =
                    if in_place { Some(group_in) } else { group_out };
                if let Some(group_out) = group_out {
                    let mut writer = fs::File::create(group_out).unwrap();
                    group.merge_pending_commit().unwrap();
                    group.save(&mut writer).unwrap();
                }

                if let Some(welcome_out) = welcome_out {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }

                commit.tls_serialize(&mut io::stdout()).unwrap();
            }
            Command::Message { group, text } => {
                let mut group = {
                    let data = path_reader(&group).unwrap();
                    MlsGroup::load(data).unwrap()
                };
                let message = group
                    .create_message(&backend, text.as_bytes())
                    .await
                    .unwrap();
                message.tls_serialize(&mut io::stdout()).unwrap();
            }
            Command::Proposal {
                group_in,
                group_out,
                in_place,
                command: ProposalCommand::Add { key_package },
            } => {
                let key_package = {
                    let mut data = path_reader(&key_package).unwrap();
                    KeyPackage::tls_deserialize(&mut data).unwrap()
                };
                let mut group = {
                    let data = path_reader(&group_in).unwrap();
                    MlsGroup::load(data).unwrap()
                };
                let message = group
                    .propose_add_member(&backend, &key_package)
                    .await
                    .unwrap();
                message.tls_serialize(&mut io::stdout()).unwrap();

                let group_out =
                    if in_place { Some(group_in) } else { group_out };
                if let Some(group_out) = group_out {
                    let mut writer = fs::File::create(group_out).unwrap();
                    group.save(&mut writer).unwrap();
                }
            }
            Command::Proposal {
                group_in,
                group_out,
                in_place,
                command: ProposalCommand::Remove { key_package_ref },
            } => {
                let key_package_ref = hash_ref::HashReference::from_slice(
                    &base64::decode(key_package_ref).unwrap(),
                );
                let mut group = {
                    let data = path_reader(&group_in).unwrap();
                    MlsGroup::load(data).unwrap()
                };
                let message = group
                    .propose_remove_member(&backend, &key_package_ref)
                    .await
                    .unwrap();
                message.tls_serialize(&mut io::stdout()).unwrap();

                let group_out =
                    if in_place { Some(group_in) } else { group_out };
                if let Some(group_out) = group_out {
                    let mut writer = fs::File::create(group_out).unwrap();
                    group.save(&mut writer).unwrap();
                }
            }
            Command::ExternalProposal {
                group_in,
                group_out,
                in_place,
                command: ExternalProposalCommand::Add {},
            } => {
                let mut group = {
                    let data = path_reader(&group_in).unwrap();
                    MlsGroup::load(data).unwrap()
                };

                let credential = get_credential_bundle(&backend).await;
                let kp_bundle = new_key_package(&backend, None).await;
                let key_package = kp_bundle.key_package().clone();
                let external_proposal = ExternalProposal::new_add(
                    key_package,
                    group.group_id().clone(),
                    group.epoch(),
                    &credential,
                    &backend,
                )
                .unwrap();

                let group_out =
                    if in_place { Some(group_in) } else { group_out };
                if let Some(group_out) = group_out {
                    let mut writer = fs::File::create(group_out).unwrap();
                    group.save(&mut writer).unwrap();
                }

                external_proposal.tls_serialize(&mut io::stdout()).unwrap();
            }
            Command::Commit { group, welcome_out } => {
                let mut group = {
                    let data = path_reader(&group).unwrap();
                    MlsGroup::load(data).unwrap()
                };

                let (message, welcome, _) =
                    group.commit_to_pending_proposals(&backend).await.unwrap();
                message.tls_serialize(&mut io::stdout()).unwrap();

                if let Some(welcome_out) = welcome_out {
                    if let Some(welcome) = welcome {
                        let mut writer = fs::File::create(welcome_out).unwrap();
                        welcome.tls_serialize(&mut writer).unwrap();
                    }
                }
            }
            Command::CheckSignature { group, message, signer_key } => {
                let mut group = {
                    let data = path_reader(&group).unwrap();
                    MlsGroup::load(data).unwrap()
                };

                let mut public_key_data = Vec::new();
                path_reader(&signer_key).unwrap().read_to_end(&mut public_key_data).unwrap();
                let public_key = SignaturePublicKey::new(public_key_data, SignatureScheme::ED25519).unwrap();

                let mut mdata = path_reader(&message).unwrap();
                let msg_in = MlsMessageIn::tls_deserialize(&mut mdata).unwrap();

                let unverified_message =
                    group.parse_message(msg_in, &backend).unwrap();
                group
                    .process_unverified_message(
                        unverified_message,
                        Some(&public_key),
                        &backend,
                    )
                    .await
                    .unwrap();
            }
        }
    })
}
