mod backend;
mod keystore;

use serde_json::json;

use futures_lite::future;
use openmls::prelude::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use backend::TestBackend;

use clap::{Parser, Subcommand};
use io::Read;
use io::Write;
use std::fs;
use std::io;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug)]
struct ClientId {
    user: String,
    client: String,
    domain: String,
}

impl core::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let dom_index = s.find('@').ok_or("No domain separator")?;
        let cli_index =
            s[0..dom_index].find(':').ok_or("No client ID separator")?;
        Ok(ClientId {
            user: s[0..cli_index].to_string(),
            client: s[cli_index + 1..dom_index].to_string(),
            domain: s[dom_index + 1..].to_string(),
        })
    }
}

impl ClientId {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.user.bytes());
        out.push(b':');
        out.extend(self.client.bytes());
        out.push(b'@');
        out.extend(self.domain.bytes());
        out
    }

    fn to_x509(&self, handle: &str) -> String {
        let uuid = Uuid::parse_str(&self.user).unwrap();
        let uid =
            base64::encode_config(uuid.into_bytes(), base64::URL_SAFE_NO_PAD);
        format!(
            "subjectAltName=URI:wireapp://{}%21{}@{}, URI:wireapp://%40{}@{}",
            uid, self.client, self.domain, handle, self.domain
        )
    }
}

#[derive(Debug)]
enum CredentialType {
    Basic,
    X509,
}

impl core::str::FromStr for CredentialType {
    type Err = String;

    fn from_str(x: &str) -> Result<Self, String> {
        match x {
            "basic" => Ok(Self::Basic),
            "x509" => Ok(Self::X509),
            _ => Err(format!("Invalid credential type {}", x)),
        }
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

    fn new(
        backend: &impl OpenMlsCryptoProvider,
        credential_type: CredentialType,
        client_id: ClientId,
        ciphersuite: Ciphersuite,
        handle: Option<String>,
    ) -> Self {
        let keys = SignatureKeyPair::new(
            ciphersuite.signature_algorithm(),
            &mut *backend.rand().borrow_rand().unwrap(),
        )
        .unwrap();
        let credential = match credential_type {
            CredentialType::Basic => Credential::new_basic(client_id.to_vec()),
            CredentialType::X509 => {
                // generate a self-signed certificate
                let handle = handle.unwrap_or(client_id.user.clone());
                let subject = format!("/O={}/CN={}", client_id.domain, handle);
                let san = client_id.to_x509(&handle);
                let openssl = std::process::Command::new("openssl")
                    .args([
                        "req",
                        "-new",
                        "-x509",
                        "-nodes",
                        "-days",
                        "3650",
                        "-key",
                        "/dev/stdin",
                        "-keyform",
                        "DER",
                        "-out",
                        "/dev/stdout",
                        "-keyout",
                        "/dev/null",
                        "-outform",
                        "DER",
                        "-subj",
                        &subject,
                        "-addext",
                        &san,
                    ])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut stdin = openssl.stdin.as_ref().unwrap();
                // add hardcoded pkcs8 envelope
                stdin.write_all(b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20")
                    .unwrap();
                stdin.write_all(keys.private()).unwrap();
                let out = openssl.wait_with_output().unwrap();
                if !out.status.success() {
                    panic!(
                        "openssl failed: {}",
                        core::str::from_utf8(&out.stderr).unwrap()
                    );
                }
                let cert = out.stdout;
                Credential::new_x509(vec![cert.clone(), cert]).unwrap()
            }
        };
        Self { credential, keys }
    }

    fn store(&self, backend: &TestBackend) {
        backend
            .key_store()
            .store_value(b"self", &(&self.keys, &self.credential))
            .unwrap();
    }

    fn read(backend: &TestBackend) -> Self {
        let ks = backend.key_store();
        let (keys, credential) = ks
            .read_value(b"self")
            .ok()
            .flatten()
            .expect("Credential not initialised. Please run `init` first.");
        Self { credential, keys }
    }
}

#[derive(Parser, Debug)]
#[clap(name = "mls-test-cli", version = env!("CARGO_PKG_VERSION"))]
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
        #[clap(short = 't', long, default_value = "basic")]
        credential_type: CredentialType,
        #[clap(short, long, default_value = "0x0001")]
        ciphersuite: String,
        #[clap(long)]
        handle: Option<String>,
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
        #[clap(short, long, default_value = "0x0001")]
        ciphersuite: String,
    },
    /// Create a commit that references all pending proposals
    Commit {
        #[clap(short, long)]
        group: String,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(long)]
        group_info_out: Option<String>,
        #[clap(short, long, conflicts_with = "group-out")]
        in_place: bool,
        #[clap(short, long)]
        welcome_out: Option<String>,
    },
    /// Create an external commit
    ExternalCommit {
        #[clap(long)]
        group_info_in: String,
        #[clap(long)]
        group_info_out: Option<String>,
        #[clap(long)]
        group_out: Option<String>,
        #[clap(short, long, default_value = "0x0001")]
        ciphersuite: String,
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
        #[clap(short, long, default_value = "0x0001")]
        ciphersuite: String,
    },
    /// Compute the hash of a key package.
    Ref { key_package: String },
}

#[derive(Subcommand, Debug)]
enum GroupCommand {
    Create {
        group_id: String,
        #[clap(short, long)]
        removal_key: Option<String>,
        #[clap(short, long, default_value = "-")]
        group_out: String,
        #[clap(short, long, default_value = "0x0001")]
        ciphersuite: String,
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
        group_info_out: Option<String>,
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
        group_info_out: Option<String>,
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
    /// Create a re-init proposal
    ReInit { ciphersuite: Option<String> },
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

fn path_writer(path: &str) -> io::Result<Box<dyn Write>> {
    if path == "-" {
        Ok(Box::new(io::stdout()))
    } else {
        Ok(Box::new(fs::File::create(path)?))
    }
}

fn save_group<W: Write>(group: &MlsGroup, mut writer: W) {
    let json = serde_json::to_string_pretty(&group).unwrap();
    writer.write_all(&json.into_bytes()).unwrap();
}

fn load_group<R: Read>(reader: R) -> MlsGroup {
    #[allow(deprecated)]
    let group: SerializedMlsGroup = serde_json::from_reader(reader).unwrap();
    group.into()
}

fn group_id_from_str(group_id: &str) -> GroupId {
    let group_id =
        base64::decode(group_id).expect("Failed to decode group_id as base64");
    GroupId::from_slice(&group_id)
}

fn build_configuration(
    external_senders: Vec<ExternalSender>,
    ciphersuite: Ciphersuite,
) -> MlsGroupConfig {
    MlsGroupConfig::builder()
        .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(3)
        .padding_size(16)
        .number_of_resumption_psks(1)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 5))
        .use_ratchet_tree_extension(true)
        .external_senders(external_senders)
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build()
}

fn parse_ciphersuite(s: &str) -> Result<Ciphersuite, String> {
    let s = s.trim_start_matches("0x");
    let n = u16::from_str_radix(s, 16).map_err(|e| e.to_string())?;
    Ciphersuite::try_from(n).map_err(|e| e.to_string())
}

async fn new_key_package(
    backend: &TestBackend,
    _lifetime: Option<u64>,
    ciphersuite: Ciphersuite,
) -> KeyPackage {
    let cred_bundle = CredentialBundle::read(backend);
    // TODO: set lifetime
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
        .await
        .unwrap()
}

async fn run() {
    let cli = Cli::parse();
    let backend = TestBackend::new(PathBuf::from(&cli.store)).unwrap();
    match cli.command {
        Command::Init {
            client_id,
            credential_type,
            ciphersuite,
            handle,
        } => {
            let ciphersuite = parse_ciphersuite(&ciphersuite).unwrap();
            let ks = backend.key_store();
            match ks.read_value::<serde_json::Value>(b"self").unwrap() {
                Some(_) => {
                    panic!("Credential already initialised");
                }
                None => {
                    CredentialBundle::new(
                        &backend,
                        credential_type,
                        client_id,
                        ciphersuite,
                        handle,
                    )
                    .store(&backend);
                }
            }
        }
        Command::KeyPackage {
            command:
                KeyPackageCommand::Create {
                    lifetime,
                    ciphersuite,
                },
        } => {
            let ciphersuite = parse_ciphersuite(&ciphersuite).unwrap();
            let key_package =
                new_key_package(&backend, lifetime, ciphersuite).await;

            // output key package to standard output
            key_package.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Show {
            command: ShowCommand::Message { file },
        } => {
            let message = {
                let mut data = path_reader(&file).unwrap();
                MlsMessageIn::tls_deserialize(&mut data).unwrap()
            };
            match message.extract() {
                MlsMessageInBody::PublicMessage(pmsg) => {
                    let v = serde_json::to_value(&pmsg).unwrap();
                    let obj = json!({ "type": "public_message",
                                      "message": v });
                    serde_json::to_writer_pretty(io::stdout(), &obj).unwrap();
                }
                MlsMessageInBody::PrivateMessage(_) => {
                    let obj = json!({ "type": "private_message" });
                    serde_json::to_writer_pretty(io::stdout(), &obj).unwrap();
                }
                MlsMessageInBody::Welcome(_) => {
                    let obj = json!({ "type": "welcome" });
                    serde_json::to_writer_pretty(io::stdout(), &obj).unwrap();
                }
                MlsMessageInBody::GroupInfo(_) => {
                    let obj = json!({ "type": "group_info" });
                    serde_json::to_writer_pretty(io::stdout(), &obj).unwrap();
                }
                MlsMessageInBody::KeyPackage(kp) => {
                    let v = serde_json::to_value(&kp).unwrap();
                    let obj = json!({ "type": "key_package",
                                      "message": v });
                    serde_json::to_writer_pretty(io::stdout(), &obj).unwrap();
                }
            }
        }
        Command::Show {
            command: ShowCommand::KeyPackage { file },
        } => {
            let kp = {
                let mut data = path_reader(&file).unwrap();
                let key_package =
                    KeyPackageIn::tls_deserialize(&mut data).unwrap();
                key_package
                    .validate(backend.crypto(), ProtocolVersion::Mls10)
                    .unwrap()
            };
            serde_json::to_writer_pretty(io::stdout(), &kp).unwrap();
        }
        Command::KeyPackage {
            command: KeyPackageCommand::Ref { key_package },
        } => {
            let mut data = path_reader(&key_package).unwrap();
            let key_package = KeyPackageIn::tls_deserialize(&mut data).unwrap();
            let key_package = key_package
                .validate(backend.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            io::stdout()
                .write_all(
                    key_package.hash_ref(backend.crypto()).unwrap().as_slice(),
                )
                .unwrap();
        }
        Command::PublicKey => {
            let cred_bundle = CredentialBundle::read(&backend);
            let bytes = cred_bundle.keys.public();
            io::stdout().write_all(bytes).unwrap();
        }
        Command::Group {
            command:
                GroupCommand::Create {
                    group_id,
                    removal_key,
                    group_out,
                    ciphersuite,
                },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let group_id = group_id_from_str(&group_id);
            let backend_credential = Credential::new_basic(b"backend".to_vec());
            let external_senders = match removal_key {
                Some(removal_key) => {
                    let removal_key = {
                        let mut reader = path_reader(&removal_key).unwrap();
                        let mut data = Vec::new();
                        reader.read_to_end(&mut data).unwrap();
                        SignaturePublicKey::from(data)
                    };
                    let backend_sender =
                        ExternalSender::new(removal_key, backend_credential);
                    vec![backend_sender]
                }
                None => vec![],
            };
            let ciphersuite = parse_ciphersuite(&ciphersuite).unwrap();
            let group_config =
                build_configuration(external_senders, ciphersuite);

            let group = MlsGroup::new_with_group_id(
                &backend,
                &cred_bundle.keys,
                &group_config,
                group_id,
                cred_bundle.credential_with_key(),
            )
            .await
            .unwrap();

            save_group(&group, &mut path_writer(&group_out).unwrap());
        }
        Command::Group {
            command: GroupCommand::FromWelcome { welcome, group_out },
        } => {
            let message = MlsMessageIn::tls_deserialize(
                &mut path_reader(&welcome).unwrap(),
            )
            .unwrap();

            let welcome = match message.extract() {
                MlsMessageInBody::Welcome(welcome) => welcome,
                _ => {
                    panic!("expected welcome")
                }
            };

            let ciphersuite = welcome.ciphersuite();
            let group_config = build_configuration(vec![], ciphersuite);

            let group = MlsGroup::new_from_welcome(
                &backend,
                &group_config,
                welcome,
                None,
            )
            .await
            .unwrap();
            let mut group_out = fs::File::create(group_out).unwrap();
            save_group(&group, &mut group_out);
        }
        Command::Member {
            command:
                MemberCommand::Add {
                    group: group_in,
                    key_packages,
                    welcome_out,
                    group_out,
                    group_info_out,
                    in_place,
                },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                load_group(data)
            };
            let kps = key_packages
                .into_iter()
                .map(|kp| {
                    let mut data = path_reader(&kp).expect(&format!(
                        "Could not open key package file: {}",
                        kp
                    ));
                    let kp = KeyPackageIn::tls_deserialize(&mut data).unwrap();
                    kp.validate(backend.crypto(), ProtocolVersion::Mls10)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            let (handshake, welcome, group_info) = if kps.is_empty() {
                group
                    .commit_to_pending_proposals(&backend, &cred_bundle.keys)
                    .await
                    .unwrap()
            } else {
                let (commit, welcome, group_info) = group
                    .add_members(&backend, &cred_bundle.keys, &kps)
                    .await
                    .unwrap();
                (commit, Some(welcome), group_info)
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
                group.merge_pending_commit(&backend).await.unwrap();
                save_group(&group, &mut writer);
            }

            if let (Some(group_info_out), Some(group_info)) =
                (group_info_out, group_info)
            {
                let mut writer = fs::File::create(group_info_out).unwrap();
                group_info.tls_serialize(&mut writer).unwrap();
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
                    group_info_out,
                    in_place,
                },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                load_group(data)
            };

            let indices = indices
                .into_iter()
                .map(LeafNodeIndex::new)
                .collect::<Vec<_>>();

            let (commit, welcome, group_info) = group
                .remove_members(&backend, &cred_bundle.keys, &indices[..])
                .await
                .unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit(&backend).await.unwrap();
                save_group(&group, &mut writer);
            }

            if let Some(welcome_out) = welcome_out {
                if let Some(welcome) = welcome {
                    let mut writer = fs::File::create(welcome_out).unwrap();
                    welcome.tls_serialize(&mut writer).unwrap();
                }
            }

            if let (Some(group_info_out), Some(group_info)) =
                (group_info_out, group_info)
            {
                let mut writer = fs::File::create(group_info_out).unwrap();
                group_info.tls_serialize(&mut writer).unwrap();
            }

            commit.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Message { group, text } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group).unwrap();
                load_group(data)
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
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                load_group(data)
            };
            let key_package = {
                let mut data = path_reader(&key_package).unwrap();
                let kp = KeyPackageIn::tls_deserialize(&mut data).unwrap();
                kp.validate(backend.crypto(), ProtocolVersion::Mls10)
                    .unwrap()
            };
            let (message, _) = group
                .propose_add_member(&backend, &cred_bundle.keys, &key_package)
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                save_group(&group, &mut writer);
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
                load_group(data)
            };
            let message = group
                .propose_remove_member(&backend, &cred_bundle.keys, index)
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                save_group(&group, &mut writer);
            }
        }
        Command::Proposal {
            group_in,
            group_out,
            in_place,
            command: ProposalCommand::ReInit { ciphersuite },
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                load_group(data)
            };
            let ciphersuite = match ciphersuite {
                Some(ciphersuite) => parse_ciphersuite(&ciphersuite).unwrap(),
                None => group.ciphersuite(),
            };
            let (message, _) = group
                .propose_reinit(
                    &backend,
                    &cred_bundle.keys,
                    Extensions::empty(),
                    ciphersuite,
                    ProtocolVersion::Mls10,
                )
                .unwrap();
            message.tls_serialize(&mut io::stdout()).unwrap();

            let group_out = if in_place { Some(group_in) } else { group_out };
            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                save_group(&group, &mut writer);
            }
        }
        Command::ExternalProposal {
            group_id,
            epoch,
            command: ExternalProposalCommand::Add {},
            ciphersuite,
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let ciphersuite = parse_ciphersuite(&ciphersuite).unwrap();
            let key_package =
                new_key_package(&backend, None, ciphersuite).await;
            let group_id = group_id_from_str(&group_id);
            let proposal = JoinProposal::new(
                key_package,
                group_id,
                GroupEpoch::from(epoch),
                &cred_bundle.keys,
            )
            .unwrap();
            proposal.tls_serialize(&mut io::stdout()).unwrap();
        }
        Command::Commit {
            group: group_in,
            group_out,
            group_info_out,
            in_place,
            welcome_out,
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let mut group = {
                let data = path_reader(&group_in).unwrap();
                load_group(data)
            };

            let (message, welcome, group_info) = group
                .commit_to_pending_proposals(&backend, &cred_bundle.keys)
                .await
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
                group.merge_pending_commit(&backend).await.unwrap();
                save_group(&group, &mut writer);
            }

            if let (Some(group_info_out), Some(group_info)) =
                (group_info_out, group_info)
            {
                let mut writer = fs::File::create(group_info_out).unwrap();
                group_info.tls_serialize(&mut writer).unwrap();
            }
        }
        Command::ExternalCommit {
            group_info_in,
            group_info_out,
            group_out,
            ciphersuite,
        } => {
            let cred_bundle = CredentialBundle::read(&backend);
            let group_info = {
                let mut data = path_reader(&group_info_in).unwrap();
                VerifiableGroupInfo::tls_deserialize(&mut data).unwrap()
            };

            let ciphersuite = parse_ciphersuite(&ciphersuite).unwrap();
            let (mut group, message, group_info) =
                MlsGroup::join_by_external_commit(
                    &backend,
                    &cred_bundle.keys,
                    None,
                    group_info,
                    &build_configuration(vec![], ciphersuite),
                    &[],
                    cred_bundle.credential_with_key(),
                )
                .await
                .unwrap();

            message.tls_serialize(&mut io::stdout()).unwrap();

            if let Some(group_out) = group_out {
                let mut writer = fs::File::create(group_out).unwrap();
                group.merge_pending_commit(&backend).await.unwrap();
                save_group(&group, &mut writer);
            }

            if let (Some(group_info_out), Some(group_info)) =
                (group_info_out, group_info)
            {
                let mut writer = fs::File::create(group_info_out).unwrap();
                group_info.tls_serialize(&mut writer).unwrap();
            }
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
                load_group(data)
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
            let message = group.process_message(&backend, pmsg).await.unwrap();

            // store proposal or apply commit
            match message.into_content() {
                ProcessedMessageContent::ApplicationMessage(_) => {}
                ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                    group.store_pending_proposal(*staged_proposal);
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    group
                        .merge_staged_commit(&backend, *staged_commit)
                        .await
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
                save_group(&group, &mut writer);
            }
        }
    }
}

fn main() {
    future::block_on(run());
}
