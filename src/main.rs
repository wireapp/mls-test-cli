use openmls::prelude::*;
use core_crypto::prelude::*;
use mls_crypto_provider::*;

use clap::{Parser, Subcommand};
use std::io;
use std::fs;
use io::Write;
use io::Read;

fn key_package(backend: &MlsCryptoProvider, client_id: ClientId) {
    let mut client = Client::init(client_id, &backend).unwrap();
    let kp = client.gen_keypackage(&backend).unwrap();
    let mut kp_bytes = Vec::new();
    kp.tls_serialize(&mut kp_bytes).unwrap();
    io::stdout().write_all(&kp_bytes).unwrap();
}

fn public_key(backend: &MlsCryptoProvider, client_id: ClientId) {
    let client = Client::init(client_id, &backend).unwrap();
    let pk = client.public_key();
    io::stdout().write_all(pk).unwrap();
}

fn group(backend: &MlsCryptoProvider, client_id: ClientId, group_id: &[u8]) {
    let mut client = Client::init(client_id, &backend).unwrap();
    let group_id = GroupId::from_slice(group_id);
    let group_config = MlsConversationConfiguration::openmls_default_configuration();
    let kp_hash = client.keypackage_hash(&backend).unwrap();
    let mut group = MlsGroup::new(backend, &group_config, group_id, &kp_hash).unwrap();
    group.save(&mut io::stdout()).unwrap();
}

fn add_member(backend: &MlsCryptoProvider, group_data: &mut dyn Read, mut kp_data: &mut dyn Read) {
    let mut group = MlsGroup::load(group_data).unwrap();
    let mut kp = KeyPackage::tls_deserialize(&mut kp_data).unwrap();
    let (handshake, welcome) = group
        .add_members(backend, &[kp]).unwrap();
    handshake.tls_serialize(&mut io::stdout()).unwrap();
}

#[derive(Parser)]
#[derive(Debug)]
#[clap(name = "crypto-cli")]
struct Cli {
    #[clap(short, long)]
    store: String,
    #[clap(short, long)]
    enc_key: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[derive(Debug)]
enum Command {
    KeyPackage {
        client_id: ClientId
    },
    PublicKey {
        client_id: ClientId
    },
    Group {
        client_id: ClientId,
        group_id: String,
    },
    Member {
        #[clap(subcommand)]
        command: MemberCommand,
    }
}

#[derive(Subcommand)]
#[derive(Debug)]
enum MemberCommand {
    Add {
        #[clap(short, long)]
        group: String,
        key_package: String
    }
}

fn path_reader(path: String) -> io::Result<Box<dyn Read>> {
    if path == "-" {
        Ok(Box::new(io::stdin()))
    }
    else {
        Ok(Box::new(fs::File::open(path)?))
    }
}

fn main() {
    let cli = Cli::parse();
    let backend = MlsCryptoProvider::try_new(&cli.store, &cli.enc_key).unwrap();
    match cli.command {
        Command::KeyPackage { client_id } => key_package(&backend, client_id),
        Command::PublicKey { client_id } => public_key(&backend, client_id),
        Command::Group { client_id, group_id } => group(&backend, client_id, group_id.as_bytes()),
        Command::Member { command: MemberCommand::Add { group, key_package } } => {
            let mut group_data = path_reader(group).unwrap();
            let mut kp_data = path_reader(key_package).unwrap();
            add_member(&backend, &mut group_data, &mut kp_data);
        },
    }
}
