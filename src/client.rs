use uuid::Uuid;
use x509_cert::ext::pkix::name::GeneralName;

#[derive(Debug)]
pub struct RegularClient {
    pub user: String,
    pub client: String,
    pub domain: String,
}

#[derive(Debug)]
pub enum ClientId {
    Regular(RegularClient),
    History { id: String },
}

impl core::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s.starts_with(Self::HISTORY_CLIENT_PREFIX) {
            Ok(Self::History {
                id: s[Self::HISTORY_CLIENT_PREFIX.len()..].to_string(),
            })
        } else {
            let dom_index = s.find('@').ok_or("No domain separator")?;
            let cli_index = s[0..dom_index].find(':').ok_or("No client ID separator")?;
            Ok(ClientId::Regular(RegularClient {
                user: s[0..cli_index].to_string(),
                client: s[cli_index + 1..dom_index].to_string(),
                domain: s[dom_index + 1..].to_string(),
            }))
        }
    }
}

impl ClientId {
    const HISTORY_CLIENT_PREFIX: &'static str = "history-client:";

    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Regular(client) => {
                out.extend(client.user.bytes());
                out.push(b':');
                out.extend(client.client.bytes());
                out.push(b'@');
                out.extend(client.domain.bytes());
            }
            Self::History { id } => {
                out.extend(Self::HISTORY_CLIENT_PREFIX.bytes());
                out.extend(id.bytes());
            }
        }
        out
    }
}

impl RegularClient {
    pub fn to_x509(&self, handle: &str) -> impl Iterator<Item = GeneralName> {
        let uuid = Uuid::parse_str(&self.user).unwrap();
        let uid = base64::encode_config(uuid.into_bytes(), base64::URL_SAFE_NO_PAD);
        [
            format!("wireapp://{}%21{}@{}", uid, self.client, self.domain),
            format!("wireapp://%40{}@{}", handle, self.domain),
        ]
        .into_iter()
        .map(|n| GeneralName::UniformResourceIdentifier(n.try_into().unwrap()))
    }
}
