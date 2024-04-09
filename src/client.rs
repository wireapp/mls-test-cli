use uuid::Uuid;

#[derive(Debug)]
pub struct ClientId {
    pub user: String,
    pub client: String,
    pub domain: String,
}

impl core::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let dom_index = s.find('@').ok_or("No domain separator")?;
        let cli_index = s[0..dom_index].find(':').ok_or("No client ID separator")?;
        Ok(ClientId {
            user: s[0..cli_index].to_string(),
            client: s[cli_index + 1..dom_index].to_string(),
            domain: s[dom_index + 1..].to_string(),
        })
    }
}

impl ClientId {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.user.bytes());
        out.push(b':');
        out.extend(self.client.bytes());
        out.push(b'@');
        out.extend(self.domain.bytes());
        out
    }

    pub fn to_x509(&self, handle: &str) -> String {
        let uuid = Uuid::parse_str(&self.user).unwrap();
        let uid = base64::encode_config(uuid.into_bytes(), base64::URL_SAFE_NO_PAD);
        format!(
            "subjectAltName=URI:wireapp://{}%21{}@{}, URI:wireapp://%40{}@{}",
            uid, self.client, self.domain, handle, self.domain
        )
    }
}
