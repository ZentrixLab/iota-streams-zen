use std::str::FromStr;
use identity_iota::{
    account::Account,
    core::BaseEncoding,
    crypto::{KeyPair, KeyType},
    did::{DID, IotaDID, MethodScope},
    iota::{Client, IotaClient, IotaDocument, IotaIdentityClientExt},
    verification::jws::JwsVerifier,
    document::verifiable::JwsVerificationOptions,
};
use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::Bytes,
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};
use anyhow::Result;
use base64;
use ed25519_dalek::{PublicKey, Signature, Verifier};

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DIDUrlInfo {
    did: String,
    client_url: String,
    exchange_fragment: String,
    signing_fragment: String,
}

impl DIDUrlInfo {
    pub fn new<T: Into<String>>(did: IotaDID, client_url: T, exchange_fragment: T, signing_fragment: T) -> Self {
        Self {
            did: did.into_string(),
            client_url: client_url.into(),
            exchange_fragment: exchange_fragment.into(),
            signing_fragment: signing_fragment.into(),
        }
    }

    pub async fn resolve_document(&self) -> Result<IotaDocument> {
        let client = Client::builder()
            .with_primary_node(&self.client_url, None)?
            .finish()
            .await?;
        
        let did = IotaDID::parse(&self.did)?;
        let document = client.resolve_did(&did).await?;
        
        Ok(document)
    }

    pub async fn verify_signature(&self, signature: &str, message: &[u8]) -> Result<bool> {
        let document = self.resolve_document().await?;
        let method = document
            .methods()
            .find(|m| m.id().fragment() == Some(&self.signing_fragment))
            .ok_or_else(|| anyhow::anyhow!("Signing method not found"))?;

        let public_key_bytes = method.data().as_ref();
        let public_key = PublicKey::from_bytes(public_key_bytes)?;

        let decoded_signature = base64::decode(signature)?;
        let signature = Signature::from_bytes(&decoded_signature)?;

        Ok(public_key.verify(message, &signature).is_ok())
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn client_url(&self) -> &str {
        &self.client_url
    }

    pub fn exchange_fragment(&self) -> &str {
        &self.exchange_fragment
    }

    pub fn signing_fragment(&self) -> &str {
        &self.signing_fragment
    }
}

impl Mask<&DIDUrlInfo> for sizeof::Context {
    fn mask(&mut self, url_info: &DIDUrlInfo) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<OS, F> Mask<&DIDUrlInfo> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, url_info: &DIDUrlInfo) -> SpongosResult<&mut Self> {
        self.mask(Bytes::new(url_info.did()))?
            .mask(Bytes::new(url_info.client_url()))?
            .mask(Bytes::new(url_info.exchange_fragment()))?
            .mask(Bytes::new(url_info.signing_fragment()))
    }
}

impl<IS, F> Mask<&mut DIDUrlInfo> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, url_info: &mut DIDUrlInfo) -> SpongosResult<&mut Self> {
        let mut did_bytes = Vec::new();
        let mut client_url = Vec::new();
        let mut exchange_fragment_bytes = Vec::new();
        let mut signing_fragment_bytes = Vec::new();
        
        self.mask(Bytes::new(&mut did_bytes))?
            .mask(Bytes::new(&mut client_url))?
            .mask(Bytes::new(&mut exchange_fragment_bytes))?
            .mask(Bytes::new(&mut signing_fragment_bytes))?;

        *url_info.did_mut() = String::from_utf8(did_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", e.to_string()))?;
        *url_info.client_url_mut() = String::from_utf8(client_url)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", e.to_string()))?;
        *url_info.exchange_fragment_mut() = String::from_utf8(exchange_fragment_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", e.to_string()))?;
        *url_info.signing_fragment_mut() = String::from_utf8(signing_fragment_bytes)
            .map_err(|e| SpongosError::Context("Mask DIDUrlInfo", e.to_string()))?;
        Ok(self)
    }
}







/* 
use identity_iota::did::DID;
use identity_iota::iota::{IotaDID, IotaDocument, IotaIdentityClientExt};
use identity_iota::verification::jws::{JwsVerifier};
use identity_iota::document::verifiable::JwsVerificationOptions;
use identity_iota::credential::Jws;
use iota_sdk::client::Client;
use anyhow::Result;
use ed25519_dalek::{PublicKey, Signature, Verifier};
use base64;
use alloc::string::String;

// For creating new DIDs using IOTA Identity and publishing the DID document to the network.

//`DIDUrlInfo` contains details about the DID document and fragments for key exchange and signing.
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DIDUrlInfo {
    did: String,
    client_url: String,
    exchange_fragment: String,
    signing_fragment: String,
}

impl DIDUrlInfo {
    /// Creates a new `DIDUrlInfo` with the given values.
    pub fn new<T: Into<String>>(did: IotaDID, client_url: T, exchange_fragment: T, signing_fragment: T) -> Self {
        Self {
            did: did.into_string(),
            client_url: client_url.into(),
            exchange_fragment: exchange_fragment.into(),
            signing_fragment: signing_fragment.into(),
        }
    }

    /// Resolves the DID document using the DID and fragment information.
    pub async fn resolve_document(&self) -> Result<IotaDocument> {
        let client = Client::builder()
            .with_primary_node(&self.client_url, None)?
            .finish()
            .await?;
        
        // Resolve the DID from the network using client_url and DID
        let did = IotaDID::parse(&self.did)?;
        let document = client.resolve_did(&did).await?;
        
        Ok(document)
    }

*/