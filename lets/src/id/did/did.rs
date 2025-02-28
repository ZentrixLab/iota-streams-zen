use crate::alloc::borrow::ToOwned;
use std::println;
use identity_iota::iota::{IotaClientExt, IotaDocument, IotaIdentityClientExt, NetworkName};
use identity_iota::storage::{JwkDocumentExt, JwkMemStore, KeyIdMemstore};
use identity_iota::verification::{jws::JwsAlgorithm, MethodScope};
use iota_sdk::client::secret::stronghold::StrongholdSecretManager;
use iota_sdk::client::secret::SecretManager;
use iota_sdk::client::{Client, Password};
use iota_sdk::types::block::address::Address;
use iota_sdk::types::block::output::AliasOutput;
// use crate::utils::{get_address_with_funds, random_stronghold_path, MemStorage};

// TO DO

pub async fn create_did(api_endpoint: &str, password: &str, faucet_endpoint: &str) -> anyhow::Result<IotaDocument> {
    let client: Client = Client::builder()
        .with_primary_node(api_endpoint, None)?
        .finish()
        .await?;

    let secret_manager: SecretManager = SecretManager::Stronghold(
        StrongholdSecretManager::builder()
            .password(Password::from(password.to_owned()))
            .build(random_stronghold_path())?,
    );

    let address: Address = get_address_with_funds(&client, &secret_manager, faucet_endpoint).await?;

    let network_name: NetworkName = client.network_name().await?;

    let mut document: IotaDocument = IotaDocument::new(&network_name);

    let storage: MemStorage = MemStorage::new(JwkMemStore::new(), KeyIdMemstore::new());
    document
        .generate_method(
            &storage,
            JwkMemStore::ED25519_KEY_TYPE,
            JwsAlgorithm::EdDSA,
            None,
            MethodScope::VerificationMethod,
        )
        .await?;

    let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

    let document: IotaDocument = client.publish_did_output(&secret_manager, alias_output).await?;
    
    println!("Published DID document: {document:#}");

    Ok(document)
}


/*

use std::str::FromStr;

use identity_iota::account::Account;
use identity_iota::account::AccountBuilder;
use identity_iota::core::FromJson;
use identity_iota::did::{DID, IotaDID, MethodScope};
use identity_iota::iota::{Client, IotaClient, IotaDocument};
use identity_iota::crypto::{KeyPair, KeyType};

use spongos::{
    ddml::{
        commands::{sizeof, unwrap, wrap, Mask},
        io,
        types::NBytes,
    },
    error::{Error as SpongosError, Result as SpongosResult},
    PRP,
};

use crate::error::{Error, Result};

pub async fn create_did(client: &IotaClient) -> Result<(IotaDID, KeyPair, IotaDocument)> {
    let keypair = KeyPair::new(KeyType::Ed25519)?;
    let mut doc = IotaDocument::new(&keypair)?;
    doc.insert_method(
        keypair.method().try_into()?,
        MethodScope::VerificationMethod,
    )?;
    let receipt = client.publish_document(&doc).await?;
    println!("DID dokument objavljen: {:?}", receipt);
    Ok((doc.id().clone(), keypair, doc))
}

pub async fn resolve_did(client: &IotaClient, did: &IotaDID) -> Result<IotaDocument> {
    let doc = client.resolve_document(did).await?;
    Ok(doc)
}

pub struct DIDIdentity {
    pub did: IotaDID,
    pub keypair: KeyPair,
}

impl Mask<&DIDIdentity> for sizeof::Context {
    fn mask(&mut self, identity: &DIDIdentity) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(identity.did.as_ref()))?
            .mask(NBytes::new(identity.keypair.private()))
    }
}

impl<OS, F> Mask<&DIDIdentity> for wrap::Context<OS, F>
where
    F: PRP,
    OS: io::OStream,
{
    fn mask(&mut self, identity: &DIDIdentity) -> SpongosResult<&mut Self> {
        self.mask(NBytes::new(identity.did.as_ref()))?
            .mask(NBytes::new(identity.keypair.private()))
    }
}

impl<IS, F> Mask<&mut DIDIdentity> for unwrap::Context<IS, F>
where
    F: PRP,
    IS: io::IStream,
{
    fn mask(&mut self, identity: &mut DIDIdentity) -> SpongosResult<&mut Self> {
        let mut did_bytes = vec![0; 32];
        let mut private_key_bytes = vec![0; 32];

        self.mask(NBytes::new(&mut did_bytes))?
            .mask(NBytes::new(&mut private_key_bytes))?;

        identity.did = IotaDID::from_str(std::str::from_utf8(&did_bytes).unwrap()).unwrap();
        identity.keypair = KeyPair::try_from_bytes(KeyType::Ed25519, &private_key_bytes).unwrap();

        Ok(self)
    }
}


*/