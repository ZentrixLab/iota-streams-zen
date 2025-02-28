use async_trait::async_trait;
use hex::encode;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use std::println;
use std::str::FromStr;
use std::string::String;

use alloc::{boxed::Box, vec::Vec};
use crate::alloc::string::ToString;


use iota_sdk::{
    client::{secret::SecretManager, Client},
    types::block::{
        address::Bech32Address,
        output::{
            feature::{MetadataFeature, TagFeature},
            unlock_condition::AddressUnlockCondition,
            BasicOutputBuilder,
        },
    },
    types::block::output::Feature,
};

use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};


#[derive(Debug, Deserialize)]
struct IndexerOutputsResponse {
    #[serde(rename = "items")]
    output_ids: Vec<String>,

}



pub struct IotaTransport {
    client: Client,
    secret_manager: SecretManager,
    bech32_address: Bech32Address, 
    node_url: String,              
}

impl IotaTransport {

    pub async fn new(node_url: &str, mnemonic: &str, sender_address: &str) -> Result<Self> {
        let client = Client::builder()
            .with_node(node_url)
            .map_err(|e| Error::IotaClient("Failed to initialize client", e))?
            .finish()
            .await
            .map_err(|e| Error::IotaClient("Failed to create client", e))?;

        let secret_manager = SecretManager::try_from_mnemonic(mnemonic)
            .map_err(|e| Error::IotaClient("Failed to initialize secret manager", e))?;

        let bech32_address = Bech32Address::from_str(sender_address)
            .map_err(|e| Error::External(anyhow::anyhow!("Failed to parse sender address: {:?}", e)))?;

        println!("Using sender address: {bech32_address:#?}");

        Ok(Self {
            client,
            secret_manager,
            bech32_address,
            node_url: node_url.to_string(),
        })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[async_trait(?Send)]
impl<'a> Transport<'a> for IotaTransport {
    type Msg = TransportMessage;
    type SendResponse = String;

    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse> {
        let metadata = MetadataFeature::new(msg.into_body())
            .map_err(|e| Error::IotaClient("Failed to create MetadataFeature", iota_sdk::client::Error::Block(e)))?;

        let token_supply = self.client
            .get_token_supply()
            .await
            .map_err(|e| Error::IotaClient("Failed to get token supply", e))?;

        let msg_index_hex = encode(address.to_msg_index());

        let decoded_tag = hex::decode(&msg_index_hex)
            .map_err(|e| Error::External(anyhow::anyhow!("Failed to decode Tag hex: {:?}", e)))?;

        let tag_feature = TagFeature::new(decoded_tag)
            .map_err(|e| Error::IotaClient("Failed to create TagFeature", iota_sdk::client::Error::Block(e)))?;

        let output = BasicOutputBuilder::new_with_amount(1_000_000)
            .add_unlock_condition(AddressUnlockCondition::new(self.bech32_address.clone()))
            .add_feature(metadata)
            .add_feature(tag_feature)
            .finish_output(token_supply)
            .map_err(|e| Error::IotaClient("Failed to create BasicOutput", iota_sdk::client::Error::Block(e)))?;

        let block = self.client
            .build_block()
            .with_secret_manager(&self.secret_manager)
            .with_outputs(vec![output])?
            .finish()
            .await
            .map_err(|e| Error::IotaClient("Failed to send block", e))?;

        Ok(block.id().to_string())
    }


    async fn recv_messages(&mut self, msg_index: Address) -> Result<Vec<Self::Msg>> {
        let msg_index_hex = encode(msg_index.to_msg_index());
        println!("Searching outputs for tag: {}", msg_index_hex);

        let url = format!("{}/api/indexer/v1/outputs/basic?tag=0x{}", self.node_url, msg_index_hex);

        let resp = HttpClient::new()
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::External(anyhow::anyhow!("Failed to query indexer for output IDs: {}", e)))?;

        if !resp.status().is_success() {
            return Err(Error::External(anyhow::anyhow!("Indexer returned non-success status: {}", resp.status())));
        }

        let indexer_resp: IndexerOutputsResponse = resp
            .json()
            .await
            .map_err(|e| Error::External(anyhow::anyhow!("Failed to parse indexer response JSON: {}", e)))?;

        println!("Found {} outputs matching the tag.", indexer_resp.output_ids.len());

        let mut messages = Vec::new();

        for output_id_hex in indexer_resp.output_ids {
            let output_id = output_id_hex.parse()
                .map_err(|e| Error::External(anyhow::anyhow!("Failed to parse output ID: {:?}", e)))?;
            let output_response = self.client
                .get_output(&output_id)
                .await
                .map_err(|e| Error::IotaClient("Failed to fetch output data", e))?;
            if let Some(features) = output_response.output().features() {
                if let Some(metadata_feature) = features.iter().find_map(|f| {
                    if let Feature::Metadata(m) = f { Some(m) } else { None }
                }) {
                    messages.push(TransportMessage::new(metadata_feature.data().to_vec()));
                    println!("Message found: {:?}", metadata_feature.data());
                } else {
                    println!("Warning: No MetadataFeature in this output.");
                }
            }
        }

        if messages.is_empty() {
            println!("No messages found for tag: {}", msg_index_hex);
        }

        Ok(messages)
    }
}
