use anyhow::Result;
use chrono::Utc;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use tokio::{runtime::Runtime, time::sleep};
use std::time::Duration;
use lets::{
    address::{Address, AppAddr, MsgId},
    id::Identifier,
    message::{Topic, TransportMessage},
    transport::tangle::IotaTransport,
};
use lets::Transport;


const DEFAULT_NODE: &str = "127.0.0.1:14265";
const DEFAULT_SENDER_ADDRESS: &str = "rms-address"; 
const NUM_MESSAGES: usize = 10; 

async fn send_message(client: &mut IotaTransport, payload_size: usize) -> Result<String> {
    let msg = TransportMessage::new(vec![12u8; payload_size]);

    let address = Address::new(
        AppAddr::default(),
        MsgId::gen(
            AppAddr::default(),
            &Identifier::default(),
            &Topic::default(),
            Utc::now().timestamp_millis() as usize,
        ),
    );

    println!("Sending message of size {} bytes...", payload_size);
    let block_id = client.send_message(address, msg).await?;
    
    println!("Message sent! Block ID: {}", block_id);
    println!("Check transaction in Explorer: https://explorer.shimmer.network/testnet/block/{}", block_id);

    Ok(block_id)
}

fn bench_clients(c: &mut Criterion) {
    let url = std::env::var("NODE_URL").unwrap_or_else(|_| String::from(DEFAULT_NODE));
    let mnemonic = "remember vast two nerve please roof core hint time police parade gate trick beyond file illness patient scene auto bullet supreme erosion axis kitchen";
    let sender_address = std::env::var("SENDER_ADDRESS").unwrap_or_else(|_| String::from(DEFAULT_SENDER_ADDRESS));

    let runtime = Runtime::new().unwrap();
    let mut group = c.benchmark_group("Send Message by Size");

    let mut transport = runtime.block_on(async {
        IotaTransport::new(&url, mnemonic, &sender_address).await.unwrap()
    });

    group.sample_size(NUM_MESSAGES); 

    for size in [32, 64, 512, 1024] { 
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("IOTA Transport", size), &size, |b, &payload_size| {
            b.iter(|| {
                runtime.block_on(async {
                    let result = send_message(&mut transport, payload_size).await;
                    match result {
                        Ok(block_id) => println!("Successfully sent message of size {} | Block ID: {}", payload_size, block_id),
                        Err(e) => println!("Error sending message of size {}: {:?}", payload_size, e),
                    }

                    sleep(Duration::from_secs(10)).await;
                })
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_clients);
criterion_main!(benches);