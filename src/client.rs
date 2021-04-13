use actix_web::client::Client;
use clap::Clap;
use polkabtc_telemetry_types::{ClientInfo, Message, Payload};
use sp_core::crypto::Pair;
use sp_keyring::AccountKeyring;

/// Simple client to interact with the telemetry service.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// The address of the server.
    #[clap(long, default_value = "http://127.0.0.1:8080")]
    telemetry_url: String,

    /// The client version to update.
    #[clap(long, default_value = "0.0.1")]
    version: String,
}

#[actix_web::main]
async fn main() {
    let opts: Opts = Opts::parse();

    let client = Client::default();

    let signer = AccountKeyring::Alice.pair();
    let public = signer.public();

    let payload = Payload::UpdateClient(ClientInfo { version: opts.version });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = signer.sign(&payload_bytes);

    let response = client
        .post(opts.telemetry_url)
        .send_json(&Message {
            public,
            payload,
            signature,
        })
        .await;

    println!("Response: {:?}", response);
}
