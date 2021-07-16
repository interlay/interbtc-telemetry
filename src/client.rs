use actix_web::client::Client;
use clap::Clap;
use interbtc_telemetry_types::{ClientInfo, Message, Payload};
use sp_keyring::AccountKeyring;

/// Simple client to interact with the telemetry service.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// The address of the server.
    #[clap(long, default_value = "http://127.0.0.1:8080")]
    telemetry_url: String,

    /// The client name to update.
    #[clap(long, default_value = "Client")]
    name: String,

    /// The client version to update.
    #[clap(long, default_value = "0.0.1")]
    version: String,
}

#[actix_web::main]
async fn main() {
    let opts: Opts = Opts::parse();

    let client = Client::default();

    let signer = AccountKeyring::Alice.pair();

    let payload = Payload::UpdateClient(ClientInfo {
        name: opts.name,
        version: opts.version,
    });
    let message = Message::from_payload_and_signer(payload, &signer);

    let response = client.post(opts.telemetry_url).send_json(&message).await;
    println!("Response: {:?}", response);
}
