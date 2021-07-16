use actix_web::{
    dev::ConnectionInfo, error, http::HeaderName, middleware, post, web, App, Error, HttpRequest, HttpResponse,
    HttpServer,
};
use clap::Clap;
use interbtc_telemetry_types::{Message, Payload};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};
use sqlx::{postgres::PgPool, Error as SqlxError};
use std::{cell::Ref, net::Ipv4Addr};
use thiserror::Error;

pub type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

const X_ORIGINAL_FORWARDED_FOR: &[u8] = b"x-original-forwarded-for";

// like ConnectionInfo but also parses X_ORIGINAL_FORWARDED_FOR
struct ConnectionInfoExt<'a> {
    info: Ref<'a, ConnectionInfo>,
    original_remote_addr: Option<String>,
}

impl<'a> ConnectionInfoExt<'a> {
    fn get(req: &'a HttpRequest) -> Self {
        let head = req.head();
        Self {
            info: ConnectionInfo::get(head, &*req.app_config()),
            original_remote_addr: head
                .headers
                .get(&HeaderName::from_lowercase(X_ORIGINAL_FORWARDED_FOR).unwrap())
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split(',').next().map(|v| v.trim()))
                .map(|s| s.to_owned()),
        }
    }

    fn realip_remote_addr(&self) -> Option<&str> {
        if let Some(ref r) = self.original_remote_addr {
            Some(r)
        } else {
            self.info.realip_remote_addr()
        }
    }
}

#[derive(Error, Debug)]
pub enum InternalError {
    #[error("Invalid Signature")]
    InvalidSignature,
    #[error("SqlxError: {0}")]
    SqlxError(#[from] SqlxError),
}

impl actix_web::ResponseError for InternalError {}

async fn route(
    account_id: AccountId,
    ip_addr: Option<Ipv4Addr>,
    payload: Payload,
    pool: &PgPool,
) -> Result<HttpResponse, InternalError> {
    match payload {
        Payload::UpdateClient(info) => {
            sqlx::query!(
                r#"
                    INSERT INTO clients ( account_id, client_name, client_version, ip_addr, updated )
                    VALUES ( $1, $2, $3, $4, NOW() )
                    ON CONFLICT ( account_id )
                    DO UPDATE SET client_name = $2, client_version = $3, ip_addr = $4, updated = NOW();
                "#,
                account_id.to_string(),
                &info.name,
                &info.version,
                ip_addr.map(|ip| ip.to_string()),
            )
            .fetch_all(pool)
            .await?;
        }
    }
    Ok(HttpResponse::Ok().finish())
}

#[post("/")]
async fn index(req: HttpRequest, body: web::Bytes, pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    let ip_addr = ConnectionInfoExt::get(&req).realip_remote_addr().and_then(|mut addr| {
        if let Some(port_idx) = addr.find(':') {
            addr = &addr[..port_idx];
        }
        addr.parse::<Ipv4Addr>().ok()
    });

    if let Some(ip) = ip_addr {
        log::info!("Got request from {}", ip);
    } else {
        log::info!("Got request from unknown client");
    }

    let msg = serde_json::from_slice::<Message>(&body)?;
    let payload_bytes = serde_json::to_vec(&msg.payload)?;
    if !msg.signature.verify(&*payload_bytes, &msg.public) {
        Err(error::ErrorUnauthorized(InternalError::InvalidSignature))
    } else {
        // TODO: check client is registered on-chain
        let account_id = <MultiSignature as Verify>::Signer::from(msg.public).into_account();
        route(account_id, ip_addr, msg.payload, pool.get_ref())
            .await
            .map_err(Into::into)
    }
}

/// Remote telemetry service for monitoring client up-time.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// The socket address to bind.
    #[clap(long, default_value = "127.0.0.1:8080")]
    listen_addr: String,

    /// The socket address to bind.
    #[clap(long, default_value = "postgres://postgres:password@localhost/telemetry")]
    database_url: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );

    let opts: Opts = Opts::parse();

    let pool = PgPool::connect(&opts.database_url)
        .await
        .expect("Unable to connect to database");

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .wrap(middleware::Logger::default())
            .data(web::JsonConfig::default().limit(4096))
            .service(index)
    })
    .bind(&opts.listen_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        dev::Service,
        http,
        test::{self, TestRequest},
        App,
    };
    use interbtc_telemetry_types::ClientInfo;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use sp_core::{sr25519::Signature, Pair};
    use sp_keyring::AccountKeyring;

    fn new_rand_str() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect()
    }

    #[actix_rt::test]
    async fn should_insert_or_update_client() -> Result<(), Error> {
        let pool = PgPool::connect(&dotenv::var("DATABASE_URL").unwrap()).await.unwrap();
        let mut app = test::init_service(App::new().data(pool.clone()).service(index)).await;

        let signer = AccountKeyring::Alice.pair();
        let account_id = <MultiSignature as Verify>::Signer::from(signer.public()).into_account();

        let name = new_rand_str();
        let version = new_rand_str();
        let payload = Payload::UpdateClient(ClientInfo {
            name: name.clone(),
            version: version.clone(),
        });
        let message = Message::from_payload_and_signer(payload, &signer);

        let req = test::TestRequest::post().uri("/").set_json(&message).to_request();
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);

        let record = sqlx::query!(
            "SELECT client_name, client_version from clients where account_id = $1;",
            account_id.to_string(),
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(name, record.client_name);
        assert_eq!(version, record.client_version);

        Ok(())
    }

    #[actix_rt::test]
    async fn should_reject_invalid_signature() -> Result<(), Error> {
        let pool = PgPool::connect(&dotenv::var("DATABASE_URL").unwrap()).await.unwrap();
        let mut app = test::init_service(App::new().data(pool.clone()).service(index)).await;

        let signer = AccountKeyring::Alice.pair();
        let public = signer.public();
        let payload = Payload::UpdateClient(ClientInfo {
            name: "Client".to_string(),
            version: new_rand_str(),
        });
        let signature = Signature::default();

        let req = test::TestRequest::post()
            .uri("/")
            .set_json(&Message {
                public,
                payload,
                signature,
            })
            .to_request();
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[actix_rt::test]
    async fn should_parse_ip_addr() -> Result<(), Error> {
        let req = TestRequest::with_header(X_ORIGINAL_FORWARDED_FOR, "1.1.1.1").to_http_request();
        assert_eq!(ConnectionInfoExt::get(&req).realip_remote_addr(), Some("1.1.1.1"));

        let req = TestRequest::with_header("x-forwarded-for", "1.1.1.1").to_http_request();
        assert_eq!(ConnectionInfoExt::get(&req).realip_remote_addr(), Some("1.1.1.1"));

        let req = TestRequest::default().to_http_request();
        assert_eq!(ConnectionInfoExt::get(&req).realip_remote_addr(), None);

        Ok(())
    }
}
