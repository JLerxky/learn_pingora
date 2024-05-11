mod app;

use std::time::Duration;

use async_trait::async_trait;
use pingora::server::configuration::Opt;
use pingora::server::{Server, ShutdownWatch};
use pingora::services::background::{background_service, BackgroundService};
use pingora::services::{listening::Service as ListeningService, Service};
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use structopt::StructOpt;
use tokio::time::interval;
use tracing::info;

pub struct ExampleBackgroundService;
#[async_trait]
impl BackgroundService for ExampleBackgroundService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut period = interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    // shutdown
                    break;
                }
                _ = period.tick() => {
                    // do some work
                    // ...
                }
            }
        }
    }
}
struct DynamicCert {
    cert: X509,
    key: PKey<Private>,
}

impl DynamicCert {
    fn new(cert: &str, key: &str) -> Box<Self> {
        let cert_bytes = std::fs::read(cert).unwrap();
        let cert = X509::from_pem(&cert_bytes).unwrap();

        let key_bytes = std::fs::read(key).unwrap();
        let key = PKey::private_key_from_pem(&key_bytes).unwrap();
        Box::new(DynamicCert { cert, key })
    }
}

#[async_trait]
impl pingora::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        use pingora::tls::ext;
        ext::ssl_use_certificate(ssl, &self.cert).unwrap();
        ext::ssl_use_private_key(ssl, &self.key).unwrap();
    }
}

fn main() {
    common_x::log::init_log_filter("info");

    let opt = Some(Opt::from_args());

    let mut my_server = Server::new(opt).unwrap();
    my_server.bootstrap();

    let cert_path = "config/cert/server_cert.pem";
    let key_path = "config/cert/server_key.pem";

    let mut echo_service = app::echo_service();
    echo_service.add_tcp("127.0.0.1:6142");
    echo_service
        .add_tls("0.0.0.0:6143", cert_path, key_path)
        .unwrap();

    let dynamic_cert = DynamicCert::new(cert_path, key_path);
    let mut tls_settings = pingora::listeners::TlsSettings::with_callbacks(dynamic_cert).unwrap();
    // by default intermediate supports both TLS 1.2 and 1.3. We force to tls 1.2 just for the demo
    tls_settings
        .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))
        .unwrap();
    tls_settings.enable_h2();

    let mut prometheus_service_http = ListeningService::prometheus_http_service();
    prometheus_service_http.add_tcp("127.0.0.1:6150");

    let background_service = background_service("example", ExampleBackgroundService {});

    let services: Vec<Box<dyn Service>> = vec![
        Box::new(echo_service),
        Box::new(prometheus_service_http),
        Box::new(background_service),
    ];
    my_server.add_services(services);
    info!("Starting server");
    my_server.run_forever();
}

#[tokio::test]
async fn cert() {
    use common_x::{
        file::create_file,
        tls::{new_ca, new_end_entity},
    };
    // ca
    let (ca_cert, ca_key_pair) = new_ca();
    create_file("./config/cert/ca_cert.pem", ca_cert.pem().as_bytes())
        .await
        .unwrap();
    create_file(
        "./config/cert/ca_key.pem",
        ca_key_pair.serialize_pem().as_bytes(),
    )
    .await
    .unwrap();

    // server cert
    let (server_cert, server_key) = new_end_entity("test-host", &ca_cert, &ca_key_pair);
    create_file(
        "./config/cert/server_cert.pem",
        server_cert.pem().as_bytes(),
    )
    .await
    .unwrap();
    create_file(
        "./config/cert/server_key.pem",
        server_key.serialize_pem().as_bytes(),
    )
    .await
    .unwrap();

    // client cert
    let (client_cert, client_key) = new_end_entity("client.test-host", &ca_cert, &ca_key_pair);
    create_file(
        "./config/cert/client_cert.pem",
        client_cert.pem().as_bytes(),
    )
    .await
    .unwrap();
    create_file(
        "./config/cert/client_key.pem",
        client_key.serialize_pem().as_bytes(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn client() {
    use pingora::connectors::TransportConnector;
    use pingora::upstreams::peer::BasicPeer;
    use tokio::io::AsyncWriteExt;

    let connector = TransportConnector::new(None);
    let peer = BasicPeer::new("127.0.0.1:6142");
    // BasicPeer will use tls when SNI is set
    // peer.sni = "client.test-host".to_string();
    // make a new connection to 127.0.0.1:6143
    let mut stream = connector.new_stream(&peer).await.unwrap();

    let mut period = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = period.tick() => {
                stream.write_all(b"hello").await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    }
    // connector.release_stream(stream, peer.reuse_hash(), None);

    // let (_, reused) = connector.get_stream(&peer).await.unwrap();
    // Ok(())
}
