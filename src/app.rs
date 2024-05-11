use std::sync::Arc;

use async_trait::async_trait;
use pingora::{
    apps::ServerApp, protocols::Stream, server::ShutdownWatch, services::listening::Service,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

#[derive(Clone)]
pub struct EchoApp;

#[async_trait]
impl ServerApp for EchoApp {
    async fn process_new(
        self: &Arc<Self>,
        mut io: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let mut buf = [0; 1024];
        loop {
            let n = io.read_exact(&mut buf).await.unwrap();
            if n == 0 {
                debug!("session closing");
                return None;
            } else {
                debug!("read {} bytes", n);
            }
            io.write_all(&buf[0..n]).await.unwrap();
            io.flush().await.unwrap();
        }
    }
}

impl EchoApp {
    pub fn new() -> Arc<Self> {
        Arc::new(EchoApp {})
    }
}

pub fn echo_service() -> Service<EchoApp> {
    Service::new("Echo Service".to_string(), EchoApp::new())
}
