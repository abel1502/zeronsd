use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::info;

use rustls::server::ResolvesServerCert;
use tokio::net::{TcpListener, UdpSocket};

use hickory_server::server::ServerFuture;

use crate::authority::{init_catalog, ZTAuthority};

#[derive(Clone)]
pub struct Server(ZTAuthority);

impl Server {
    pub fn new(zt: ZTAuthority) -> Self {
        Self(zt)
    }

    // listener routine for TCP and UDP.
    pub async fn listen(
        self,
        ip: IpAddr,
        tcp_timeout: Duration,
        tls_resolver: Option<Arc<dyn ResolvesServerCert>>,
    ) -> Result<(), anyhow::Error> {
        let sa = SocketAddr::new(ip, 53);
        let tcp = TcpListener::bind(sa).await?;
        let udp = UdpSocket::bind(sa).await?;

        let mut sf = ServerFuture::new(init_catalog(self.0).await?);

        if let Some(tls_resolver) = tls_resolver {
            info!("Configuring DoT Listener");
            let tls = TcpListener::bind(SocketAddr::new(ip, 853)).await?;

            match sf.register_tls_listener(tls, tcp_timeout, tls_resolver) {
                Ok(_) => {}
                Err(e) => tracing::error!("Cannot start DoT listener: {}", e),
            }
        }

        sf.register_socket(udp);
        sf.register_listener(tcp, tcp_timeout);

        match sf.block_until_done().await {
            Ok(_) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("{}", e)),
        }
    }
}
