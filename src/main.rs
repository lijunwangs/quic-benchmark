use anyhow::{Context, Result};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Endpoint, ServerConfig, TransportConfig};

use rustls::crypto::ring::cipher_suite;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::pki_types::{ServerName, UnixTime};
use tokio::time::sleep_until;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;
use tokio::{
    sync::mpsc,
    task,
    time::{self, Instant as AsyncInstant},
};
use tracing::info;

const PACKET_SIZE: usize = 1000;

#[derive(StructOpt, Debug, Clone)]
#[structopt(name = "quic_benchmark")]
struct Opt {
    /// Run only the server
    #[structopt(long)]
    server_only: bool,

    /// Run only the client
    #[structopt(long)]
    client_only: bool,

    /// Server address (IP:port) for client mode
    #[structopt(long, default_value = "0.0.0.0:11228")]
    server_address: String,

    /// Number of sender threads
    #[structopt(long, default_value = "4")]
    num_threads: usize,

    /// Number of packets per sender thread
    #[structopt(long, default_value = "10000")]
    num_packets: usize,

    /// Server certificate
    #[structopt(long)]
    cert: Option<PathBuf>,

    /// Server key
    #[structopt(long)]
    key: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let mut opt = Opt::from_args();
    tracing_subscriber::fmt::init();

    match (opt.server_only, opt.client_only) {
        (true, false) => {
            let addr = opt
                .server_address
                .parse::<SocketAddr>()
                .expect("Exepected correct server address in IP:port format"); // SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let endpoint = setup_server(&opt, addr).expect("Failed to create server");
            let _ = run_server(endpoint).await;
        }
        (false, true) => {
            let _ = run_client(&opt).await;
        }
        _ => {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let endpoint = setup_server(&opt, addr).expect("Failed to create server");
            let addr: SocketAddr = endpoint.local_addr().unwrap();
            opt.server_address = addr.to_string();
            tokio::spawn(async move { run_server(endpoint).await });
            time::sleep(Duration::from_secs(1)).await;
            let _ = run_client(&opt).await;
        }
    }
}

async fn report_stats(total_received: Arc<AtomicUsize>) {
    let mut last_datapoint = AsyncInstant::now();
    loop {
        if last_datapoint.elapsed().as_secs() >= 5 {
            let total_received = total_received.swap(0, Ordering::Relaxed);
            info!("Received packets: {total_received}");
            last_datapoint = AsyncInstant::now();
        }
        sleep_until(last_datapoint.checked_add(Duration::from_secs(5)).unwrap()).await;
    }
}

async fn run_server(endpoint: Endpoint) -> Result<()> {
    info!("Server listening on {}", endpoint.local_addr().unwrap());
    let total_received = Arc::new(AtomicUsize::new(0));

    tokio::spawn(report_stats(total_received.clone()));

    while let Some(handshake) = endpoint.accept().await {
        info!(
            "Got incoming connection from {:?}",
            handshake.remote_address()
        );
        let total_received = total_received.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(handshake, total_received).await {
                info!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn handle(handshake: quinn::Incoming, total_received: Arc<AtomicUsize>) -> Result<()> {
    let connection = handshake.await.context("handshake failed")?;
    info!("{} connected", connection.remote_address());
    tokio::try_join!(drive_datagram(connection.clone(), total_received),)?;
    Ok(())
}

async fn drive_datagram(
    connection: quinn::Connection,
    total_received: Arc<AtomicUsize>,
) -> Result<()> {
    loop {
        let result = connection.read_datagram().await;
        match result {
            Ok(_) => {
                total_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                info!("Received a datagram!");
            }
            Err(err) => {
                info!(
                    "Got error {err:?} for connection from {:?}",
                    connection.remote_address()
                );
                break;
            }
        }
    }
    Ok(())
}

async fn run_client(opt: &Opt) -> Result<()> {
    let mut server_addr: SocketAddr = opt
        .server_address
        .parse()
        .expect("Invalid server address format");

    if server_addr.ip().is_unspecified() {
        server_addr.set_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }
    info!("Connecting to server {server_addr:?}");
    let endpoint = setup_client().expect("Failed to create client");

    let conn = endpoint
        .connect(server_addr, "localhost")
        .expect("Failed to connect")
        .await
        .expect("Connection failed");

    let packet = vec![0; PACKET_SIZE];
    let start = Instant::now();
    let (tx, mut rx) = mpsc::channel::<usize>(opt.num_threads);

    for _ in 0..opt.num_threads {
        let conn = conn.clone();
        let packet = packet.clone();
        let tx = tx.clone();
        let num_packets = opt.num_packets;
        task::spawn(async move {
            let mut sent = 0;
            for _ in 0..num_packets {
                conn.send_datagram_wait(packet.clone().into()).await.unwrap();
                sent += 1;
            }
            tx.send(sent).await.unwrap();
        });
    }

    drop(tx);
    let mut total_sent = 0;
    while let Some(sent) = rx.recv().await {
        total_sent += sent;
    }

    let duration = start.elapsed().as_secs_f64();
    info!(
        "Sent {} packets in {:.2} seconds ({:.2} packets/sec)",
        total_sent,
        duration,
        total_sent as f64 / duration
    );

    Ok(())
}

fn setup_server(opt: &Opt, addr: SocketAddr) -> Result<Endpoint, Box<dyn std::error::Error>> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (Some(key), Some(cert)) => {
            let key = fs::read(key).context("reading key")?;
            let cert = fs::read(cert).expect("reading cert");
            (
                PrivatePkcs8KeyDer::from(key),
                rustls_pemfile::certs(&mut cert.as_ref())
                    .collect::<Result<_, _>>()
                    .context("parsing cert")?,
            )
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
                vec![CertificateDer::from(cert.cert)],
            )
        }
    };

    let default_provider = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: [
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into(),
        ..default_provider
    };

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key.into())
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    let crypto = Arc::new(QuicServerConfig::try_from(crypto)?);

    let mut transport_config = TransportConfig::default();
    transport_config.datagram_receive_buffer_size(Some(PACKET_SIZE * 1024 * 1024));

    let mut server_config = ServerConfig::with_crypto(crypto);
    server_config.transport = Arc::new(transport_config);

    let endpoint = Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn setup_client() -> Result<Endpoint, Box<dyn std::error::Error>> {
    info!("Setting up client");
    let default_provider = rustls::crypto::ring::default_provider();
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: [
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ]
        .into(),
        ..default_provider
    });

    let mut transport_config = TransportConfig::default();
    transport_config.datagram_send_buffer_size(PACKET_SIZE * 1024 * 1024);

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    info!("Setting up QuicClientConfig...");

    let crypto = Arc::new(QuicClientConfig::try_from(crypto)?);

    let mut client_config = quinn::ClientConfig::new(crypto);

    client_config.transport_config(Arc::new(transport_config));

    info!("Creating client endpoint...");

    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
