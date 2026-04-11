/// FIFA 17 SSL Proxy
/// 
/// Listens on port 42230 (where FIFA 17 connects for the Blaze redirector).
/// Handles the ProtoSSL handshake using blaze-ssl-async, then forwards
/// decrypted traffic to the Node.js server on port 42231.

use blaze_ssl_async::{BlazeListener, BlazeServerContext, RsaPrivateKey};
use blaze_ssl_async::listener::Certificate;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const LISTEN_PORT: u16 = 42230;
const BACKEND_PORT: u16 = 42231;

// Our server certificate and CA cert as DER bytes
const SERVER_CERT_DER: &[u8] = include_bytes!("../server.der");
const CA_CERT_DER: &[u8] = include_bytes!("../ca.der");

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("FIFA 17 SSL Proxy starting...");
    println!("  SSL listener: 0.0.0.0:{}", LISTEN_PORT);
    println!("  Backend (plain TCP): 127.0.0.1:{}", BACKEND_PORT);
    println!();

    // Parse the private key from PEM
    use rsa::pkcs8::DecodePrivateKey;
    let key_pem = include_str!("../server.key");
    let private_key = RsaPrivateKey::from_pkcs8_pem(key_pem)
        .expect("Failed to parse private key");

    // Build certificate chain: server cert + CA cert
    let server_cert = Certificate::from_static(SERVER_CERT_DER);
    let ca_cert = Certificate::from_static(CA_CERT_DER);

    let context = Arc::new(BlazeServerContext::new(
        private_key,
        vec![server_cert, ca_cert],
    ));

    let listener = BlazeListener::bind(("0.0.0.0", LISTEN_PORT), context).await?;
    println!("Listening for ProtoSSL connections on port {}...", LISTEN_PORT);

    loop {
        let accept = match listener.accept().await {
            Ok(accept) => accept,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };

        tokio::spawn(async move {
            // Complete the SSL handshake
            let (mut ssl_stream, addr) = match accept.finish_accept().await {
                Ok(result) => result,
                Err(e) => {
                    eprintln!("SSL handshake failed: {}", e);
                    return;
                }
            };

            println!("[SSL] Client connected from {}", addr);

            // Connect to the backend Node.js server
            let mut backend = match TcpStream::connect(("127.0.0.1", BACKEND_PORT)).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("[SSL] Failed to connect to backend: {}", e);
                    return;
                }
            };

            println!("[SSL] Connected to backend, proxying data...");

            // Proxy data between SSL client and plain TCP backend
            let mut client_buf = vec![0u8; 8192];
            let mut backend_buf = vec![0u8; 8192];

            loop {
                tokio::select! {
                    // Read from SSL client, write to backend
                    result = ssl_stream.read(&mut client_buf) => {
                        match result {
                            Ok(0) => {
                                println!("[SSL] Client disconnected");
                                break;
                            }
                            Ok(n) => {
                                println!("[SSL] Client -> Backend: {} bytes", n);
                                if backend.write_all(&client_buf[..n]).await.is_err() {
                                    break;
                                }
                                let _ = backend.flush().await;
                            }
                            Err(e) => {
                                eprintln!("[SSL] Client read error: {}", e);
                                break;
                            }
                        }
                    }
                    // Read from backend, write to SSL client
                    result = backend.read(&mut backend_buf) => {
                        match result {
                            Ok(0) => {
                                println!("[SSL] Backend disconnected");
                                break;
                            }
                            Ok(n) => {
                                println!("[SSL] Backend -> Client: {} bytes", n);
                                if ssl_stream.write_all(&backend_buf[..n]).await.is_err() {
                                    break;
                                }
                                let _ = ssl_stream.flush().await;
                            }
                            Err(e) => {
                                eprintln!("[SSL] Backend read error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
}
