use std::net::SocketAddr;
use std::task::{Context, Poll}; // Required for poll_fn
use tokio::io::{self, AsyncWriteExt, ReadBuf}; // ReadBuf is needed for poll_peek
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tracing::{error, info, instrument, warn, Level};
use tracing_subscriber::FmtSubscriber;

// For peeking and parsing TLS ClientHello
use bytes::BytesMut;
use futures::future::poll_fn; // Required for using poll functions in async
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessage, TlsMessageHandshake, SNIType};

// Define a reasonable buffer size for peeking the ClientHello
const PEEK_BUFFER_SIZE: usize = 8192; // Max TLS record size is ~16k, ClientHello is usually much smaller

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO) // Adjust log level as needed
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let listener = TcpListener::bind("127.0.0.1:1106").await?;
    info!("Listening on 127.0.0.1:1106");

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                info!(client.addr = %addr, "Accepted connection");
                // Spawn a new task for each connection
                tokio::spawn(process_socket(socket, addr)); // Pass addr for better tracing context
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Parses the TLS ClientHello from the provided buffer and extracts the SNI hostname.
/// Returns Ok(Some(hostname)), Ok(None) if no SNI, or Err if parsing fails.
fn parse_sni(buffer: &[u8]) -> Result<Option<String>, String> {
    // Try parsing the first record as TLS plaintext
    // We only care about the first message, which should be ClientHello
    info!("Parse SNI from ClientHello");
    match parse_tls_plaintext(buffer) {
        Ok((_, plaintext_message)) if !plaintext_message.msg.is_empty() => {
            // Check if the first message is a Handshake message
            if let TlsMessage::Handshake(handshake_message) = &plaintext_message.msg[0] {
                // Check if it's a ClientHello
                if let TlsMessageHandshake::ClientHello(client_hello) = handshake_message {
                    // Iterate through extensions to find SNI
                    if let Some(extensions_bytes) = client_hello.ext {
                        let mut remaining_extensions = extensions_bytes;
                        while !remaining_extensions.is_empty() {
                            match tls_parser::parse_tls_extension(remaining_extensions) {
                                Ok((rem, ext)) => {
                                    if let TlsExtension::SNI(sni_list) = ext {
                                        // Found SNI extension, extract the first hostname
                                        for sni in sni_list {
                                            // Updated tuple access for tls-parser 0.11+
                                            if sni.0 == SNIType::HostName {
                                                // Found hostname, convert bytes to String
                                                match std::str::from_utf8(sni.1) {
                                                    Ok(hostname) => {
                                                        info!(sni.hostname = %hostname, "Extracted SNI hostname");
                                                        return Ok(Some(hostname.to_string()));
                                                    }
                                                    Err(e) => {
                                                        return Err(format!(
                                                            "Invalid SNI hostname encoding: {}",
                                                            e
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                        // SNI extension found, but no hostname entry
                                        return Ok(None);
                                    }
                                    remaining_extensions = rem; // Move to the next extension
                                }
                                // Handle parsing errors for extensions
                                Err(nom::Err::Incomplete(needed)) => {
                                    return Err(format!("Incomplete extension data: {:?}", needed));
                                }
                                Err(e) => {
                                    return Err(format!("Failed to parse TLS extension: {:?}", e));
                                }
                            }
                        }
                    }
                    // ClientHello parsed, but no SNI extension found
                    Ok(None)
                } else {
                    // Handshake message is not ClientHello
                    Ok(None)
                }
            } else {
                // First message is not a Handshake message
                Ok(None)
            }
        }
        // Handle cases where parsing plaintext fails or message is empty
        Ok(_) => Ok(None), // No message parsed
        Err(nom::Err::Incomplete(needed)) => {
            Err(format!("Incomplete TLS plaintext data: {:?}", needed))
        }
        Err(e) => Err(format!("Failed to parse TLS plaintext: {:?}", e)),
    }
}


// Instrument the function for better tracing logs
#[instrument(skip(socket), fields(client.addr = %addr))]
async fn process_socket(mut socket: TcpStream, addr: SocketAddr) {
    info!("Attempting to peek socket for ClientHello using poll_peek...");
    let mut peek_buffer = BytesMut::with_capacity(PEEK_BUFFER_SIZE);

    // 1. Use poll_fn to bridge poll_peek into the async context
    let peek_result = poll_fn(|cx: &mut Context<'_>| {
        // Create a ReadBuf pointing to the spare capacity of peek_buffer.
        // poll_peek requires a ReadBuf to know where to put the data and how much space is available.
        let mut read_buf = ReadBuf::uninit(peek_buffer.spare_capacity_mut());

        // Call poll_peek
        match socket.poll_peek(cx, &mut read_buf) {
            Poll::Ready(Ok(n)) => {
                // If successful, poll_peek returns the number of bytes peeked.
                // The data is now in the buffer underlying read_buf.
                // We return Ok(n) wrapped in Poll::Ready.
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                // If there's an error, wrap it in Poll::Ready.
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                // If the operation would block, return Poll::Pending.
                // poll_fn will handle rescheduling the task based on the context.
                Poll::Pending
            }
        }
    })
    .await; // await the final result from poll_fn

    // Process the result obtained from polling
    let peeked_len = match peek_result {
        Ok(n) => {
            // Crucial: If poll_peek succeeded (returned Ok(n)), it wrote 'n' bytes
            // into the buffer slice managed by ReadBuf. We need to update
            // the length of our original BytesMut to reflect this.
            // Safety: `poll_peek` guarantees that it has initialized `n` bytes
            // in the buffer it was given. We can safely advance the initialized
            // portion of `peek_buffer` by `n` bytes.
            unsafe { peek_buffer.set_len(n) };
             

            if n == 0 {
                // This case means the client closed the connection (sent FIN)
                // before sending any application data after the TCP handshake.
                info!("Client closed connection before sending any data (poll_peek returned Ok(0)).");
                // No need to shutdown here, just return as the connection is already closing.
                // Dropping `socket` will close the local end.
                return;
            } else {
                info!("Successfully peeked {} bytes using poll_peek.", n);
                n // Assign n to peeked_len
            }
        }
        Err(e) => {
            error!("Failed to poll_peek socket: {}", e);
            // Attempt graceful shutdown on error before returning
            let _ = socket.shutdown().await;
            return;
        }
    };

    // Redundant check removed as Ok(0) is handled above.
    // if peeked_len == 0 { ... }

    // 2. Try parsing the peeked data to find the SNI hostname
    // The data is now available in peek_buffer[..peeked_len]
    let upstream_hostname = match parse_sni(&peek_buffer[..peeked_len]) {
        Ok(Some(hostname)) => {
            info!(sni.hostname = %hostname, "SNI hostname found");
            hostname
        }
        Ok(None) => {
            warn!("No SNI hostname found in ClientHello. Closing connection.");
            let _ = socket.shutdown().await;
            return;
        }
        Err(e) => {
            warn!(
                "Failed to parse ClientHello or SNI: {}. Assuming non-TLS or malformed. Closing connection.",
                e
            );
            let _ = socket.shutdown().await;
            return;
        }
    };

    // 3. Perform DNS lookup for the SNI hostname (assuming port 443)
    let upstream_port = 443;
    let upstream_target = format!("{}:{}", upstream_hostname, upstream_port);

    let upstream_addr = match lookup_host(&upstream_target).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                info!(upstream.host = %upstream_hostname, upstream.addr = %addr, "Resolved SNI hostname");
                addr
            } else {
                warn!(upstream.host = %upstream_hostname, "DNS lookup failed: No addresses found for SNI hostname. Closing connection.");
                let _ = socket.shutdown().await;
                return;
            }
        }
        Err(e) => {
            warn!(upstream.host = %upstream_hostname, "DNS lookup failed for SNI hostname: {}. Closing connection.", e);
            let _ = socket.shutdown().await;
            return;
        }
    };

    // 4. Connect to the resolved upstream server
    info!(upstream.addr = %upstream_addr, "Connecting to upstream");
    let mut upstream_stream = match TcpStream::connect(upstream_addr).await {
        Ok(stream) => {
            info!(upstream.addr = %upstream_addr, "Connected to upstream");
            stream
        }
        Err(e) => {
            error!(upstream.addr = %upstream_addr, "Failed to connect to upstream: {}", e);
            let _ = socket.shutdown().await; // Close client socket if upstream connection fails
            return;
        }
    };

    // 5. Proxy data using copy_bidirectional
    info!("Starting bidirectional copy between client and upstream");
    match io::copy_bidirectional(&mut socket, &mut upstream_stream).await {
        Ok((sent, received)) => {
            info!(
                bytes.sent = sent,
                bytes.received = received,
                "Connection closed gracefully."
            );
        }
        Err(e) => {
            warn!("Error during data proxying: {}", e);
        }
    }

    // Ensure both sockets are properly shut down
    let _ = socket.shutdown().await;
    let _ = upstream_stream.shutdown().await;
    info!("Sockets shut down.");
}
