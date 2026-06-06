// SPDX-License-Identifier: MIT OR Apache-2.0
//! A synchronous IronBus client: connect to a broker, produce, fetch, and acknowledge.
//!
//! The client owns one TCP connection and speaks the wire protocol (`ironbus-proto`)
//! request/response: it sends a frame and reads the response, framing the byte stream with
//! a persistent buffer so a read that delivers several frames at once is never lost. It is
//! blocking and minimal, matching the edge-first server.

use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{
    decode_deliver, encode_ack, encode_pub, AckBody, AckOp, BodyError, PubBody,
};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

/// An error from the client.
#[derive(Debug)]
pub enum ClientError {
    /// An underlying IO or connection error.
    Io(io::Error),
    /// A malformed frame from the server (the connection cannot continue).
    Frame(FrameError),
    /// A malformed message body from the server.
    Body(BodyError),
    /// The server replied with an error: the UTF-8 message it sent.
    Server(String),
    /// The server replied with an unexpected frame type for the request.
    Unexpected(FrameType),
    /// The connection closed before a complete response arrived.
    Closed,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io error: {e}"),
            ClientError::Frame(e) => write!(f, "frame error: {e}"),
            ClientError::Body(e) => write!(f, "message body error: {e}"),
            ClientError::Server(m) => write!(f, "server error: {m}"),
            ClientError::Unexpected(t) => write!(f, "unexpected response frame {t:?}"),
            ClientError::Closed => write!(f, "connection closed mid-response"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

/// A message delivered to the consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The log offset that names this message (carried back in the ack).
    pub offset: u64,
    /// The lease generation (the fencing token) to ack it with.
    pub generation: u64,
    /// Record flags as stored.
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The message payload.
    pub payload: Vec<u8>,
}

/// A connected IronBus client over one TCP connection.
#[derive(Debug)]
pub struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    /// Connects to a broker at `addr` and completes the handshake.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on a connection failure or an unexpected handshake reply.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<Client, ClientError> {
        let stream = TcpStream::connect(addr)?;
        let mut client = Client {
            stream,
            buf: Vec::new(),
        };
        client.send(FrameType::Connect, &[])?;
        match client.read_frame()? {
            (FrameType::Info, _) => Ok(client),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Produces a message and returns its assigned log offset.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error, an over-large field, or a server error.
    pub fn produce(&mut self, message: &PubBody<'_>) -> Result<u64, ClientError> {
        let mut body = Vec::new();
        encode_pub(message, &mut body).map_err(ClientError::Body)?;
        self.send(FrameType::Pub, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, body) => {
                let bytes = <[u8; 8]>::try_from(body.as_slice())
                    .map_err(|_| ClientError::Unexpected(FrameType::Ok))?;
                Ok(u64::from_le_bytes(bytes))
            }
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Fetches up to `max` messages. Returns the delivered messages (possibly fewer, or
    /// none if the queue is empty within the consumer window).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error or a server error.
    pub fn fetch(&mut self, max: u32) -> Result<Vec<Message>, ClientError> {
        self.send(FrameType::Flow, &max.to_le_bytes())?;
        let mut messages = Vec::new();
        loop {
            match self.read_frame()? {
                (FrameType::Deliver, body) => {
                    let d = decode_deliver(&body).map_err(ClientError::Body)?;
                    messages.push(Message {
                        offset: d.offset,
                        generation: d.generation,
                        flags: d.flags,
                        timestamp_ms: d.timestamp_ms,
                        key: d.key.to_vec(),
                        headers: d.headers.to_vec(),
                        payload: d.payload.to_vec(),
                    });
                }
                // The Ok terminates the batch (its body is the delivered count).
                (FrameType::Ok, _) => return Ok(messages),
                (FrameType::Err, body) => {
                    return Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
                }
                (other, _) => return Err(ClientError::Unexpected(other)),
            }
        }
    }

    /// Acknowledges a fetched message by its offset and fencing generation. Returns `true`
    /// if the ack committed, `false` if it was fenced (stale: the message will redeliver).
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error or a server error.
    pub fn ack(&mut self, offset: u64, generation: u64) -> Result<bool, ClientError> {
        let mut body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset,
                generation,
                delay_ms: 0,
            },
            &mut body,
        );
        self.send(FrameType::Ack, &body)?;
        match self.read_frame()? {
            (FrameType::Ok, body) => Ok(body.first() == Some(&1)),
            (FrameType::Err, body) => {
                Err(ClientError::Server(String::from_utf8_lossy(&body).into()))
            }
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    /// Sends a keepalive ping and waits for the pong.
    ///
    /// # Errors
    /// Returns a [`ClientError`] on an IO error or an unexpected reply.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        self.send(FrameType::Ping, &[])?;
        match self.read_frame()? {
            (FrameType::Pong, _) => Ok(()),
            (other, _) => Err(ClientError::Unexpected(other)),
        }
    }

    fn send(&mut self, frame_type: FrameType, body: &[u8]) -> Result<(), ClientError> {
        let mut frame = Vec::new();
        encode_frame(frame_type, body, &mut frame).map_err(ClientError::Frame)?;
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Reads one complete frame, buffering leftover bytes for the next call.
    fn read_frame(&mut self) -> Result<(FrameType, Vec<u8>), ClientError> {
        let mut chunk = [0u8; 4096];
        loop {
            match decode_frame(&self.buf).map_err(ClientError::Frame)? {
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed,
                } => {
                    // An unknown type from a newer server has no client handler.
                    let ty = FrameType::from_u8(type_tag)
                        .ok_or(ClientError::Unexpected(FrameType::Err))?;
                    let body = body.to_vec();
                    self.buf.drain(..consumed);
                    return Ok((ty, body));
                }
                FrameDecode::Incomplete { .. } => {}
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                return Err(ClientError::Closed);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_server::clock::SystemClock;
    use ironbus_server::engine::{Engine, EngineConfig};
    use ironbus_server::server::{serve, SharedEngine};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn start_server() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        (addr, shutdown, handle)
    }

    #[test]
    fn produce_fetch_ack_round_trip_against_a_real_server() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        c.ping().unwrap();

        let offset = c
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"k",
                headers: b"",
                payload: b"client-msg",
            })
            .unwrap();
        assert_eq!(offset, 0);

        let messages = c.fetch(10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"client-msg");
        assert_eq!(messages[0].offset, 0);

        assert!(c.ack(messages[0].offset, messages[0].generation).unwrap());
        // Nothing left to fetch.
        assert!(c.fetch(10).unwrap().is_empty());

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn fetching_an_empty_queue_returns_no_messages() {
        let (addr, shutdown, handle) = start_server();
        let mut c = Client::connect(addr).unwrap();
        assert!(c.fetch(5).unwrap().is_empty());
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }
}
