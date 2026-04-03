//! Custom codec for encoding and decoding protobuf Messages

use bytes::{Buf, BufMut, BytesMut};
use prost::Message as _;
use std::io;
use tokio_util::codec::{Decoder, Encoder};
include!(concat!(env!("OUT_DIR"), "/sase.rs"));

// Convenience functions for creating protobuf messages
impl Message {
    pub fn handshake(handshake: Handshake) -> Self {
        Self {
            msg: Some(message::Msg::Handshake(handshake)),
        }
    }

    pub fn data(data: Data) -> Self {
        Self {
            msg: Some(message::Msg::Data(data)),
        }
    }

    pub fn keepalive(keepalive: KeepAlive) -> Self {
        Self {
            msg: Some(message::Msg::Keepalive(keepalive)),
        }
    }
}

/// Header size constant (4 bytes for length prefix)
const HEADER_SIZE: usize = 4;

/// Maximum allowed frame size (1MB by default)
const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Custom codec for encoding and decoding protobuf Messages
#[derive(Debug)]
pub struct ByteCodec {
    state: DecodeState,
    max_frame_size: usize,
}

impl Default for ByteCodec {
    fn default() -> Self {
        Self {
            state: DecodeState::Head,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl ByteCodec {
    /// Create a new ByteCodec with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new ByteCodec with custom max frame size
    #[allow(dead_code)]
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self {
            state: DecodeState::Head,
            max_frame_size,
        }
    }
}

/// Decoder state machine
#[derive(Debug, Clone, Copy)]
pub enum DecodeState {
    /// Waiting to read frame header
    Head,
    /// Reading frame body
    Body { data_len: usize },
}

impl Default for DecodeState {
    fn default() -> Self {
        DecodeState::Head
    }
}

// Encoder implementation
impl Encoder<Message> for ByteCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), io::Error> {
        let body = item.encode_to_vec();
        let required = HEADER_SIZE + body.len();

        // Validate frame size
        if required > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Frame size {} exceeds maximum {}",
                    required, self.max_frame_size
                ),
            ));
        }

        // Reserve space efficiently
        dst.reserve(required);

        // Encode frame header (little-endian for network compatibility)
        dst.put_u32_le(body.len() as u32);

        // Encode frame body (protobuf data)
        dst.extend_from_slice(&body);

        Ok(())
    }
}

// Decoder implementation
impl Decoder for ByteCodec {
    type Item = Message;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, io::Error> {
        match self.state {
            DecodeState::Head => {
                // Check if we have enough data for header
                if src.len() < HEADER_SIZE {
                    return Ok(None);
                }

                // Parse header
                let data_len = src.get_u32_le() as usize;

                // Validate data length
                if data_len > self.max_frame_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Data length {} exceeds maximum {}",
                            data_len, self.max_frame_size
                        ),
                    ));
                }

                // Transition to body state
                self.state = DecodeState::Body { data_len };

                // Continue decoding body
                self.decode(src)
            }
            DecodeState::Body { data_len } => {
                // Check if we have enough data for body
                if src.len() < data_len {
                    return Ok(None);
                }

                // Extract body data
                let data = src.split_to(data_len).to_vec();

                // Reset state for next frame
                self.state = DecodeState::Head;

                // Decode protobuf message
                Message::decode(&*data)
                    .map(Some)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}
