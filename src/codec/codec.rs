//! Custom codec for encoding and decoding Message

use crate::codec::message::Message;
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// Header size constant (5 bytes: message_type(1) + data_len(4))
const HEADER_SIZE: usize = 5;

/// Maximum allowed frame size (1MB by default)
const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Custom codec for encoding and decoding Message
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

    /// Calculate the total frame size for a given message
    pub fn calculate_frame_size(message: &Message) -> usize {
        HEADER_SIZE + message.data.len()
    }
}

/// Decoder state machine
#[derive(Debug, Clone, Copy)]
pub enum DecodeState {
    /// Waiting to read frame header
    Head,
    /// Reading frame body
    Body {
        message_type: u8,
        data_len: usize,
    },
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
        let required = Self::calculate_frame_size(&item);

        // Validate frame size
        if required > self.max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Frame size {} exceeds maximum {}", required, self.max_frame_size),
            ));
        }

        // Reserve space efficiently
        dst.reserve(required);

        // Encode frame header (little-endian for network compatibility)
        dst.put_u8(item.message_type);
        dst.put_u32_le(item.data.len() as u32);

        // Encode frame body
        dst.extend_from_slice(&item.data);

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
                let message_type = src.get_u8();
                let data_len = src.get_u32_le() as usize;

                // Validate data length
                if data_len > self.max_frame_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Data length {} exceeds maximum {}", data_len, self.max_frame_size),
                    ));
                }

                // Transition to body state
                self.state = DecodeState::Body {
                    message_type,
                    data_len,
                };

                // Continue decoding body
                self.decode(src)
            }
            DecodeState::Body {
                message_type,
                data_len,
            } => {
                // Check if we have enough data for body
                if src.len() < data_len {
                    return Ok(None);
                }

                // Extract body data
                let data = src.split_to(data_len).to_vec();

                // Reset state for next frame
                self.state = DecodeState::Head;

                // Return complete message
                Ok(Some(Message {
                    message_type,
                    data,
                }))
            }
        }
    }
}
