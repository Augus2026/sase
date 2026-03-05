//! Custom message types for TCP communication

use serde::{Deserialize, Serialize};

/// Message type enumeration for type-safe message creation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 1,
    Data = 2,
    KeepAlive = 3,
    Disconnect = 4,
}

impl From<MessageType> for u8 {
    fn from(t: MessageType) -> Self {
        t as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Handshake),
            2 => Ok(MessageType::Data),
            3 => Ok(MessageType::KeepAlive),
            4 => Ok(MessageType::Disconnect),
            _ => Err(()),
        }
    }
}

/// Custom message structure for TCP communication
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Message type/command
    pub message_type: u8,
    /// Message payload data
    pub data: Vec<u8>,
}

impl Message {
    /// Create a new custom message
    pub fn new(message_type: MessageType, data: Vec<u8>) -> Self {
        Self {
            message_type: message_type.into(),
            data,
        }
    }

    /// Create a handshake message
    pub fn handshake(data: Vec<u8>) -> Self {
        Self::new(MessageType::Handshake, data)
    }

    /// Create a data message
    pub fn data(data: Vec<u8>) -> Self {
        Self::new(MessageType::Data, data)
    }

    /// Create a keepalive message
    pub fn keepalive(data: Vec<u8>) -> Self {
        Self::new(MessageType::KeepAlive, data)
    }

    /// Create a disconnect message
    pub fn disconnect(data: Vec<u8>) -> Self {
        Self::new(MessageType::Disconnect, data)
    }

    /// Get the payload as a UTF-8 string if possible
    pub fn payload_as_string(&self) -> Option<String> {
        std::str::from_utf8(&self.data).ok().map(|s| s.to_string())
    }
}
