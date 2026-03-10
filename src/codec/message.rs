use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub message_type: u8,
    pub data: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, data: Vec<u8>) -> Self {
        Self {
            message_type: message_type.into(),
            data,
        }
    }

    pub fn handshake(data: Vec<u8>) -> Self {
        Self::new(MessageType::Handshake, data)
    }

    pub fn data(data: Vec<u8>) -> Self {
        Self::new(MessageType::Data, data)
    }

    pub fn keepalive(data: Vec<u8>) -> Self {
        Self::new(MessageType::KeepAlive, data)
    }
}
