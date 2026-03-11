//! Codec module for custom message encoding/decoding

pub mod message;
pub mod codec;

pub use message::Message;
pub use message::MessageType;
pub use codec::ByteCodec;
