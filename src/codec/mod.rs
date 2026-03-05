//! Codec module for custom message encoding/decoding

pub mod message;
pub mod codec;

#[cfg(test)]
mod tests;

pub use message::Message;
pub use message::MessageType;
pub use codec::ByteCodec;
