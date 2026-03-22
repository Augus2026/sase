//! Codec module for protobuf message encoding/decoding

pub mod codec;

pub use codec::{ByteCodec, Message, message::Msg as MessageType, Handshake, Data, KeepAlive, Disconnect, TunConfig};
