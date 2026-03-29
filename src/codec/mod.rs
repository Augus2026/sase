//! Codec module for protobuf message encoding/decoding

pub mod codec;

pub use codec::{
    message::Msg as MessageType, ByteCodec, Data, Disconnect, Handshake, KeepAlive, Message,
    TunConfig,
};
