#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Status {
    Unknown = 0,
    Enabled = 1,
    Disabled = 2,
    Destroyed = 3,
}
impl Status {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Status::Unknown => "UNKNOWN",
            Status::Enabled => "ENABLED",
            Status::Disabled => "DISABLED",
            Status::Destroyed => "DESTROYED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "ENABLED" => Some(Self::Enabled),
            "DISABLED" => Some(Self::Disabled),
            "DESTROYED" => Some(Self::Destroyed),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChaCha20Poly1305 {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(string, tag = "2")]
    pub pub_id: ::prost::alloc::string::String,
    #[prost(enumeration = "Status", tag = "3")]
    pub status: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChaCha20Poly1305Keys {
    #[prost(message, repeated, tag = "1")]
    pub keys: ::prost::alloc::vec::Vec<ChaCha20Poly1305>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmKeys {
    #[prost(message, repeated, tag = "1")]
    pub keys: ::prost::alloc::vec::Vec<AesGcm>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcm {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(string, tag = "2")]
    pub pub_id: ::prost::alloc::string::String,
    #[prost(enumeration = "Status", tag = "3")]
    pub status: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Aead {
    #[prost(oneof = "aead::Algorithm", tags = "1, 2")]
    pub algorithm: ::core::option::Option<aead::Algorithm>,
}
/// Nested message and enum types in `Aead`.
pub mod aead {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Algorithm {
        #[prost(message, tag = "1")]
        AesGcm(super::AesGcmKeys),
        #[prost(message, tag = "2")]
        Chacha20Poly1305(super::ChaCha20Poly1305Keys),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Daead {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ed25519Keys {
    #[prost(message, repeated, tag = "1")]
    pub keys: ::prost::alloc::vec::Vec<Ed25519>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ed25519 {
    #[prost(string, tag = "1")]
    pub key_id: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "2")]
    pub private_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub public_key: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Hybrid {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Mac {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Signature {
    #[prost(oneof = "signature::Algorithm", tags = "1")]
    pub algorithm: ::core::option::Option<signature::Algorithm>,
}
/// Nested message and enum types in `Signature`.
pub mod signature {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Algorithm {
        #[prost(message, tag = "1")]
        Ed25519(super::Ed25519Keys),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Keyset {
    #[prost(uint32, tag = "1")]
    pub primary_key_id: u32,
}
/// Nested message and enum types in `Keyset`.
pub mod keyset {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Keys {
        #[prost(oneof = "keys::Primitive", tags = "1, 2, 3, 4, 5")]
        pub primitive: ::core::option::Option<keys::Primitive>,
    }
    /// Nested message and enum types in `Keys`.
    pub mod keys {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Primitive {
            #[prost(message, tag = "1")]
            Aead(super::super::Aead),
            #[prost(message, tag = "2")]
            Daead(super::super::Daead),
            #[prost(message, tag = "3")]
            Mac(super::super::Mac),
            #[prost(message, tag = "4")]
            Hybrid(super::super::Hybrid),
            #[prost(message, tag = "5")]
            Signature(super::super::Signature),
        }
    }
}
