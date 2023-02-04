mod algorithm;
mod context;
mod key;
mod ring;
mod tag;

pub use algorithm::Algorithm;
pub use tag::Tag;

use tag::InternalTag;
// algorithm_enum!({
//     hmac:  ([ Sha256, Sha384, Sha512 ], [Sha224, Sha3_224, Sha3_256, Sha3_384, Sha3_512]),
//     cmac: [Aes128, Aes192, Aes256]
// });
