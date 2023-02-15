# Message Authentication Code ([HMAC](https://www.rfc-editor.org/rfc/rfc2104) & [CMAC](https://www.rfc-editor.org/rfc/rfc4493))

### Basic usage

```rust
use navajo::mac::{Mac, Algorithm};
// create a generated Mac:
let mac = Mac::new(Algorithm::Sha256, None);
let tag = mac.compute(b"an example");
// tags are prepended with a 4 byte key-id for optimization.
// to remove it from output:
let tag = tag.omit_header().unwrap();
// which can fail if you have previously set a truncation length.

// to set a truncation length:
let tag = tag.truncate_to(16).unwrap();
// which is fallible because tags must be at least 8 bytes long
// with the header omitted or 12 bytes with.

// Once you have a Tag, you can validate other tags, in either Tag
// or byte slice with a equal (==) to get constant-time comparison.

// To use the Mac instance to compute and verify:
mac.verify(&tag, b"an example").unwrap();
```

### Read Compute / Verify

```rust
use navajo::mac::{Mac, Algorithm};
use std::fs::{ File, BufReader };
use std::io::prelude::*;

let mac = Mac::new(Algorithm::Sha256, None);
let file = fs::File::open("foo.txt").unwrap();
let mut buf_reader = BufReader::new(file);
let tag = mac.compute_reader(&mut file).unwrap()

let other_file = fs::File::open("other.txt").unwrap();
let mut buf_reader = BufReader::new(other_file);
let verified = mac.verify_reader(&tag, &mut buf_reader);
```

### Stream Compute / Verify

```rust
use navajo::mac::{Mac, Algorithm};
use futures::{ StreamExt, stream };

fn to_try_stream<T>(d: T) -> Result<T, ()> { Ok(d) }

#[tokio::main]
async fn main() {
    let mac = Mac::new(Algorithm::Sha256, None);
    let data = vec![b"hello", b"world"];
    let stream = stream::iter(data);
    let tag = mac.compute_stream(stream).await;

    let try_stream = stream::iter(data).map(to_try_stream);
    let result = mac.verify_try_stream(&tag, try_stream).await;

    println!("{result:?}");
}
```

### Importing keys

```rust
use navajo::Mac;
use hex::{decode, encode};
 let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    .unwrap();
let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
let tag = mac.compute(b"hello world").omit_header().unwrap();
assert_eq!(encode(tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a")

// alternatively:
let mut mac = Mac::new(Algorithm::Sha256);
let key = mac.add_external_key(&external_key, Algorithm::Sha256, None).unwrap();
let key = mac.promote_key(key).unwrap();
println!("{key}");
```
