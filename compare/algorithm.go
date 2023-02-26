package main

// for clarity
type Algorithm = string

const (
	// HMAC, HKDF
	SHA2_256 Algorithm = "SHA2-256"
	SHA2_384 Algorithm = "SHA2-384"
	SHA2_512 Algorithm = "SHA2-512"
	SHA3_256 Algorithm = "SHA3-256"
	SHA3_384 Algorithm = "SHA3-384"
	SHA3_512 Algorithm = "SHA3-512"
	AES_128  Algorithm = "AES-128"
	AES_256  Algorithm = "AES-256"
	BLAKE3   Algorithm = "BLAKE3" // ignored

	// AEAD
	AES_128_GCM       Algorithm = "AES-128-GCM"
	AES_256_GCM       Algorithm = "AES-256-GCM"
	ChaCha20Poly1305  Algorithm = "ChaCha20Poly1305"
	XChaCha20Poly1305 Algorithm = "XChaCha20Poly1305"

	// DAEAD
	AES_SIV Algorithm = "AES-SIV"

	// Signature
	ES256   Algorithm = "ES256"
	ES384   Algorithm = "ES384"
	ES512   Algorithm = "ES512" // not provided by RustCrypto or Ring
	Ed25519 Algorithm = "Ed25519"
	RS256   Algorithm = "RS256"
	RS384   Algorithm = "RS384"
	RS512   Algorithm = "RS512"
	PS256   Algorithm = "PS256"
	PS384   Algorithm = "PS384"
	PS512   Algorithm = "PS512"
	// Agreement
	// todo

	// HPKE
	// todo
)

var ignoredAlgorithms = []Algorithm{
	BLAKE3,
}

var macAlgorithms = []Algorithm{
	SHA2_256,
	SHA2_384,
	SHA2_512,
	SHA3_256,
	SHA3_384,
	SHA3_512,
	AES_128,
	AES_256,
}

var hmacAlgorithms = []Algorithm{
	SHA2_256,
	SHA2_384,
	SHA2_512,
	SHA3_256,
	SHA3_384,
	SHA3_512,
}

var hkdfAlgorithms = []Algorithm{
	SHA2_256,
	SHA2_384,
	SHA2_512,
	SHA3_256,
	SHA3_384,
	SHA3_512,
}

var aeadAlgorithms = []Algorithm{
	AES_128_GCM,
	AES_256_GCM,
	ChaCha20Poly1305,
	XChaCha20Poly1305,
}

var daeadAlgorithms = []Algorithm{
	AES_SIV,
}

var signatureAlgorithms = []Algorithm{
	ES256,
	ES384,
	ES512,
	Ed25519,
	RS256,
	RS384,
	RS512,
	PS256,
	PS384,
	PS512,
}

var agreementAlgorithms = []Algorithm{
	// todo
}

var hpkeAlgorithms = []Algorithm{
	// todo
}

func join(algos ...[]Algorithm) []Algorithm {
	var all []Algorithm
	for _, a := range algos {
		all = append(all, a...)
	}
	return all
}

var allAlgorithms = join(
	ignoredAlgorithms,
	macAlgorithms,
	hmacAlgorithms,
	hkdfAlgorithms,
	aeadAlgorithms,
	daeadAlgorithms,
	signatureAlgorithms,
	agreementAlgorithms,
	hpkeAlgorithms,
)

func isKnown(a Algorithm) bool {
	for _, an := range allAlgorithms {
		if a == an {
			return true
		}
	}
	return false
}

func isIgnored(a Algorithm) bool {
	for _, ia := range ignoredAlgorithms {
		if a == ia {
			return true
		}
	}
	return false
}
