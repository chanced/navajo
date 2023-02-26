package main

import (
	"log"
)

func main() {
	log.SetFlags(0)
	p, err := parseParams()
	if err != nil {
		log.Fatalf("Error parsing parameters: %s", err)
	}
	switch p.Primitive {
	case "MAC":
		handleMAC(p)
	case "AEAD":
		handleAEAD(p)
	case "DAEAD":
		handleDAEAD(p)
	case "HPKE":
		handleHPKE(p)
	case "HKDF":
		handleHKDF(p)
	case "Signature":
		handleSignature(p)
	case "Agreement":
		handleAgreement(p)
	default:
		log.Fatalf("Unknown primitive: %s", p.Primitive)
	}
}
