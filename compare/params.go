package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type Primitive = string

const (
	MAC       Primitive = "MAC"
	AEAD      Primitive = "AEAD"
	DAEAD     Primitive = "DAEAD"
	HPKE      Primitive = "HPKE"
	HKDF      Primitive = "HKDF"
	Signature Primitive = "Signature"
	Agreement Primitive = "Agreement"
)

type Params struct {
	Primitive Primitive
	Algorithm Algorithm
	Nonce     []byte
	Key       []byte
	KeyID     uint32
	Payload   []byte
	In        io.Reader
}

func parseParams() (Params, error) {
	var (
		pr string
		a  string
		n  string
		k  string
		i  uint
	)
	flag.StringVar(&pr, "primitive", "", "Primitive")
	flag.StringVar(&a, "algorithm", "", "Algorithm")
	flag.StringVar(&n, "nonce", "", "Nonce")
	flag.StringVar(&k, "key", "", "Key")
	flag.UintVar(&i, "kid", 0, "Key ID")

	flag.Parse()
	var ps string
	args := flag.Args()[1:]
	for _, ap := range args {
		ps += " " + ap
	}
	nb, err := base64.StdEncoding.DecodeString(n)
	if err != nil {
		return Params{}, fmt.Errorf("invalid nonce: %s", err)
	}
	var pb []byte
	if strings.TrimSpace(ps) != "" {
		pb, err = base64.StdEncoding.DecodeString(ps)
		if err != nil {
			return Params{}, err
		}
	}
	kb, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		log.Fatalf("invalid key: %s", err)
	}

	return Params{
		Primitive: Primitive(pr),
		Algorithm: Algorithm(a),
		Nonce:     nb,
		Key:       kb,
		KeyID:     uint32(i),
		Payload:   pb,
		In:        os.Stdin,
	}, nil
}

func (p Params) validate() error {
	if p.Primitive == "" {
		return fmt.Errorf("missing primitive")
	}
	if len(p.Algorithm) == 0 {
		return fmt.Errorf("missing algorithm")
	}
	if !isKnown(p.Algorithm) {
		return fmt.Errorf("unknown algorithm: %s", p.Algorithm)
	}
	if isIgnored(p.Algorithm) {
		return fmt.Errorf("ignored algorithm: %s", p.Algorithm)
	}
	return nil
}
