package set5

import (
	"crypto/rand"
	"math/big"
)

type DiffieHellman struct {
	p *big.Int // modulus p
	g *big.Int // base g

	a *big.Int // private key (secret) aka Alice's a
	A *big.Int // public key aka Alice's A
	s *big.Int // shared secret key, known only to Alice (this should be the same value computed by the second peer)
}

func (dh *DiffieHellman) Init(p, g *big.Int) error {
	dh.p = p
	dh.g = g

	// chose a secret key (a)
	a, err := rand.Int(rand.Reader, big.NewInt(8)) // some lower value
	if err != nil {
		return err
	}

	dh.a = a

	return nil
}

func (dh *DiffieHellman) Public() *big.Int {
	dh.A = new(big.Int).Exp(dh.g, dh.a, dh.p) // Alice then sends Bob A = g**a mod p
	return dh.A
}

func (dh *DiffieHellman) SharedSecretKey(B *big.Int) *big.Int {
	dh.s = new(big.Int).Exp(B, dh.a, dh.p) // Alice computes s = B**a mod p
	return dh.s
}

func NewDiffieHellman(p, g *big.Int) *DiffieHellman {
	dh := &DiffieHellman{}
	dh.Init(p, g)

	return dh
}
