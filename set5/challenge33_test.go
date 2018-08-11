package set5

import (
	"math/big"
	"testing"
)

func TestDiffieHellman(t *testing.T) {
	// p := big.NewInt(23) // modulus p
	// g := big.NewInt(5)  // base g

	p := new(big.Int)
	p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16) // modulus p
	g := big.NewInt(2)                                                                                                                                                                                                                                                                                                                                                                                                  // base g

	/*
	    This is "normal", step by step DH

	   	a := big.NewInt(4)             // Alice chooses a secret integer a
	   	A := new(big.Int).Exp(g, a, p) // Alice then sends Bob A = g**a mod p

	   	b := big.NewInt(3)             // Bob chooses a secret integer b
	   	B := new(big.Int).Exp(g, b, p) // Bob then sends Alice B = g**b mod p

	   	sAlice := new(big.Int).Exp(B, a, p) // Alice computes s = B**a mod p
	   	sBob := new(big.Int).Exp(A, b, p)   // Bob computes s = A**b mod p

	    // sAlice = sBob should be 4096
	*/

	aliceDH := NewDiffieHellman(p, g)
	A := aliceDH.Public()

	bobDH := NewDiffieHellman(p, g)
	B := bobDH.Public()

	sAlice := aliceDH.SharedSecretKey(B)
	sBob := bobDH.SharedSecretKey(A)

	if sAlice.Cmp(sBob) != 0 {
		t.Error("Failed to compute Diffie-Hellman shared key")

		t.Log("Alice s = ", sAlice)
		t.Log("Bob s = ", sBob)
	}

}
