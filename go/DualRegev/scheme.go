package DualRegev

import (
	"anamorphicLWE/matrix"
	"fmt"
)

// Represents a complete instance of the anamorphci Dual Regev cryptographic scheme
type DualRegevScheme struct {
	lam int // Security parameter lambda

	pk PublicKey              // Regular public key
	sk matrix.BigIntMatrix    // Regular secret key
	ct [2]matrix.BigIntMatrix // Regular ciphertext

	apk PublicKey              // Anamorphic public key
	ask matrix.BigIntMatrix    // Anamorphic secret key
	tk  matrix.BigIntMatrix    // Trapdoor key
	act [2]matrix.BigIntMatrix // Anamorphic ciphertext

	mu, muBar matrix.BigIntMatrix // Regular and anamorphic messages
}

// Creates and returns a new instance of Dual Regev scheme.
func NewDualRegev() *DualRegevScheme {
	return &DualRegevScheme{}
}

// Returns the name of this scheme implementation.
func (dr *DualRegevScheme) Name() string { return "DualRegev" }

// Generates a public and secret key pair for the Dual Regev scheme
func (dr *DualRegevScheme) KeyGen(lam int) error {
	dr.lam = lam
	sk, pk := KGen(lam) // Call to the scheme-specific key generation function.
	dr.sk, dr.pk = sk, pk
	return nil
}

// Performs standard encryption under the public key.
func (dr *DualRegevScheme) Enc(lam int) error {
	fmt.Println("I was here!")

	n := dr.pk.Params.N // Dimension of the message space
	p := dr.pk.Params.P // Modulus

	// Sample a random plaintext vector mu mod p
	dr.mu = matrix.SampleMatrix(n, 1, p)

	// Encrypt mu using the Dual Regev encryption function
	dr.ct = Enc(dr.pk, dr.mu)
	return nil
}

// Performs a standard decryption using the secret key
func (dr *DualRegevScheme) Dec(lam int) error {
	_ = Dec(dr.pk.Params, dr.sk, dr.ct)
	return nil
}

// Performs anamorphic key generation
func (dr *DualRegevScheme) AGen(lam int) error {
	fmt.Println("Anamorphic Key Gen!")
	dr.lam = lam

	// Generate anamorphic keys (public, secret, and trapdoor)
	apk, ask, tk := AGen(dr.lam)
	dr.apk, dr.ask, dr.tk = apk, ask, tk
	return nil
}

// Performs anamorphic encryption
func (dr *DualRegevScheme) AEnc(lam int) error {
	n := dr.apk.Params.N // Message dimension
	p := dr.apk.Params.P // Modulus

	// Sample two plaintext messages mod p
	dr.mu = matrix.SampleMatrix(n, 1, p)
	dr.muBar = matrix.SampleMatrix(n, 1, p)

	// Encrypt using the anamorphic encryption function
	dr.act = AEnc(dr.apk, dr.mu, dr.muBar)
	return nil
}

// Performs anamorphic decryption using the anamorphic secret and trapdoor keys.
func (dr *DualRegevScheme) ADec(lam int) error {
	_ = ADec(dr.apk, dr.tk, dr.ask, dr.act)
	return nil
}
