package DualGSW

import (
	"anamorphicLWE/matrix"
	"fmt"
	"math/big"
)

// Represents an instance of the anamorphic Dual GSW scheme
type DualGSWScheme struct {
	lam int // Security parameter

	// Regular Dual GSW components
	pk PublicKey           // Public key
	sk matrix.BigIntMatrix // Secret key
	ct matrix.BigIntMatrix // Ciphertext matrix

	// Anamorphic variant components
	apk PublicKey           // Anamorphic public key
	ask matrix.BigIntMatrix // Anamorphic secret key
	dk  []int               // Double key
	tk  matrix.BigIntMatrix // Trapdoor key
	act matrix.BigIntMatrix // Anamorphic ciphertext matrix

	// Normal and anamorphic messages
	mu, muBar *big.Int
}

// Creates a new, empty instance of the Dual GSW scheme
func NewDualGSW() *DualGSWScheme {
	return &DualGSWScheme{}
}

// Returns the name of this scheme implementation
func (gsw *DualGSWScheme) Name() string { return "DualGSW" }

// Generates the standard Dual GSW public and secret keys.
func (gsw *DualGSWScheme) KeyGen(lam int) error {
	gsw.lam = lam
	sk, pk := KGen(lam) // Generate secret and public keys.
	gsw.sk, gsw.pk = sk, pk
	return nil
}

// Performs standard encryption in the Dual GSW scheme.
func (gsw *DualGSWScheme) Enc(lam int) error {
	fmt.Println("Encryptioooon....")

	p := gsw.pk.Par.P // Modulus

	// Sample random plaintext mod p
	mu_matrix := matrix.SampleMatrix(1, 1, p)
	gsw.mu = mu_matrix[0][0]

	// Encrypt the sampled plaintext using the public key
	gsw.ct = Enc(gsw.pk, gsw.mu)
	return nil
}

// Perfomrs standard Dual GSW decryption using the secret key.
func (gsw *DualGSWScheme) Dec(lam int) error {
	_ = Dec(gsw.pk.Par, gsw.sk, gsw.ct)
	return nil
}

// Performs anamorphic key generation
func (gsw *DualGSWScheme) AGen(lam int) error {
	gsw.lam = lam

	// Generate anamorphic key components
	KeySet := AGen(lam)

	// Assign anamorphic key materials
	gsw.ask, gsw.apk, gsw.dk, gsw.tk = KeySet.Ask, KeySet.Apk, KeySet.Dk, KeySet.Tk
	return nil
}

// Performs anamorphic encryption
func (gsw *DualGSWScheme) AEnc(lam int) error {
	p := gsw.apk.Par.P // Modulus

	// Sample two plaintext values from Z_p
	mu_matrix := matrix.SampleMatrix(1, 1, p)
	muBar_matrix := matrix.SampleMatrix(1, 1, p)

	// Extract both messages from the sampled matrices
	gsw.mu, gsw.muBar = mu_matrix[0][0], muBar_matrix[0][0]

	// Encrypt both messages using anamorphic encryption
	gsw.act = AEnc(gsw.apk, gsw.dk, gsw.mu, gsw.muBar)
	return nil
}

// Perfomrs anamorphic decryption
func (gsw *DualGSWScheme) ADec(lam int) error {
	_ = ADec(gsw.apk.Par, gsw.dk, gsw.tk, gsw.ask, gsw.act)
	return nil
}
