package PrimalRegev

import (
	"anamorphicLWE/matrix"
	"fmt"
)

// Represents a full instance of the anamorphic Primal Regev cryptographic scheme
type PrimalRegevScheme struct {
	lam int // Security parameter lambda

	pk PublicKey              // Regular public key
	sk matrix.BigIntMatrix    // Regular secret key
	ct [2]matrix.BigIntMatrix // Regular ciphertext

	apk PublicKey              // Anamorphic public key
	ask matrix.BigIntMatrix    // Anamorphic secret key
	dk  [2]matrix.BigIntMatrix // Double key
	tk  matrix.BigIntMatrix    // Trapdoor key

	act       [2]matrix.BigIntMatrix // Anamorphic ciphertext
	mu, muBar matrix.BigIntMatrix    // Regular and anamorphic messages
}

// Creates and returns a new empty instance of the Primal Regev scheme
func NewPrimalRegev() *PrimalRegevScheme {
	return &PrimalRegevScheme{}
}

// Returns the string identifier for this scheme.
func (pr *PrimalRegevScheme) Name() string { return "PrimalRegev" }

// Generates a new key pair (public and secret keys) for the Primal Regev scheme.
func (pr *PrimalRegevScheme) KeyGen(lam int) error {
	pr.lam = lam
	pk, sk := KGen(pr.lam) // Call to the scheme-specific key generation function
	pr.sk, pr.pk = sk, pk  // Store the generated keys in the struct
	return nil
}

// Initializes the plaintext messages (mu and muBar) used for encryption.
func (pr *PrimalRegevScheme) initPlaintexts() {
	if pr.pk.Params.L == 0 {
		pr.KeyGen(pr.lam) // Generate keys if not already done.
	}

	l := pr.pk.Params.L // Message length
	p := pr.pk.Params.P // Modulus parameter

	// Sample two random plaintext message vectors from Z_p
	pr.mu = matrix.SampleMatrix(l, 1, p)
	pr.muBar = matrix.SampleMatrix(l, 1, p)
}

// Preforms standard encryption under the public key.
func (pr *PrimalRegevScheme) Enc(lam int) error {
	pr.lam = lam
	pr.initPlaintexts()
	pr.ct = Enc(pr.pk, pr.mu) // Encrypt the message mu using public key
	return nil
}

// Performs standard decryption using the secret key.
func (pr *PrimalRegevScheme) Dec(lam int) error {
	pr.lam = lam
	pr.initPlaintexts()
	_ = Dec(pr.pk.Params, pr.sk, pr.ct) // Decrypt ciphertect using secret key
	return nil
}

// Performs anamorphic key generation.
func (pr *PrimalRegevScheme) AGen(lam int) error {
	pr.lam = lam
	fmt.Println("Anamorphic KeyGen!")
	apk, ask, dk, tk := AGen(pr.lam) // Generate anamorphic key materials
	pr.apk, pr.ask, pr.dk, pr.tk = apk, ask, dk, tk
	return nil
}

// Perfomrs anamorphic encryption using anamorphic keys.
func (pr *PrimalRegevScheme) AEnc(lam int) error {
	pr.lam = lam
	pr.initPlaintexts()
	pr.act = AEnc(pr.apk, pr.dk, pr.mu, pr.muBar) // Encrypt both plaintexts
	return nil
}

// Performs anamorphic decryption using the trapdoor key (tk).
func (pr *PrimalRegevScheme) ADec(lam int) error {
	pr.lam = lam
	_ = ADec(pr.lam, pr.tk, pr.act, pr.apk) // Decrypt using anamorphic components.
	return nil
}
